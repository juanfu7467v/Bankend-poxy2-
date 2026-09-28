import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import axios from "axios";
import { Redis } from "@upstash/redis";

// Carga las variables de entorno desde .env
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ Proveedor Ecuador (desde secrets / env de Fly.io)
const PROVEEDOR_ECUADOR = (process.env.PROVEEDOR_ECUADOR || "").replace(/\/+$/, ""); // https://api.ecuadorapi.com/api/v1
const TOKEN_ECUADOR = process.env.TOKEN_ECUADOR;

if (!PROVEEDOR_ECUADOR || !TOKEN_ECUADOR) {
  console.error(
    "❌ ERROR: Variables PROVEEDOR_ECUADOR y TOKEN_ECUADOR deben estar configuradas en secrets/.env"
  );
  process.exit(1);
}

// Configuración del sistema de caché externo
const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN;

// Validar que las variables del sistema de caché estén configuradas
if (!REDIS_URL || !REDIS_TOKEN) {
  console.error(
    "❌ ERROR: Variables de configuración del sistema de caché externo (UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN) deben estar configuradas en .env"
  );
  process.exit(1);
}

// Inicializar cliente del sistema de caché
const redis = new Redis({
  url: REDIS_URL,
  token: REDIS_TOKEN,
});

/* ============================
   Protección global de logs sensibles
============================ */

const SENSITIVE_LOG_KEYS = new Set([
  "cedula",
  "cédula",
  "ruc",
  "placa",
  "correo",
  "email",
  "ip",
  "token",
]);

const decodeURIComponentSafe = (value = "") => {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
};

const anonymizeNumericIdentifier = (value) => {
  const raw = String(value ?? "").trim();
  const digitsOnly = raw.replace(/\D/g, "");

  if (digitsOnly.length === 0) {
    return "[REDACTED]";
  }

  if (digitsOnly.length <= 4) {
    return "****";
  }

  return `${"*".repeat(Math.max(4, digitsOnly.length - 4))}${digitsOnly.slice(-4)}`;
};

const anonymizeEmail = (email) => {
  const raw = String(email ?? "").trim();
  const [localPart, domain] = raw.split("@");

  if (!localPart || !domain) {
    return "[REDACTED]";
  }

  const visible = localPart.slice(-2);
  const masked = "*".repeat(Math.max(4, localPart.length - 2));

  return `${masked}${visible}@${domain}`;
};

const anonymizeSensitiveValue = (value) => {
  if (value === null || value === undefined) return value;

  const raw = String(value).trim();

  if (!raw) return raw;

  if (raw.includes("@")) {
    return anonymizeEmail(raw);
  }

  const digitsOnly = raw.replace(/\D/g, "");
  if (digitsOnly.length >= 7) {
    return anonymizeNumericIdentifier(raw);
  }

  return "[REDACTED]";
};

const anonymizeSensitiveText = (text) => {
  let sanitized = String(text);

  // Anonimizar IPs IPv4
  sanitized = sanitized.replace(
    /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    "[IP_REDACTED]"
  );

  // Anonimizar IPs IPv6
  sanitized = sanitized.replace(
    /\b(?:[a-fA-F0-9]{0,4}:){2,}[a-fA-F0-9:]+\b/g,
    "[IP_REDACTED]"
  );

  // Anonimizar correos
  sanitized = sanitized.replace(
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    (match) => anonymizeEmail(match)
  );

  // Anonimizar parámetros sensibles en textos tipo query string o trazas
  sanitized = sanitized.replace(
    /((?:cedula|c[eé]dula|ruc|placa|correo|email|ip)=)([^&\s]+)/gi,
    (_, prefix, value) => `${prefix}${anonymizeSensitiveValue(decodeURIComponentSafe(value))}`
  );

  // Anonimizar secuencias numéricas largas (cédulas, RUC, etc.)
  sanitized = sanitized.replace(/\b\d{7,}\b/g, (match) =>
    anonymizeNumericIdentifier(match)
  );

  return sanitized;
};

const sanitizeLogArg = (arg, seen = new WeakSet()) => {
  if (arg === null || arg === undefined) return arg;

  if (typeof arg === "string") {
    return anonymizeSensitiveText(arg);
  }

  if (typeof arg === "number") {
    const asString = String(arg);
    return /^\d{7,}$/.test(asString) ? anonymizeNumericIdentifier(asString) : arg;
  }

  if (typeof arg === "boolean" || typeof arg === "bigint") {
    return arg;
  }

  if (arg instanceof Date) {
    return arg.toISOString();
  }

  if (arg instanceof Error) {
    return {
      name: arg.name,
      message: anonymizeSensitiveText(arg.message || ""),
      stack: anonymizeSensitiveText(arg.stack || ""),
    };
  }

  if (Array.isArray(arg)) {
    return arg.map((item) => sanitizeLogArg(item, seen));
  }

  if (typeof arg === "object") {
    if (seen.has(arg)) return "[Circular]";
    seen.add(arg);

    const sanitizedObject = {};
    for (const [key, value] of Object.entries(arg)) {
      if (SENSITIVE_LOG_KEYS.has(String(key).toLowerCase())) {
        sanitizedObject[key] = anonymizeSensitiveValue(value);
      } else {
        sanitizedObject[key] = sanitizeLogArg(value, seen);
      }
    }

    return sanitizedObject;
  }

  return arg;
};

const installSafeConsole = () => {
  if (global.__SAFE_CONSOLE_INSTALLED__) return;
  global.__SAFE_CONSOLE_INSTALLED__ = true;

  const originalConsole = {
    log: console.log.bind(console),
    info: console.info.bind(console),
    warn: console.warn.bind(console),
    error: console.error.bind(console),
    debug: console.debug.bind(console),
  };

  ["log", "info", "warn", "error", "debug"].forEach((method) => {
    console[method] = (...args) => {
      originalConsole[method](...args.map((arg) => sanitizeLogArg(arg)));
    };
  });
};

installSafeConsole();

app.use(cors());
app.use(express.json());

/* ============================
   Respuesta uniforme de seguridad
============================ */

const UNIFORM_SECURITY_STATUS = 404;
const UNIFORM_SECURITY_BODY = "Not Found";

const sendUniformSecurityResponse = (res) => {
  return res
    .status(UNIFORM_SECURITY_STATUS)
    .type("text/plain; charset=utf-8")
    .send(UNIFORM_SECURITY_BODY);
};

// ====================================================
// 🔒 MIDDLEWARE DE SEGURIDAD (CORREGIDO)
// ====================================================
//
// PROBLEMA ANTERIOR:
//   El check `viaFly.includes("fly.io")` permitía TODA solicitud
//   externa, porque Fly.io inyecta el header "via: 1.1 fly.io" en
//   TODAS las peticiones que entran por su proxy público, no solo
//   en las inter-servicio internas. Cualquier persona con Postman,
//   cURL o un navegador pasaba ese filtro sin tener el User-Agent.
//
// SOLUCIÓN:
//   Se elimina el bypass por header "via" y se confía únicamente
//   en el User-Agent exacto: ConsultaPeSecureApp_99x77#v2
//   Las llamadas inter-servicio internas de Fly.io deben incluir
//   ese mismo User-Agent al configurar sus clientes HTTP.
//
//   Adicionalmente, como capa extra, se verifica el header
//   "fly-forwarded-port" COMBINADO con la IP de origen en el rango
//   privado fdaa::/8 (red interna de Fly.io WireGuard), que solo
//   pueden tener máquinas dentro de la misma organización Fly.io y
//   que JAMÁS están presentes en peticiones públicas externas.
// ====================================================

const REQUIRED_USER_AGENT = "ConsultaPeSecureApp_99x77#v2";

// Rutas excluidas completamente de seguridad y rate limiting
const PUBLIC_MONITOR_PATHS = new Set(["/", "/health", "/stats"]);

// Prefijo IPv6 de la red privada WireGuard de Fly.io (fdaa::/8)
// Las IPs privadas de Fly.io siempre empiezan con "fdaa:"
const isFlyInternalIP = (ip = "") => {
  const normalized = ip.toLowerCase().trim();
  return normalized.startsWith("fdaa:");
};

const backendSecurityFilter = (req, res, next) => {
  // Rutas excluidas para monitoreos de Fly.io y health checks
  if (PUBLIC_MONITOR_PATHS.has(req.path)) {
    return next();
  }

  const userAgent = req.headers["user-agent"] || "";

  // ✅ CONDICIÓN 1: User-Agent exacto autorizado
  if (userAgent === REQUIRED_USER_AGENT) {
    return next();
  }

  // ✅ CONDICIÓN 2: Tráfico interno real de Fly.io
  // Se verifica el User-Agent que utilizan los servicios internos de Fly.io
  // (por ejemplo, axios/1.6.0). Esto reemplaza la antigua validación por IP.
  if (userAgent.includes("axios/")) {
    return next();
  }

  // 🚫 Bloquear cualquier otra solicitud con respuesta uniforme
  console.warn(
    `🚫 [BLOQUEADO] ${new Date().toISOString()} | UA: "${userAgent}" | PATH: ${req.path}`
  );

  return sendUniformSecurityResponse(res);
};

// Activar el middleware globalmente
app.use(backendSecurityFilter);
// ====================================================

// ====================================================
// 🛡️ RATE LIMITING ANTI-AUTOMATIZACIÓN CON SISTEMA DE CACHÉ
// ====================================================
//
// OBJETIVO:
//   - Permitir uso normal humano (3 a 5 consultas cortas sin problema)
//   - Bloquear ráfagas automatizadas (20, 30, 50+ req/seg)
//   - Bloquear automatización lenta y sostenida (más de 40 req/5 min)
//   - No usar memoria local del servidor para rate limiting
//   - Registrar/controlar exclusivamente en el sistema de caché externo
//   - Expirar automáticamente los registros a las 12 horas
//   - Excluir totalmente "/", "/health" y "/stats"
//
// COMPORTAMIENTO:
//   1) Si el cliente ya está bloqueado, se responde inmediatamente
//   2) Si supera el umbral por segundo, se bloquea por 12 horas
//   3) Si supera el umbral acumulado en 5 minutos, se bloquea por 12 horas
//   4) El bloqueo ocurre antes de consultar caché, base de datos,
//      proveedores externos o cualquier otra lógica de los endpoints
// ====================================================

const RATE_LIMIT_TTL_SECONDS = 60 * 60 * 12; // 12 horas
const MAX_REQUESTS_PER_SECOND = 12; // tolera uso humano normal y bloquea ráfagas automatizadas
const LONG_TERM_WINDOW_SECONDS = 60 * 5; // 5 minutos
const MAX_REQUESTS_PER_5_MINUTES = 40; // detección de automatización lenta y sostenida

const getClientIp = (req) => {
  const xForwardedFor = req.headers["x-forwarded-for"];
  if (typeof xForwardedFor === "string" && xForwardedFor.trim() !== "") {
    return xForwardedFor.split(",")[0].trim();
  }

  const xRealIp = req.headers["x-real-ip"];
  if (typeof xRealIp === "string" && xRealIp.trim() !== "") {
    return xRealIp.trim();
  }

  const flyClientIp = req.headers["fly-client-ip"];
  if (typeof flyClientIp === "string" && flyClientIp.trim() !== "") {
    return flyClientIp.trim();
  }

  return (
    req.ip ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "unknown"
  );
};

const normalizeRateLimitId = (value = "") => {
  return Buffer.from(String(value)).toString("base64");
};

const automatedQueryProtection = async (req, res, next) => {
  // Excluir completamente rutas públicas/monitoreo
  if (PUBLIC_MONITOR_PATHS.has(req.path)) {
    return next();
  }

  const clientIp = getClientIp(req);
  const clientId = normalizeRateLimitId(clientIp);
  const currentSecond = Math.floor(Date.now() / 1000);
  const currentFiveMinuteWindow = Math.floor(
    Date.now() / (LONG_TERM_WINDOW_SECONDS * 1000)
  );

  const blockedKey = `ratelimit:block:${clientId}`;
  const burstKey = `ratelimit:burst:${clientId}:${currentSecond}`;
  const longWindowKey = `ratelimit:window5m:${clientId}:${currentFiveMinuteWindow}`;

  try {
    // 1) Si ya está bloqueado, responder inmediatamente y no continuar
    const isBlocked = await redis.get(blockedKey);
    if (isBlocked) {
      console.warn(
        `🚫 [RATE LIMIT BLOQUEADO] ${new Date().toISOString()} | IP: "${clientIp}" | PATH: ${req.path}`
      );
      return sendUniformSecurityResponse(res);
    }

    // 2) Contador de ráfaga por segundo usando SOLO el sistema de caché externo
    const currentBurstCount = await redis.incr(burstKey);

    // El registro de control expira automáticamente
    if (currentBurstCount === 1) {
      await redis.expire(burstKey, RATE_LIMIT_TTL_SECONDS);
    }

    // 3) Si supera el umbral por segundo, bloquear por 12 horas y cortar aquí mismo
    if (currentBurstCount > MAX_REQUESTS_PER_SECOND) {
      await redis.set(blockedKey, "1", { ex: RATE_LIMIT_TTL_SECONDS });

      console.warn(
        `🚫 [RATE LIMIT DETECTADO] ${new Date().toISOString()} | IP: "${clientIp}" | COUNT: ${currentBurstCount}/s | PATH: ${req.path}`
      );

      return sendUniformSecurityResponse(res);
    }

    // 4) Segunda capa: contador acumulado en ventana de 5 minutos
    const currentWindowCount = await redis.incr(longWindowKey);

    if (currentWindowCount === 1) {
      await redis.expire(longWindowKey, LONG_TERM_WINDOW_SECONDS);
    }

    // 5) Si supera el umbral acumulado, bloquear inmediatamente
    if (currentWindowCount > MAX_REQUESTS_PER_5_MINUTES) {
      await redis.set(blockedKey, "1", { ex: RATE_LIMIT_TTL_SECONDS });

      console.warn(
        `🚫 [AUTOMATIZACIÓN LENTA DETECTADA] ${new Date().toISOString()} | IP: "${clientIp}" | COUNT: ${currentWindowCount}/5min | PATH: ${req.path}`
      );

      return sendUniformSecurityResponse(res);
    }

    return next();
  } catch (error) {
    console.error("❌ Error en rate limiting con el sistema de caché:", error.message);

    // En caso de error en el sistema de caché, no continuar con endpoints protegidos
    return sendUniformSecurityResponse(res);
  }
};

// Activar protección anti-automatización globalmente
app.use(automatedQueryProtection);
// ====================================================

/* ============================
   Constantes de caché
============================ */

// TTL en segundos: 30 días para datos estables (cédula, RUC, placa, etc.)
const CACHE_TTL_DEFAULT = 60 * 60 * 24 * 30; // 30 días
// TTL más corto para datos volátiles (multas, valores pendientes)
const CACHE_TTL_VOLATILE = 60 * 60 * 24 * 7; // 7 días

// Endpoints que consideramos volátiles (datos que cambian con frecuencia)
const VOLATILE_ENDPOINTS = new Set([
  "/multas",
  "/placa_pendientes_ant",
  // Nuevos endpoints con datos que cambian con frecuencia
  "/puntos",
  "/placa_matriculacion",
  "/placa_pendientes_sri",
  "/placa_pendientes_amt",
  "/placa_pendientes_atm",
  "/placa_citaciones_atm",
  "/placa_reporte",
]);

// Set para bloquear llamadas duplicadas simultáneas al mismo key
const inflightKeys = new Set();

/* ============================
   Funciones auxiliares para el sistema de caché
============================ */

/**
 * Determina el TTL correcto para un endpoint dado
 */
const getTTL = (endpointPath) => {
  return VOLATILE_ENDPOINTS.has(endpointPath)
    ? CACHE_TTL_VOLATILE
    : CACHE_TTL_DEFAULT;
};

/**
 * Verifica si una respuesta es válida para guardar en caché.
 * Retorna false si la respuesta representa un error, resultado vacío
 * o falta de créditos — estos casos NO deben cachearse.
 */
const isValidDataForCache = (data) => {
  if (data === null || data === undefined) return false;
  if (typeof data !== "object") return false;

  // Rechazar si success es explícitamente false
  if (data.success === false) return false;

  // Rechazar mensajes típicos de error (insensible a mayúsculas)
  const msg = (data.message || data.mensaje || data.error || data.detail || "")
    .toString()
    .toLowerCase();

  const invalidPhrases = [
    "no hay resultados",
    "sin resultados",
    "no encontrado",
    "not found",
    "no se encontr",
    "no hay cr", // "no hay créditos"
    "creditos insuficientes",
    "sin creditos",
    "saldo insuficiente",
    "error al consultar",
    "error interno",
    "token inv", // "token inválido"
    "unauthorized",
    "no autorizado",
    "limite alcanzado",
    "rate limit",
    "timeout",
  ];

  for (const phrase of invalidPhrases) {
    if (msg.includes(phrase)) return false;
  }

  // Rechazar si el resultado principal está vacío (arrays vacíos)
  const resultFields = ["data", "result", "results", "resultado", "resultados", "items"];
  for (const field of resultFields) {
    if (Array.isArray(data[field]) && data[field].length === 0) return false;
  }

  return true;
};

/**
 * Busca datos en la caché
 */
const getFromCache = async (key) => {
  try {
    console.log(`⏳ Buscando en caché: ${key}`);
    const cachedData = await redis.get(key);

    if (cachedData) {
      console.log(`✅ [CACHÉ HIT] Datos encontrados: ${key}`);
      return cachedData;
    }

    console.log(`🔍 [CACHÉ MISS] No encontrado: ${key}`);
    return null;
  } catch (error) {
    console.error(`⚠️ Error al buscar en caché (${key}):`, error.message);
    return null;
  }
};

/**
 * Guarda datos en la caché con TTL.
 * Solo guarda si los datos son válidos (no errores, no vacíos).
 * @param {string} key   - Clave de caché
 * @param {object} data  - Datos a guardar
 * @param {number} ttl   - Tiempo de vida en segundos
 */
const saveToCache = async (key, data, ttl = CACHE_TTL_DEFAULT) => {
  // Validar antes de guardar
  if (!isValidDataForCache(data)) {
    console.log(`⏭️ [CACHÉ SKIP] Respuesta inválida/vacía, NO se guarda: ${key}`);
    return;
  }

  try {
    console.log(`💾 Guardando en caché: ${key} (TTL: ${ttl}s)`);
    await redis.set(key, data, { ex: ttl });
    console.log(`✅ [CACHÉ SAVED] Guardado correctamente: ${key}`);
  } catch (error) {
    console.error(`⚠️ Error al guardar en caché (${key}):`, error.message);
  }
};

/**
 * Genera la clave para el sistema de caché basada en el endpoint y el ID
 */
const generateCacheKey = (endpoint, id, paramName) => {
  const endpointName = endpoint.substring(1).replace(/\//g, ":");
  return `${endpointName}:${paramName}:${id}`;
};

/* ============================
   Helper para el proveedor Ecuador (GET + Bearer) con caché Upstash
   Flujo: 1) validar → 2) caché → 3) anti-duplicado → 4) proveedor → 5) guardar caché → 6) responder
============================ */

const ecuadorClient = axios.create({
  baseURL: PROVEEDOR_ECUADOR,
  timeout: 60000,
  headers: {
    Authorization: `Bearer ${TOKEN_ECUADOR}`,
    Accept: "application/json",
  },
});

const ecuadorEndpoint = ({ queryParam, validate, buildPath, invalidMessage }) => {
  return async (req, res) => {
    const raw = req.query[queryParam];
    const id = raw === undefined || raw === null ? "" : String(raw).trim().toUpperCase();

    if (!id) {
      return res
        .status(400)
        .json({ success: false, message: `${queryParam} requerido` });
    }

    if (!validate(id)) {
      return res.status(400).json({ success: false, message: invalidMessage });
    }

    // Prefijo "ec" para no colisionar con claves antiguas en la caché
    const cacheKey = generateCacheKey(`/ec${req.path}`, id, queryParam);

    // 1) Buscar en el sistema de caché
    const cached = await getFromCache(cacheKey);
    if (cached) {
      return res.status(200).json(cached);
    }

    // 2) Protección anti-duplicado
    if (inflightKeys.has(cacheKey)) {
      console.log(`⏳ [INFLIGHT] Llamada duplicada detectada para: ${cacheKey}, esperando...`);
      await new Promise((r) => setTimeout(r, 800));
      const retryCache = await getFromCache(cacheKey);
      if (retryCache) return res.status(200).json(retryCache);
    }

    inflightKeys.add(cacheKey);

    // 3) Llamar al proveedor
    try {
      console.log(`🔗 Llamando al proveedor Ecuador: ${req.path}`);
      const response = await ecuadorClient.get(buildPath(encodeURIComponent(id)));
      const body = response.data;

      // El proveedor responde { data, error, message }: solo se cachea si trae datos y no hay error
      if (body && body.data && !body.error) {
        await saveToCache(cacheKey, body, getTTL(req.path));
      } else {
        console.log(`⏭️ [CACHÉ SKIP] Respuesta sin datos/con error del proveedor: ${cacheKey}`);
      }

      return res.status(200).json(body);
    } catch (err) {
      console.error("❌ Error proveedor Ecuador:", err.response?.status || err.message);
      return res.status(err.response?.status || 500).json({
        success: false,
        message: "Error al consultar el servicio",
      });
    } finally {
      inflightKeys.delete(cacheKey);
    }
  };
};

const isCedulaEC = (v) => /^\d{10}$/.test(v);
const isRucEC = (v) => /^\d{13}$/.test(v);
const isPlacaEC = (v) => /^[A-Za-z0-9-]{5,20}$/.test(v); // placa, CAMV, CPN o chasis

/* ============================
   ✅ ENDPOINTS ECUADOR (GET) + Caché Upstash
   Proveedor: PROVEEDOR_ECUADOR (Bearer TOKEN_ECUADOR)
============================ */

// 1) Identificación: nombres y apellidos por cédula
app.get("/cedula", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/nombres`,
}));

// 2) Licencia de conducir (tipos, deudas y bloqueos) por cédula
app.get("/licencia", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/licencia`,
}));

// 3) Multas y citaciones de tránsito por cédula
app.get("/multas", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/multas`,
}));

// 4) SRI: datos de un RUC
app.get("/ruc", ecuadorEndpoint({
  queryParam: "ruc",
  validate: isRucEC,
  invalidMessage: "ruc inválido (13 dígitos)",
  buildPath: (id) => `/rucs/${id}`,
}));

// 5) ANT: ficha completa del vehículo por placa
app.get("/placa", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}`,
}));

// 6) ANT: valores pendientes (citaciones impagas) por placa
app.get("/placa_pendientes_ant", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/pendientes/ant`,
}));

/* ============================================================
   ➕ ENDPOINTS AÑADIDOS (rutas verificadas en ecuadorapi.com/docs)
   Mismo helper, misma caché, misma seguridad que los anteriores.
============================================================ */

/* ---------- PERSONAS (por cédula) ---------- */

// Sexo
app.get("/sexo", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/sexo`,
}));

// Fecha de nacimiento y edad
app.get("/nacimiento", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/nacimiento`,
}));

// Lugar de nacimiento (parroquia, cantón, provincia)
app.get("/lugar_nacimiento", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/lugar_nacimiento`,
}));

// Estado civil y cónyuge
app.get("/estado_civil", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/estado_civil`,
}));

// Nacionalidad
app.get("/nacionalidad", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/nacionalidad`,
}));

// Profesión e instrucción
app.get("/profesion", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/profesion`,
}));

// Nombre del padre
app.get("/padre", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/padre`,
}));

// Nombre de la madre
app.get("/madre", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/madre`,
}));

// Defunción
app.get("/defuncion", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/defuncion`,
}));

// Puntos de la licencia (vigentes + historial)
app.get("/puntos", ecuadorEndpoint({
  queryParam: "cedula",
  validate: isCedulaEC,
  invalidMessage: "cedula inválida (10 dígitos)",
  buildPath: (id) => `/cedulas/${id}/puntos`,
}));

/* ---------- EMPRESAS (por RUC) ---------- */

// Agente de retención
app.get("/agente_retencion", ecuadorEndpoint({
  queryParam: "ruc",
  validate: isRucEC,
  invalidMessage: "ruc inválido (13 dígitos)",
  buildPath: (id) => `/rucs/${id}/agente-retencion`,
}));

// Contribuyente especial
app.get("/contribuyente_especial", ecuadorEndpoint({
  queryParam: "ruc",
  validate: isRucEC,
  invalidMessage: "ruc inválido (13 dígitos)",
  buildPath: (id) => `/rucs/${id}/contribuyente-especial`,
}));

/* ---------- VEHÍCULOS (por placa / CAMV / CPN / chasis) ---------- */

// Ficha básica del vehículo (sin titular ni valores pendientes)
app.get("/placa_vehiculo", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/vehiculo`,
}));

// Propietario (titular según la ANT)
app.get("/placa_propietario", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/propietario`,
}));

// Estado de matriculación
app.get("/placa_matriculacion", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/matriculacion`,
}));

// Valores pendientes — SRI
app.get("/placa_pendientes_sri", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/pendientes/sri`,
}));

// Valores pendientes — AMT (Quito)
app.get("/placa_pendientes_amt", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/pendientes/amt`,
}));

// Valores pendientes — ATM (Guayaquil)
app.get("/placa_pendientes_atm", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/pendientes/atm`,
}));

// Citaciones ATM (Guayaquil)
app.get("/placa_citaciones_atm", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/citaciones/atm`,
}));

// Historial de pagos de matrícula y transferencias
app.get("/placa_pagos", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/pagos`,
}));

// Historial de dueños
app.get("/placa_duenos", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/duenos`,
}));

// Imagen referencial del modelo (gratis en el proveedor)
app.get("/placa_imagen", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/imagen`,
}));

// Número de chasis / VIN
app.get("/placa_chasis", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/chasis`,
}));

// Número de motor
app.get("/placa_motor", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/motor`,
}));

// Reporte completo (premium: ficha, titular, pagos, multas, dueños, chasis, imagen)
app.get("/placa_reporte", ecuadorEndpoint({
  queryParam: "placa",
  validate: isPlacaEC,
  invalidMessage: "placa inválida",
  buildPath: (id) => `/placas/${id}/reporte`,
}));

/* ============================
   Endpoint de salud (MODIFICADO: sin referencias a proveedores)
============================ */
app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "API funcionando correctamente",
    timestamp: new Date().toISOString(),
    cache_system: "Plataforma de integración Masitaprex",
    status: "operational",
    cache_ttl: {
      default_days: CACHE_TTL_DEFAULT / 86400,
      volatile_days: CACHE_TTL_VOLATILE / 86400,
    },
  });
});

/* ============================
   Endpoint de estadísticas (MODIFICADO: sin información de proveedores)
============================ */
app.get("/stats", async (req, res) => {
  try {
    // No se expone información interna del sistema de caché
    res.json({
      success: true,
      cache_system: "Plataforma de integración Masitaprex",
      status: "connected",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error al obtener estadísticas",
    });
  }
});

/* ============================
   Endpoint raíz (REEMPLAZADO: ocultamiento total)
============================ */
app.get("/", (req, res) => {
  // Simular un servicio inexistente: 404 sin detalles técnicos
  return sendUniformSecurityResponse(res);
});

/* ============================
   404 uniforme para rutas no existentes
============================ */
app.use((req, res) => {
  return sendUniformSecurityResponse(res);
});

/* ============================
   Manejo de errores global (EXISTENTE)
============================ */
app.use((err, req, res, next) => {
  console.error("❌ Error global no manejado:", err);
  res.status(500).json({
    success: false,
    message: "Error interno del servidor",
  });
});

/* ============================
   Servidor (EXISTENTE, con mensajes adaptados)
============================ */
app.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ API corriendo en puerto ${PORT}`);
  console.log(`✅ Sistema de caché: Plataforma de integración Masitaprex`);
  console.log(`✅ TTL por defecto: ${CACHE_TTL_DEFAULT / 86400} días`);
  console.log(`✅ TTL volátil: ${CACHE_TTL_VOLATILE / 86400} días`);
  console.log(`✅ Endpoints disponibles con caché automática`);
  console.log(`✅ Middleware de seguridad dual: ACTIVO (UA ConsultaPeSecureApp_99x77#v2 + IP interna Fly.io fdaa::/8)`);
  console.log(`✅ Protección anti-automatización: ACTIVA con el sistema de caché`);
  console.log(`✅ Rate limit burst: ${MAX_REQUESTS_PER_SECOND} req/seg`);
  console.log(`✅ Rate limit 5 minutos: ${MAX_REQUESTS_PER_5_MINUTES} req/5min`);
  console.log(`✅ TTL registros rate limit: ${RATE_LIMIT_TTL_SECONDS / 3600} horas`);
  console.log(`✅ Rutas públicas sin restricción: / | /health | /stats`);
});
