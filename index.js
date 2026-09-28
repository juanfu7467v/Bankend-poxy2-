import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import axios from "axios";
import { Redis } from "@upstash/redis";

// Carga las variables de entorno desde .env
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// Variables de configuración del servicio externo
const TOKEN_LEDER = process.env.TOKEN_LEDER;

// ✅ URL base (desde secrets / env)
const URL_BASE1 = process.env.URL_BASE1; // https://bankend-tlgm-2p.fly.dev
const URL_BASE2 = process.env.URL_BASE2;

if (!URL_BASE1 || !URL_BASE2) {
  console.error(
    "❌ ERROR: Variables URL_BASE1 y URL_BASE2 deben estar configuradas en secrets/.env"
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
  "dni",
  "ruc",
  "telefono",
  "teléfono",
  "numero",
  "número",
  "documento",
  "doc",
  "cedula",
  "cédula",
  "pasaporte",
  "carnet_extranjeria",
  "placa",
  "query",
  "data",
  "nombres",
  "apepaterno",
  "apematerno",
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
    /((?:dni|ruc|telefono|tel[eé]fono|numero|n[uú]mero|documento|doc|cedula|c[eé]dula|pasaporte|carnet_extranjeria|placa|query|data|nombres|apepaterno|apematerno|correo|email|ip)=)([^&\s]+)/gi,
    (_, prefix, value) => `${prefix}${anonymizeSensitiveValue(decodeURIComponentSafe(value))}`
  );

  // Anonimizar secuencias numéricas largas (DNI, RUC, teléfonos, etc.)
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

// TTL en segundos: 30 días para datos estables (DNI, RENIEC, RUC, etc.)
const CACHE_TTL_DEFAULT = 60 * 60 * 24 * 30; // 30 días
// TTL más corto para datos volátiles (teléfonos, movimientos, consumos)
const CACHE_TTL_VOLATILE = 60 * 60 * 24 * 7; // 7 días

// Endpoints que consideramos volátiles (datos que cambian con frecuencia)
const VOLATILE_ENDPOINTS = new Set([
  "/movimientos",
  "/consumos",
  "/telefonia-num",
  "/telefonia-doc",
  "/azura_bitel",
  "/azura_claro",
  "/azura_entel",
  "/azura_movistar",
]);

// Set para bloquear llamadas duplicadas simultáneas al mismo key
const inflightKeys = new Set();

/* ============================
   Funciones auxiliares para el sistema de caché
============================ */

/**
 * Limpia la respuesta del servicio externo removiendo los campos de metadata
 */
const cleanLederDataResponse = (data) => {
  if (!data || typeof data !== "object") return data;
  const cleanedData = { ...data };
  delete cleanedData["developed-by"];
  delete cleanedData["credits"];
  return cleanedData;
};

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
    "error leder",
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
 * Verifica si la respuesta del servicio externo es un error explícito
 */
const isErrorResponse = (data) => {
  return (
    data &&
    data.success === false &&
    data.message === "Error al consultar el servicio"
  );
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
   Función centralizada para manejar el servicio externo (antes LederData)
============================ */

const fetchFromLederData = async (
  req,
  res,
  lederDataPath,
  payload,
  id,
  paramName = "dni"
) => {
  try {
    const url = `https://leder-data-api.ngrok.dev/v1.7${lederDataPath}`;
    console.log(
      `🔗 Llamando a intermediario tecnológico Masitaprex: ${req.path} para ${paramName}=${id}`
    );

    const postPayload = {
      ...payload,
      token: TOKEN_LEDER,
    };

    const response = await axios.post(url, postPayload);
    const resultData = response.data;

    // Verificar si es una respuesta de error
    if (isErrorResponse(resultData)) {
      console.log(`❌ Respuesta de error del servicio, NO se guarda en caché: ${id}`);
      return res.status(200).json(resultData);
    }

    // Limpiar la respuesta antes de guardarla
    const cleanedData = cleanLederDataResponse(resultData);

    // Guardar en caché con TTL apropiado
    if (id) {
      const cacheKey = generateCacheKey(req.path, id, paramName);
      const ttl = getTTL(req.path);
      await saveToCache(cacheKey, cleanedData, ttl);
    }

    return res.status(200).json(resultData); // Devolver la respuesta original al usuario
  } catch (err) {
    console.error("❌ Error en el servicio externo:", err.response?.data || err.message);
    return res.status(err.response?.status || 500).json({
      success: false,
      message: "Error al consultar el servicio",
    });
  }
};

/* ============================
   Middleware para endpoints con caché (servicio externo)
============================ */

const cacheableEndpoint = (lederDataPath, paramName = "dni") => {
  return async (req, res) => {
    const id = req.query[paramName];
    if (!id) {
      return res
        .status(400)
        .json({ success: false, message: `${paramName} requerido` });
    }

    // 1. Buscar en caché
    const cacheKey = generateCacheKey(req.path, id, paramName);
    const cachedResult = await getFromCache(cacheKey);

    if (cachedResult) {
      return res.status(200).json(cachedResult);
    }

    // 2. Protección anti-duplicado: si ya hay una llamada en vuelo para esta clave,
    //    esperamos brevemente y reintentamos la caché antes de volver a llamar.
    if (inflightKeys.has(cacheKey)) {
      console.log(`⏳ [INFLIGHT] Llamada duplicada detectada para: ${cacheKey}, esperando...`);
      await new Promise((r) => setTimeout(r, 800));
      const retryCache = await getFromCache(cacheKey);
      if (retryCache) return res.status(200).json(retryCache);
    }

    inflightKeys.add(cacheKey);

    // 3. No hay caché, llamar al servicio externo
    const payload = { [paramName]: id };

    if (req.path === "/reniec") {
      payload.source = req.query.source || "database";
    }

    try {
      if (req.path === "/sunat" || req.path === "/sunat-razon") {
        await fetchFromLederData(req, res, lederDataPath, { data: id }, id, paramName);
      } else {
        await fetchFromLederData(req, res, lederDataPath, payload, id, paramName);
      }
    } finally {
      inflightKeys.delete(cacheKey);
    }
  };
};

/* ============================
   Transformación para la API externa de árbol genealógico
============================ */

const transformArbolDataToFamilyFormat = (apiResponse) => {
  if (
    !apiResponse ||
    apiResponse.message !== "found data" ||
    !apiResponse.result ||
    !apiResponse.result.coincidences
  ) {
    console.warn("⚠️ Respuesta de la API de Árbol Genealógico no válida o vacía.");
    return {
      success: false,
      message: "No se encontraron coincidencias o la respuesta fue inválida.",
    };
  }

  const { person, coincidences } = apiResponse.result;

  const transformedData = {
    dni: person.dni,
    apellidos_nombres: `${person.ap} ${person.am} ${person.nom}`,
    edad: person.edad,
    success: true,
    message: "Datos de Árbol Genealógico (API Externa) obtenidos y transformados.",
    familia: coincidences.map((c) => ({
      dni: c.dni,
      apellidos_nombres: `${c.ap} ${c.am} ${c.nom}`,
      edad: c.edad,
      relacion_tipo: c.tipo,
      relacion_detalle: c.verificacion_relacion,
      fec_emision: null,
      est_civil: null,
      departamento: null,
    })),
  };

  return transformedData;
};

/**
 * Función para la nueva API externa del árbol genealógico con caché
 */
const fetchFromExternalArbolAPI = async (req, res, id) => {
  const url = `https://banckend-poxyv1-cosultape-masitaprex.fly.dev/arbol?dni=${id}`;

  try {
    // 1. Buscar en caché primero
    const cacheKey = generateCacheKey(req.path, id, "dni");
    const cachedResult = await getFromCache(cacheKey);

    if (cachedResult) {
      return res.status(200).json(cachedResult);
    }

    // 2. No hay caché, llamar a la API externa
    console.log(`🔗 Llamando a API Externa de Árbol Genealógico: ${url}`);
    const response = await axios.get(url);
    const apiResponse = response.data;

    // 3. Transformar la respuesta
    const transformedData = transformArbolDataToFamilyFormat(apiResponse);

    // 4. Guardar en caché solo si es exitoso
    await saveToCache(cacheKey, transformedData, CACHE_TTL_DEFAULT);

    // 5. Devolver el resultado transformado
    return res.status(200).json(transformedData);
  } catch (err) {
    console.error("❌ API Árbol Genealógico Externo error:", err.response?.data || err.message);
    return res.status(err.response?.status || 500).json({
      success: false,
      message: "Error al consultar la API externa del Árbol Genealógico",
    });
  }
};

/* ============================
   Helper genérico para APIs externas GET con caché
   Flujo: 1) cache → 2) fetch GET → 3) validar → 4) save cache → 5) return
============================ */

const fetchExternalGetWithCache = async ({
  req,
  res,
  baseUrl,
  externalPath,
  queryParam,
  required = true,
  cacheParamName = null,
}) => {
  const paramNameForCache = cacheParamName || queryParam;
  const value = req.query[queryParam];

  if (required && (!value || String(value).trim() === "")) {
    return res
      .status(400)
      .json({ success: false, message: `${queryParam} requerido` });
  }

  const id = String(value).trim();
  const cacheKey = generateCacheKey(req.path, id, paramNameForCache);

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

  // 3) Llamar API externa GET
  const url = `${baseUrl}${externalPath}`;
  try {
    console.log(`🔗 Llamando a API Externa: ${url} (${queryParam}=${id})`);
    const response = await axios.get(url, {
      params: { [queryParam]: id },
    });

    const data = response.data;
    const ttl = getTTL(req.path);

    // 4) Guardar solo si la respuesta es válida (no errores, no vacíos)
    await saveToCache(cacheKey, data, ttl);

    // 5) Devolver resultado
    return res.status(200).json(data);
  } catch (err) {
    console.error("❌ Error API externa:", err.response?.data || err.message);
    return res.status(err.response?.status || 500).json({
      success: false,
      message: "Error al consultar API externa",
    });
  } finally {
    inflightKeys.delete(cacheKey);
  }
};

/* ============================
   Helper para endpoint con múltiples query params (dni_nombres)
   Cache key basada en (nombres|apepaterno|apematerno)
============================ */

const fetchExternalGetMultiParamsWithCache = async ({
  req,
  res,
  baseUrl,
  externalPath,
  requiredParams,
}) => {
  for (const p of requiredParams) {
    const v = req.query[p];
    if (!v || String(v).trim() === "") {
      return res.status(400).json({ success: false, message: `${p} requerido` });
    }
  }

  // Construir un ID compuesto estable para la caché
  const compositeId = requiredParams
    .map((p) => `${p}=${String(req.query[p]).trim()}`)
    .join("&");

  const cacheKey = generateCacheKey(req.path, compositeId, "query");

  // 1) Buscar en caché
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

  // 3) Llamar API externa GET
  const url = `${baseUrl}${externalPath}`;
  try {
    console.log(`🔗 Llamando a API Externa: ${url} (${compositeId})`);
    const response = await axios.get(url, { params: req.query });
    const data = response.data;

    const ttl = getTTL(req.path);

    // 4) Guardar solo si la respuesta es válida
    await saveToCache(cacheKey, data, ttl);

    // 5) Devolver
    return res.status(200).json(data);
  } catch (err) {
    console.error("❌ Error API externa:", err.response?.data || err.message);
    return res.status(err.response?.status || 500).json({
      success: false,
      message: "Error al consultar API externa",
    });
  } finally {
    inflightKeys.delete(cacheKey);
  }
};

/* ============================
   Endpoints con Lógica de Caché (EXISTENTES - NO TOCAR)
============================ */

// Endpoints de persona
app.get("/reniec", cacheableEndpoint("/persona/reniec", "dni"));
app.get("/denuncias-dni", cacheableEndpoint("/persona/denuncias-policiales-dni", "dni"));
app.get("/sueldos", cacheableEndpoint("/persona/sueldos", "dni"));
app.get("/trabajos", cacheableEndpoint("/persona/trabajos", "dni"));
app.get("/consumos", cacheableEndpoint("/persona/consumos", "dni"));
app.get("/arbol", cacheableEndpoint("/persona/arbol-genealogico", "dni"));

// Endpoints de familia
app.get("/familia1", cacheableEndpoint("/persona/familia-1", "dni"));
app.get("/familia2", cacheableEndpoint("/persona/familia-2", "dni"));
app.get("/familia3", cacheableEndpoint("/persona/familia-3", "dni"));

// Otros endpoints de persona
app.get("/movimientos", cacheableEndpoint("/persona/movimientos-migratorios", "dni"));
app.get("/matrimonios", cacheableEndpoint("/persona/matrimonios", "dni"));
app.get("/empresas", cacheableEndpoint("/persona/empresas", "dni"));
app.get("/direcciones", cacheableEndpoint("/persona/direcciones", "dni"));
app.get("/correos", cacheableEndpoint("/persona/correos", "dni"));
app.get("/fiscalia-dni", cacheableEndpoint("/persona/justicia/fiscalia/dni", "dni"));

// Endpoints de vehículos
app.get("/denuncias-placa", cacheableEndpoint("/persona/denuncias-policiales-placa", "placa"));
app.get("/vehiculos", cacheableEndpoint("/vehiculos/sunarp", "placa"));

// Endpoints de empresa
app.get("/sunat", cacheableEndpoint("/empresa/sunat", "data"));
app.get("/sunat-razon", cacheableEndpoint("/empresa/sunat/razon-social", "data"));

// Endpoints de telefonia
app.get("/telefonia-doc", cacheableEndpoint("/telefonia/documento", "documento"));
app.get("/telefonia-num", cacheableEndpoint("/telefonia/numero", "numero"));

/* ============================
   Endpoint para API externa de árbol genealógico (EXISTENTE)
============================ */
app.get("/arbol-genealogico-externo", async (req, res) => {
  const id = req.query.dni;
  if (!id) {
    return res.status(400).json({ success: false, message: "dni requerido" });
  }

  await fetchFromExternalArbolAPI(req, res, id);
});

/* ============================
   Endpoint sin caché por ID (búsqueda por nombres) (EXISTENTE)
============================ */
app.get("/fiscalia-nombres", async (req, res) => {
  if (!req.query.nombres || !req.query.apepaterno || !req.query.apematerno) {
    return res.status(400).json({
      success: false,
      message: "nombres, apepaterno y apematerno requeridos",
    });
  }

  try {
    const url = `https://leder-data-api.ngrok.dev/v1.7/persona/justicia/fiscalia/nombres`;
    console.log(`🔗 Llamando a intermediario tecnológico Masitaprex: ${req.path} para búsqueda por nombres`);

    const postPayload = {
      nombres: req.query.nombres,
      apepaterno: req.query.apepaterno,
      apematerno: req.query.apematerno,
      token: TOKEN_LEDER,
    };

    const response = await axios.post(url, postPayload);
    const resultData = response.data;

    const cleanedData = cleanLederDataResponse(resultData);

    return res.status(200).json(cleanedData);
  } catch (err) {
    console.error("❌ Error en el servicio externo:", err.response?.data || err.message);
    return res.status(err.response?.status || 500).json({
      success: false,
      message: "Error al consultar el servicio",
    });
  }
});

/* ============================
   ✅ NUEVOS 11 ENDPOINTS (GET) + Caché
============================ */

// 1) Consultar Cédula Venezolana (por número) - BASE1
app.get("/cedula", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE1,
    externalPath: "/cedula",
    queryParam: "cedula",
  });
});

// 2) Consultar Pasaporte - BASE1
app.get("/pasaporte", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE1,
    externalPath: "/pasaporte",
    queryParam: "pasaporte",
  });
});

// 3) Consultar Carnet de Extranjería - BASE1
app.get("/carnet_extranjeria", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE1,
    externalPath: "/carnet_extranjeria",
    queryParam: "carnet_extranjeria",
  });
});

// 4) Obtener DNI Peruano (Por Nombres y Apellidos) - BASE2
app.get("/dni_nombres", async (req, res) => {
  return fetchExternalGetMultiParamsWithCache({
    req,
    res,
    baseUrl: URL_BASE2,
    externalPath: "/dni_nombres",
    requiredParams: ["nombres", "apepaterno", "apematerno"],
  });
});

// 5) Obtener Cédula Venezolana (Por Nombres) - BASE2
app.get("/venezolanos_nombres", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE2,
    externalPath: "/venezolanos_nombres",
    queryParam: "query",
  });
});

// 6) Consulta Telefónica Bitel - BASE1
app.get("/azura_bitel", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE1,
    externalPath: "/azura_bitel",
    queryParam: "query",
  });
});

// 7) Consulta Telefónica Claro - BASE1
app.get("/azura_claro", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE1,
    externalPath: "/azura_claro",
    queryParam: "query",
  });
});

// 8) Consulta Telefónica Entel - BASE1
app.get("/azura_entel", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE1,
    externalPath: "/azura_entel",
    queryParam: "query",
  });
});

// 9) Consulta Telefónica Movistar - BASE1
app.get("/azura_movistar", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE1,
    externalPath: "/azura_movistar",
    queryParam: "query",
  });
});

// 10) Búsqueda por Dirección - BASE1
app.get("/bdir", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE1,
    externalPath: "/bdir",
    queryParam: "direccion",
  });
});

// 11) Consultar AFP - BASE1
app.get("/afp", async (req, res) => {
  return fetchExternalGetWithCache({
    req,
    res,
    baseUrl: URL_BASE1,
    externalPath: "/afp",
    queryParam: "dni",
  });
});

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
