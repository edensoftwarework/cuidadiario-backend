/**
 * index.js — Backend CuidaDiario (VERSIÓN COMPLETA)
 * by EDEN SoftWork
 *
 * ============================================================
 * MÓDULOS:
 *   [B2C] CuidaDiario — App para cuidadores y familiares individuales
 *   [B2B] CuidaDiario PRO — App para instituciones (geriátricos, empresas de cuidado)
 *
 *   Todos los endpoints B2B están bajo /api/b2b/*
 *   Todas las tablas B2B tienen sufijo _b2b
 *   Auth B2B usa el mismo JWT_SECRET pero con campo b2b:true en el payload
 * ============================================================
 * FUNCIONALIDADES INCLUIDAS [B2C]:
 *
 * PUSH NOTIFICATIONS (web-push):
 * 1. require('web-push') — librería para enviar notificaciones push
 * 2. Constantes VAPID — leen las claves de las variables de entorno de Railway
 * 3. webPush.setVapidDetails() — configura la librería al iniciar
 * 4. runMigrations() — crea la tabla push_subscriptions
 * 5. GET  /api/push/vapid-key      — devuelve la clave pública al frontend
 * 6. POST /api/push/subscribe      — guarda la suscripción push del usuario
 * 7. DELETE /api/push/unsubscribe  — elimina la suscripción push del usuario
 * 8. sendPushToUser(userId, payload) — helper interno para enviar push
 * 9. startPushReminders() — chequea cada hora y envía recordatorios de
 *      medicamentos (±35 min), citas del día siguiente, tareas del día (8 AM)
 *
 * RECUPERACIÓN DE CONTRASEÑA (Resend HTTP API — sin SMTP, funciona en Railway):
 * 10. POST /api/forgot-password  — genera token, guarda en DB, envía email
 * 11. POST /api/reset-password   — valida token, actualiza password_hash
 *     → Requiere: RESEND_API_KEY, FRONTEND_URL en Railway env vars
 *
 * SEGURIDAD paciente_id:
 * 12. validatePaciente()   — verifica que el paciente pertenece al usuario
 * 13. resolvePatientId()   — auto-asigna paciente a usuarios free si no viene en el body
 *     Cubre el caso de carrera donde el frontend no setea currentPacienteId a tiempo
 *
 * ANTES DE HACER DEPLOY EN RAILWAY:
 *   package.json dependencies:
 *     "web-push": "^3.6.7"
 *     (nodemailer ya NO es necesario — se usa Resend via HTTPS nativo)
 *
 *   Variables de entorno:
 *     VAPID_PUBLIC_KEY   = <tu clave pública VAPID>
 *     VAPID_PRIVATE_KEY  = <tu clave privada VAPID>
 *     VAPID_EMAIL        = mailto:edensoftwarework@gmail.com
 *     RESEND_API_KEY     = re_xxxxxxxxxx  (de https://resend.com/api-keys)
 *     EMAIL_FROM         = "CuidaDiario <onboarding@resend.dev>"   ← sin dominio propio
 *                        o "CuidaDiario <noreply@tudominio.com>"   ← con dominio verificado
 *     FRONTEND_URL       = https://tu-frontend.com  (sin barra final)
 *
 *   Crear API Key de Resend (gratis, 3000 emails/mes):
 *     1. Registrate en https://resend.com
 *     2. Generá una API Key en https://resend.com/api-keys
 *     3. Agregá RESEND_API_KEY en las variables de entorno de Railway
 * ============================================================
 */

const express = require('express');
const app = express();
const pool = require('./db');
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'tu_clave_secreta';
if (!process.env.JWT_SECRET) {
    console.error('⚠️  CRÍTICO: JWT_SECRET no está configurado en las variables de entorno de Railway. Los tokens pueden ser vulnerables. Configurá esta variable inmediatamente.');
}
const cors = require('cors');

// ========== RATE LIMITING (in-memory, sin dependencias externas) ==========
// Previene ataques de fuerza bruta en endpoints de autenticación.
// Límite: 10 intentos por IP por ventana de 60 segundos.
const _rateLimitStore = new Map();
function rateLimit(maxReq = 10, windowMs = 60000) {
    return (req, res, next) => {
        const key = req.ip || req.headers['x-forwarded-for'] || 'unknown';
        const now = Date.now();
        const windowStart = now - windowMs;
        if (!_rateLimitStore.has(key)) _rateLimitStore.set(key, []);
        const hits = _rateLimitStore.get(key).filter(t => t > windowStart);
        if (hits.length >= maxReq) {
            return res.status(429).json({ error: 'Demasiados intentos. Esperá unos minutos e intentá nuevamente.' });
        }
        hits.push(now);
        _rateLimitStore.set(key, hits);
        // Limpiar entradas viejas periódicamente
        if (_rateLimitStore.size > 5000) {
            for (const [k, times] of _rateLimitStore.entries()) {
                if (times.every(t => t <= windowStart)) _rateLimitStore.delete(k);
            }
        }
        next();
    };
}
const authRateLimit = rateLimit(10, 60000); // 10 intentos / 60 seg
const https = require('https');
const crypto = require('crypto');          // ← nativo Node.js, sin instalar nada
const webPush = require('web-push');       // ← push notifications

// ========== EMAIL VIA RESEND API (HTTP puro — Railway no bloquea puerto 443) ==========
// Railway bloquea puertos SMTP (587/465). Resend usa HTTPS (443) → siempre funciona.
// Plan gratuito: 3000 emails/mes — https://resend.com/
//
// Variables requeridas en Railway:
//   RESEND_API_KEY  = re_xxxxxxxxxx   (de https://resend.com/api-keys)
//   EMAIL_FROM      = "CuidaDiario <onboarding@resend.dev>"   ← sin dominio propio
//                   o "CuidaDiario <noreply@tudominio.com>"   ← con dominio verificado en Resend
//   FRONTEND_URL    = https://tu-frontend.com  (sin barra final)

const RESEND_API_KEY = process.env.RESEND_API_KEY || '';
const EMAIL_FROM     = process.env.EMAIL_FROM || process.env.SMTP_FROM || 'CuidaDiario <onboarding@resend.dev>';
const FRONTEND_URL     = (process.env.FRONTEND_URL     || '').replace(/\/$/, '');
const FRONTEND_URL_PRO = (process.env.FRONTEND_URL_PRO || process.env.FRONTEND_URL || 'https://cuidadiario-pro.edensoftwork.com').replace(/\/$/, '');

// Enviar email via Resend HTTP API (sin nodemailer, sin SMTP)
async function sendEmail({ to, subject, html }) {
    if (!RESEND_API_KEY) {
        console.warn('⚠️  RESEND_API_KEY no configurada — email no enviado');
        return false;
    }
    const from = EMAIL_FROM.includes('<') ? EMAIL_FROM : `CuidaDiario <${EMAIL_FROM}>`;
    const payload = JSON.stringify({ from, to: [to], subject, html });
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.resend.com',
            path: '/emails',
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${RESEND_API_KEY}`,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload)
            }
        };
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 200 || res.statusCode === 201) {
                    resolve(true);
                } else {
                    try {
                        const parsed = JSON.parse(data);
                        reject(new Error(parsed.message || `Resend error ${res.statusCode}`));
                    } catch {
                        reject(new Error(`Resend HTTP ${res.statusCode}: ${data}`));
                    }
                }
            });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}

if (RESEND_API_KEY) {
    console.log('✅ Email via Resend API configurado');
} else {
    console.warn('⚠️  RESEND_API_KEY no configurada — envío de emails desactivado');
}

// ========== CONFIGURACIÓN ==========
const ALLOWED_ORIGINS = [
    'https://cuidadiario.edensoftwork.com',
    'https://cuidadiario-pro.edensoftwork.com',
    'http://localhost:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://127.0.0.1:3000'
];
app.use(cors({
    origin: (origin, callback) => {
        // Permitir requests sin origin (ej: apps móviles, Postman, same-origin)
        if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        console.warn(`[CORS] Bloqueado: ${origin}`);
        callback(new Error('No permitido por CORS'));
    },
    credentials: true
}));
app.use('/api/paypal/webhook', express.raw({ type: 'application/json' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ========== VAPID — Web Push (NUEVO) ==========
const VAPID_PUBLIC_KEY  = process.env.VAPID_PUBLIC_KEY;
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY;
const _vapidEmailRaw    = process.env.VAPID_EMAIL || 'edensoftwarework@gmail.com';
const VAPID_EMAIL       = _vapidEmailRaw.startsWith('mailto:') ? _vapidEmailRaw : `mailto:${_vapidEmailRaw}`;

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
    webPush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
    console.log('✅ Web Push VAPID configurado');
} else {
    console.warn('⚠️  VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY no configuradas — Push notifications desactivadas');
}

// ========== MIGRACIÓN AUTOMÁTICA ==========
async function runMigrations() {
    try {
        // Columna paypal_subscription_id (existente)
        await pool.query(`
            ALTER TABLE usuarios
            ADD COLUMN IF NOT EXISTS paypal_subscription_id VARCHAR(64)
        `);

        // NUEVO: tabla de suscripciones push
        await pool.query(`
            CREATE TABLE IF NOT EXISTS push_subscriptions (
                id               SERIAL PRIMARY KEY,
                usuario_id       INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
                endpoint         TEXT    NOT NULL,
                p256dh           TEXT,
                auth             TEXT,
                created_at       TIMESTAMP DEFAULT NOW(),
                last_success_at  TIMESTAMP,
                UNIQUE(usuario_id, endpoint)
            )
        `);
        // Migración: agregar last_success_at si ya existía la tabla sin esa columna
        await pool.query(`
            ALTER TABLE push_subscriptions ADD COLUMN IF NOT EXISTS last_success_at TIMESTAMP
        `).catch(() => {});

        // NUEVO: columnas para recuperación de contraseña
        await pool.query(`
            ALTER TABLE usuarios
            ADD COLUMN IF NOT EXISTS reset_token          VARCHAR(128),
            ADD COLUMN IF NOT EXISTS reset_token_expires  TIMESTAMP
        `);

        // Zona horaria del usuario (para notificaciones push en su hora local)
        await pool.query(`
            ALTER TABLE usuarios
            ADD COLUMN IF NOT EXISTS timezone VARCHAR(50) DEFAULT 'America/Argentina/Buenos_Aires'
        `);

        // Tabla de deduplicación de notificaciones push
        // Evita reenvíos si el servidor reinicia dentro de la misma ventana de tiempo
        await pool.query(`
            CREATE TABLE IF NOT EXISTS push_sent (
                tag      TEXT      NOT NULL,
                sent_at  TIMESTAMP NOT NULL DEFAULT NOW()
            )
        `);
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_push_sent ON push_sent (tag, sent_at)
        `).catch(() => {});

        // NUEVO: tabla para co-cuidadores (compartir paciente con otro usuario)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS paciente_compartidos (
                id            SERIAL PRIMARY KEY,
                paciente_id   INTEGER NOT NULL REFERENCES pacientes(id) ON DELETE CASCADE,
                propietario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
                invitado_email TEXT NOT NULL,
                invitado_id   INTEGER REFERENCES usuarios(id) ON DELETE SET NULL,
                rol           TEXT NOT NULL DEFAULT 'viewer',
                token         TEXT UNIQUE,
                aceptado      BOOLEAN NOT NULL DEFAULT FALSE,
                created_at    TIMESTAMP DEFAULT NOW(),
                UNIQUE(paciente_id, invitado_email)
            )
        `);

        // NUEVO: columna hora_fin en medicamentos (ventana de vigilia)
        await pool.query(`
            ALTER TABLE medicamentos
            ADD COLUMN IF NOT EXISTS hora_fin VARCHAR(5)
        `);

        // NUEVO: tabla historial de tareas realizadas (similar a historial_medicamentos)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS historial_tareas (
                id              SERIAL PRIMARY KEY,
                usuario_id      INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
                paciente_id     INTEGER REFERENCES pacientes(id) ON DELETE SET NULL,
                tarea_id        INTEGER,
                tarea_titulo    TEXT,
                notas           TEXT,
                fecha           TIMESTAMP NOT NULL DEFAULT NOW()
            )
        `);
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_historial_tareas_usuario ON historial_tareas (usuario_id, fecha DESC)
        `).catch(() => {});

        // NUEVO: flag servidor para modal de bienvenida premium (multi-dispositivo)
        await pool.query(`
            ALTER TABLE usuarios
            ADD COLUMN IF NOT EXISTS premium_welcome_pending BOOLEAN DEFAULT FALSE
        `);

        // NOTAS: tablero visual con recordatorios
        await pool.query(`
            CREATE TABLE IF NOT EXISTS notas (
                id           SERIAL PRIMARY KEY,
                usuario_id   INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
                paciente_id  INTEGER REFERENCES pacientes(id) ON DELETE SET NULL,
                titulo       TEXT,
                contenido    TEXT,
                color        VARCHAR(20) DEFAULT 'amarillo',
                recordatorio TIMESTAMP,
                created_at   TIMESTAMP NOT NULL DEFAULT NOW()
            )
        `);
        await pool.query(`
            CREATE INDEX IF NOT EXISTS idx_notas_usuario ON notas (usuario_id, created_at DESC)
        `).catch(() => {});

        // ============================================================
        // MIGRACIONES B2B — Tablas completamente separadas del modelo B2C
        // ============================================================

        await pool.query(`
            CREATE TABLE IF NOT EXISTS instituciones_b2b (
                id          SERIAL PRIMARY KEY,
                nombre      TEXT NOT NULL,
                tipo        VARCHAR(50) DEFAULT 'geriatrico',
                direccion   TEXT,
                telefono    VARCHAR(30),
                email       TEXT,
                plan        VARCHAR(20) DEFAULT 'basico',
                activa      BOOLEAN DEFAULT TRUE,
                created_at  TIMESTAMP DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS usuarios_b2b (
                id                  SERIAL PRIMARY KEY,
                institucion_id      INTEGER REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                nombre              TEXT NOT NULL,
                email               TEXT UNIQUE NOT NULL,
                password_hash       TEXT NOT NULL,
                rol                 VARCHAR(30) DEFAULT 'cuidador_staff',
                activo              BOOLEAN DEFAULT TRUE,
                reset_token         TEXT,
                reset_token_expiry  TIMESTAMP,
                created_at          TIMESTAMP DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_usuarios_b2b_email ON usuarios_b2b (email)`).catch(() => {});
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_usuarios_b2b_inst ON usuarios_b2b (institucion_id)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS pacientes_b2b (
                id                       SERIAL PRIMARY KEY,
                institucion_id           INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                nombre                   TEXT NOT NULL,
                apellido                 TEXT,
                fecha_nacimiento         DATE,
                dni                      VARCHAR(20),
                habitacion               VARCHAR(20),
                diagnostico              TEXT,
                obra_social              TEXT,
                num_afiliado             TEXT,
                contacto_familiar_nombre TEXT,
                contacto_familiar_tel    TEXT,
                notas_ingreso            TEXT,
                fecha_ingreso            DATE DEFAULT CURRENT_DATE,
                foto_url                 TEXT,
                activo                   BOOLEAN DEFAULT TRUE,
                created_at               TIMESTAMP DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_pacientes_b2b_inst ON pacientes_b2b (institucion_id)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS asignaciones_b2b (
                id              SERIAL PRIMARY KEY,
                institucion_id  INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                cuidador_id     INTEGER NOT NULL REFERENCES usuarios_b2b(id) ON DELETE CASCADE,
                paciente_id     INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                activa          BOOLEAN DEFAULT TRUE,
                created_at      TIMESTAMP DEFAULT NOW(),
                UNIQUE(cuidador_id, paciente_id)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS medicamentos_b2b (
                id              SERIAL PRIMARY KEY,
                institucion_id  INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id     INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                nombre          TEXT NOT NULL,
                dosis           TEXT,
                frecuencia      VARCHAR(30),
                hora_inicio     TIME,
                hora_fin        TIME,
                horarios_custom TEXT,
                instrucciones   TEXT,
                stock           INTEGER,
                activo          BOOLEAN DEFAULT TRUE,
                created_at      TIMESTAMP DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_meds_b2b_paciente ON medicamentos_b2b (paciente_id)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS historial_medicamentos_b2b (
                id                   SERIAL PRIMARY KEY,
                institucion_id       INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id          INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                medicamento_id       INTEGER REFERENCES medicamentos_b2b(id) ON DELETE SET NULL,
                medicamento_nombre   TEXT,
                dosis                TEXT,
                administrado_por     INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
                administrador_nombre TEXT,
                notas                TEXT,
                fecha                TIMESTAMP NOT NULL DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_histmed_b2b ON historial_medicamentos_b2b (paciente_id, fecha DESC)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS citas_b2b (
                id              SERIAL PRIMARY KEY,
                institucion_id  INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id     INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                titulo          TEXT NOT NULL,
                descripcion     TEXT,
                fecha           TIMESTAMP NOT NULL,
                medico          TEXT,
                especialidad    TEXT,
                lugar           TEXT,
                estado          VARCHAR(20) DEFAULT 'pendiente',
                created_by      INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
                created_at      TIMESTAMP DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_citas_b2b_paciente ON citas_b2b (paciente_id, fecha)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS tareas_b2b (
                id              SERIAL PRIMARY KEY,
                institucion_id  INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id     INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                titulo          TEXT NOT NULL,
                descripcion     TEXT,
                categoria       VARCHAR(30),
                frecuencia      VARCHAR(30),
                hora            TIME,
                activa          BOOLEAN DEFAULT TRUE,
                created_by      INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
                created_at      TIMESTAMP DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_tareas_b2b_paciente ON tareas_b2b (paciente_id)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS historial_tareas_b2b (
                id                 SERIAL PRIMARY KEY,
                institucion_id     INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id        INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                tarea_id           INTEGER REFERENCES tareas_b2b(id) ON DELETE SET NULL,
                tarea_titulo       TEXT,
                completado_por     INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
                completador_nombre TEXT,
                notas              TEXT,
                fecha              TIMESTAMP NOT NULL DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_histtar_b2b ON historial_tareas_b2b (paciente_id, fecha DESC)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS sintomas_b2b (
                id                 SERIAL PRIMARY KEY,
                institucion_id     INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id        INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                descripcion        TEXT NOT NULL,
                intensidad         INTEGER,
                registrado_por     INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
                registrador_nombre TEXT,
                fecha              TIMESTAMP NOT NULL DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_sintomas_b2b_paciente ON sintomas_b2b (paciente_id, fecha DESC)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS signos_vitales_b2b (
                id                 SERIAL PRIMARY KEY,
                institucion_id     INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id        INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                tipo               VARCHAR(30),
                valor              TEXT,
                unidad             TEXT,
                notas              TEXT,
                registrado_por     INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
                registrador_nombre TEXT,
                fecha              TIMESTAMP NOT NULL DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_signos_b2b_paciente ON signos_vitales_b2b (paciente_id, fecha DESC)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS contactos_b2b (
                id              SERIAL PRIMARY KEY,
                institucion_id  INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id     INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                nombre          TEXT NOT NULL,
                relacion        TEXT,
                telefono        TEXT,
                email           TEXT,
                es_principal    BOOLEAN DEFAULT FALSE,
                created_at      TIMESTAMP DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_contactos_b2b_paciente ON contactos_b2b (paciente_id)`).catch(() => {});

        await pool.query(`
            CREATE TABLE IF NOT EXISTS notas_b2b (
                id              SERIAL PRIMARY KEY,
                institucion_id  INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id     INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                titulo          TEXT,
                contenido       TEXT,
                urgente         BOOLEAN DEFAULT FALSE,
                autor_id        INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
                autor_nombre    TEXT,
                created_at      TIMESTAMP DEFAULT NOW()
            )
        `);
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_notas_b2b_paciente ON notas_b2b (paciente_id, created_at DESC)`).catch(() => {});

        // MIGRACIONES B2B v2 — Campos clínicos para geriátricos
        await pool.query(`ALTER TABLE pacientes_b2b ADD COLUMN IF NOT EXISTS alergias TEXT`).catch(() => {});
        await pool.query(`ALTER TABLE pacientes_b2b ADD COLUMN IF NOT EXISTS medico_cabecera TEXT`).catch(() => {});
        await pool.query(`ALTER TABLE pacientes_b2b ADD COLUMN IF NOT EXISTS antecedentes TEXT`).catch(() => {});
        await pool.query(`ALTER TABLE pacientes_b2b ADD COLUMN IF NOT EXISTS fecha_egreso DATE`).catch(() => {});
        await pool.query(`ALTER TABLE pacientes_b2b ADD COLUMN IF NOT EXISTS motivo_egreso TEXT`).catch(() => {});
        await pool.query(`ALTER TABLE usuarios_b2b ADD COLUMN IF NOT EXISTS turno VARCHAR(20) DEFAULT 'mañana'`).catch(() => {});

        // MIGRACIONES B2B v3 — Catálogo de medicamentos y modelo de stock institucional
        await pool.query(`ALTER TABLE instituciones_b2b ADD COLUMN IF NOT EXISTS stock_modelo VARCHAR(20) DEFAULT 'familiar'`).catch(() => {});
        await pool.query(`
            CREATE TABLE IF NOT EXISTS catalogo_medicamentos_b2b (
                id              SERIAL PRIMARY KEY,
                institucion_id  INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                nombre          VARCHAR(200) NOT NULL,
                principio_activo VARCHAR(200),
                presentacion    VARCHAR(100),
                unidad          VARCHAR(50) NOT NULL DEFAULT 'comprimido',
                stock_actual    INTEGER NOT NULL DEFAULT 0,
                stock_minimo    INTEGER NOT NULL DEFAULT 5,
                activo          BOOLEAN DEFAULT TRUE,
                created_at      TIMESTAMPTZ DEFAULT NOW(),
                updated_at      TIMESTAMPTZ DEFAULT NOW()
            )
        `).catch(() => {});
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_catalogo_meds_b2b ON catalogo_medicamentos_b2b (institucion_id, activo)`).catch(() => {});
        await pool.query(`ALTER TABLE medicamentos_b2b ADD COLUMN IF NOT EXISTS catalogo_id INTEGER REFERENCES catalogo_medicamentos_b2b(id) ON DELETE SET NULL`).catch(() => {});

        console.log('✅ Migraciones B2B completadas');

        // MIGRACIONES B2B v4 — Permisos configurables del equipo + documentos adjuntos
        await pool.query(`ALTER TABLE instituciones_b2b ADD COLUMN IF NOT EXISTS permisos_equipo JSONB DEFAULT '{}'`).catch(() => {});
        await pool.query(`
            CREATE TABLE IF NOT EXISTS documentos_b2b (
                id              SERIAL PRIMARY KEY,
                institucion_id  INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                paciente_id     INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                nombre_archivo  TEXT NOT NULL,
                tipo_mime       VARCHAR(100),
                tamanio_bytes   INTEGER,
                datos           TEXT NOT NULL,
                subido_por      INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
                subido_nombre   TEXT,
                created_at      TIMESTAMP DEFAULT NOW()
            )
        `).catch(() => {});
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_documentos_b2b_paciente ON documentos_b2b (paciente_id, institucion_id)`).catch(() => {});
        console.log('✅ Migraciones B2B v4 completadas');

        // MIGRACIONES B2B v5 — Onboarding de institución
        await pool.query(`ALTER TABLE instituciones_b2b ADD COLUMN IF NOT EXISTS onboarding_done BOOLEAN DEFAULT FALSE`).catch(() => {});
        console.log('✅ Migraciones B2B v5 completadas');

        // MIGRACIONES B2B v6 — Verificación de email al registrarse
        await pool.query(`ALTER TABLE usuarios_b2b ADD COLUMN IF NOT EXISTS email_verified           BOOLEAN   DEFAULT FALSE`).catch(() => {});
        await pool.query(`ALTER TABLE usuarios_b2b ADD COLUMN IF NOT EXISTS email_verification_token  TEXT`).catch(() => {});
        await pool.query(`ALTER TABLE usuarios_b2b ADD COLUMN IF NOT EXISTS email_verification_expiry TIMESTAMPTZ`).catch(() => {});
        console.log('✅ Migraciones B2B v6 completadas');

        // MIGRACIONES B2B v7 — Plan 'free' por defecto + columna inicio período de prueba
        await pool.query(`ALTER TABLE instituciones_b2b ALTER COLUMN plan SET DEFAULT 'free'`).catch(() => {});
        await pool.query(`ALTER TABLE instituciones_b2b ADD COLUMN IF NOT EXISTS trial_started_at TIMESTAMPTZ DEFAULT NOW()`).catch(() => {});
        // Instituciones ya existentes sin trial_started_at: asignar created_at como inicio de prueba
        await pool.query(`UPDATE instituciones_b2b SET trial_started_at = created_at WHERE trial_started_at IS NULL`).catch(() => {});
        console.log('✅ Migraciones B2B v7 completadas');

        // MIGRACIONES B2B v8 — Modo estación compartida persistente (cross-device)
        await pool.query(`ALTER TABLE instituciones_b2b ADD COLUMN IF NOT EXISTS shared_mode BOOLEAN DEFAULT FALSE`).catch(() => {});
        console.log('✅ Migraciones B2B v8 completadas');

        // MIGRACIONES B2B v9 — Preferencias de alertas en DB + tracking descuento de precio introductorio
        await pool.query(`ALTER TABLE usuarios_b2b ADD COLUMN IF NOT EXISTS notif_prefs JSONB DEFAULT '{}'`).catch(() => {});
        await pool.query(`ALTER TABLE instituciones_b2b ADD COLUMN IF NOT EXISTS mp_preapproval_id TEXT`).catch(() => {});
        await pool.query(`ALTER TABLE instituciones_b2b ADD COLUMN IF NOT EXISTS discount_expires_at TIMESTAMPTZ`).catch(() => {});
        console.log('✅ Migraciones B2B v9 completadas');

        // MIGRACIONES B2B v10 — Catálogo híbrido: insumos específicos por paciente
        // paciente_id NULL = insumo institucional general; paciente_id != NULL = insumo propio del paciente
        await pool.query(`ALTER TABLE catalogo_medicamentos_b2b ADD COLUMN IF NOT EXISTS paciente_id INTEGER REFERENCES pacientes_b2b(id) ON DELETE SET NULL`).catch(() => {});
        console.log('✅ Migraciones B2B v10 completadas');
        // MIGRACIONES B2B v11 — Historial de citas (reutilizar citas)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS historial_citas_b2b (
                id              SERIAL PRIMARY KEY,
                institucion_id  INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                cita_id         INTEGER REFERENCES citas_b2b(id) ON DELETE SET NULL,
                paciente_id     INTEGER NOT NULL REFERENCES pacientes_b2b(id) ON DELETE CASCADE,
                titulo          VARCHAR(255) NOT NULL,
                descripcion     TEXT,
                fecha           TIMESTAMP NOT NULL,
                medico          VARCHAR(255),
                especialidad    VARCHAR(255),
                lugar           VARCHAR(255),
                estado          VARCHAR(50),
                archivado_en    TIMESTAMP DEFAULT NOW(),
                archivado_por   INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL
            )
        `).catch(() => {});
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_historial_citas_paciente ON historial_citas_b2b (paciente_id, fecha DESC)`).catch(() => {});
        console.log('✅ Migraciones B2B v11 completadas');

        // MIGRACIONES B2B v12 — Historial de restock de insumos + timestamp para campana de notificaciones
        await pool.query(`
            CREATE TABLE IF NOT EXISTS historial_restock_b2b (
                id                SERIAL PRIMARY KEY,
                institucion_id    INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE CASCADE,
                catalogo_id       INTEGER REFERENCES catalogo_medicamentos_b2b(id) ON DELETE SET NULL,
                paciente_id       INTEGER REFERENCES pacientes_b2b(id) ON DELETE SET NULL,
                nombre_item       TEXT NOT NULL,
                stock_anterior    INTEGER NOT NULL DEFAULT 0,
                cantidad_repuesta INTEGER NOT NULL DEFAULT 0,
                stock_nuevo       INTEGER NOT NULL DEFAULT 0,
                notas             TEXT,
                registrado_por    INTEGER REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
                registrado_nombre TEXT,
                created_at        TIMESTAMPTZ DEFAULT NOW()
            )
        `).catch(() => {});
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_restock_paciente ON historial_restock_b2b (paciente_id, created_at DESC)`).catch(() => {});
        await pool.query(`CREATE INDEX IF NOT EXISTS idx_restock_catalogo ON historial_restock_b2b (catalogo_id, created_at DESC)`).catch(() => {});
        await pool.query(`ALTER TABLE usuarios_b2b ADD COLUMN IF NOT EXISTS notif_last_seen_at TIMESTAMPTZ`).catch(() => {});
        console.log('✅ Migraciones B2B v12 completadas');

        // ============================================================
        // FIN MIGRACIONES B2B
        // ============================================================

        console.log('✅ Migraciones completadas');
    } catch (err) {
        console.error('❌ Error en migraciones:', err.message);
    }
}

// ========== MIDDLEWARE DE AUTENTICACIÓN ==========
function authMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Token requerido' });
    const token = auth.split(' ')[1];
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch (err) {
        res.status(401).json({ error: 'Token inválido' });
    }
}

// Helper: parsea paciente_id de query o body
function parsePacienteId(req) {
    const v = req.query.paciente_id || req.body?.paciente_id || req.body?.pacienteId;
    return v ? parseInt(v) : null;
}

// Helper: verifica que el paciente pertenece al usuario autenticado
async function validatePaciente(pacienteId, usuarioId) {
    if (!pacienteId) return true;
    const result = await pool.query(
        'SELECT id FROM pacientes WHERE id=$1 AND usuario_id=$2 AND activo=true',
        [pacienteId, usuarioId]
    );
    return result.rows.length > 0;
}

// Helper: para co-cuidadores — determina el usuario dueño de los datos de un paciente.
// Si el requesting user es el dueño → retorna su propio ID.
// Si el paciente está compartido con él → retorna el ID del dueño original.
// Si no tiene acceso → retorna null (403).
async function resolveDataOwnerId(requestingUserId, pacienteId) {
    if (!pacienteId) return requestingUserId;
    // Verificar si el usuario es el dueño del paciente
    const own = await pool.query(
        'SELECT id FROM pacientes WHERE id=$1 AND usuario_id=$2 AND activo=true',
        [pacienteId, requestingUserId]
    );
    if (own.rows.length > 0) return requestingUserId;
    // Verificar si el paciente está compartido con este usuario
    const shared = await pool.query(
        `SELECT p.usuario_id FROM paciente_compartidos pc
         JOIN pacientes p ON p.id = pc.paciente_id
         WHERE pc.paciente_id=$1 AND pc.invitado_id=$2 AND pc.aceptado=TRUE`,
        [pacienteId, requestingUserId]
    );
    if (shared.rows.length > 0) return shared.rows[0].usuario_id;
    return null; // Sin acceso
}

// Helper: si no viene paciente_id en el body, intenta auto-asignarlo para usuarios free
// Esto cubre el caso en que el frontend no pudo setear currentPacienteId a tiempo.
async function resolvePatientId(pid, userId) {
    if (pid) return parseInt(pid);
    // Solo auto-asignar para usuarios gratuitos (1 solo paciente)
    const userResult = await pool.query('SELECT premium FROM usuarios WHERE id=$1', [userId]);
    const isPremium = userResult.rows[0]?.premium || false;
    if (!isPremium) {
        const pacResult = await pool.query(
            'SELECT id FROM pacientes WHERE usuario_id=$1 AND activo=true ORDER BY id ASC LIMIT 1',
            [userId]
        );
        if (pacResult.rows.length > 0) return pacResult.rows[0].id;
    }
    return null;
}

// ========== ENDPOINTS PÚBLICOS ==========
app.get('/', (req, res) => res.send('Backend funcionando para CuidaDiario!'));
app.get('/api/test', (req, res) => res.json({ status: 'ok', message: 'Backend funcionando correctamente' }));
app.get('/dbtest', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({ time: result.rows[0].now, status: 'Database connected' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== AUTENTICACIÓN ==========
app.post('/api/register', authRateLimit, async (req, res) => {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password)
        return res.status(400).json({ error: 'Todos los campos son requeridos' });
    try {
        const existing = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (existing.rows.length > 0)
            return res.status(400).json({ error: 'El email ya está registrado' });
        const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
        const result = await pool.query(
            'INSERT INTO usuarios (nombre, email, password_hash, premium) VALUES ($1, $2, $3, $4) RETURNING id, nombre, email, premium',
            [nombre, email, password_hash, false]
        );
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.status(201).json({ token, usuario: user });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/login', authRateLimit, async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: 'Email y contraseña son requeridos' });
    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length === 0)
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid)
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ token, usuario: { id: user.id, nombre: user.nombre, email: user.email, premium: user.premium } });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== RECUPERACIÓN DE CONTRASEÑA ==========
app.post('/api/forgot-password', authRateLimit, async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email requerido' });
    try {
        const result = await pool.query('SELECT id, nombre FROM usuarios WHERE email=$1', [email]);
        // Responder siempre con éxito para no revelar si el email existe (seguridad)
        if (result.rows.length === 0)
            return res.json({ message: 'Si ese email está registrado, recibirás un correo con instrucciones.' });

        const user = result.rows[0];
        const token = crypto.randomBytes(48).toString('hex'); // 96 chars hex
        const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hora

        await pool.query(
            'UPDATE usuarios SET reset_token=$1, reset_token_expires=$2 WHERE id=$3',
            [token, expires, user.id]
        );

        const resetLink = FRONTEND_URL
            ? `${FRONTEND_URL}/reset-password.html?token=${token}`
            : `https://cuidadiario.edensoftwork.com/reset-password.html?token=${token}`;

        try {
            await sendEmail({
                to: email,
                subject: '🔑 Restablecer contraseña — CuidaDiario',
                html: `
                    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;border:1px solid #e0e0e0;border-radius:8px;">
                        <h2 style="color:#667eea;">CuidaDiario</h2>
                        <p>Hola <strong>${user.nombre}</strong>,</p>
                        <p>Recibimos una solicitud para restablecer tu contraseña. Hacé clic en el botón de abajo para crear una nueva:</p>
                        <div style="text-align:center;margin:28px 0;">
                            <a href="${resetLink}"
                               style="background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:14px 28px;
                                      border-radius:8px;text-decoration:none;font-weight:600;font-size:1rem;">
                                Restablecer contraseña
                            </a>
                        </div>
                        <p style="color:#777;font-size:0.85rem;">Este enlace expira en <strong>1 hora</strong>.</p>
                        <p style="color:#777;font-size:0.85rem;">Si no solicitaste este cambio, podés ignorar este email. Tu contraseña actual no cambiará.</p>
                        <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
                        <p style="color:#aaa;font-size:0.78rem;">CuidaDiario by EDEN SoftWork</p>
                    </div>
                `
            });
            console.log(`[Email] Instrucciones de recuperación enviadas a ${email}`);
        } catch (emailErr) {
            console.warn('⚠️  Email no enviado:', emailErr.message, '— Token debug:', token);
        }

        res.json({ message: 'Si ese email está registrado, recibirás un correo con instrucciones.' });
    } catch (err) {
        console.error('Error en forgot-password:', err.message);
        res.status(500).json({ error: 'Error al procesar la solicitud' });
    }
});

app.post('/api/reset-password', async (req, res) => {
    const { token, password } = req.body;
    if (!token || !password) return res.status(400).json({ error: 'Token y nueva contraseña son requeridos' });
    if (password.length < 6) return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres' });
    try {
        const result = await pool.query(
            'SELECT id FROM usuarios WHERE reset_token=$1 AND reset_token_expires > NOW()',
            [token]
        );
        if (result.rows.length === 0)
            return res.status(400).json({ error: 'El enlace es inválido o ya expiró. Solicitá uno nuevo.' });

        const userId = result.rows[0].id;
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        await pool.query(
            'UPDATE usuarios SET password_hash=$1, reset_token=NULL, reset_token_expires=NULL WHERE id=$2',
            [hash, userId]
        );
        res.json({ message: 'Contraseña actualizada correctamente. Ya podés iniciar sesión.' });
    } catch (err) {
        console.error('Error en reset-password:', err.message);
        res.status(500).json({ error: 'Error al actualizar la contraseña' });
    }
});

// ========== PACIENTES ==========
app.get('/api/pacientes', authMiddleware, async (req, res) => {
    try {
        // Pacientes propios
        const own = await pool.query(
            `SELECT *, false AS es_compartido, NULL AS compartido_por FROM pacientes
             WHERE usuario_id=$1 AND activo=true ORDER BY id ASC`,
            [req.user.id]
        );
        // Pacientes compartidos con el usuario (co-cuidador)
        const shared = await pool.query(
            `SELECT p.*, true AS es_compartido, u.nombre AS compartido_por
             FROM paciente_compartidos pc
             JOIN pacientes p ON p.id = pc.paciente_id
             JOIN usuarios u ON u.id = p.usuario_id
             WHERE pc.invitado_id=$1 AND pc.aceptado=TRUE AND p.activo=TRUE
             ORDER BY p.id ASC`,
            [req.user.id]
        );
        res.json([...own.rows, ...shared.rows]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/pacientes', authMiddleware, async (req, res) => {
    const { nombre, relacion, fecha_nacimiento, fechaNacimiento, notas } = req.body;
    if (!nombre) return res.status(400).json({ error: 'El nombre es requerido' });
    try {
        const userResult = await pool.query('SELECT premium FROM usuarios WHERE id=$1', [req.user.id]);
        const isPremium = userResult.rows[0]?.premium || false;
        if (!isPremium) {
            const count = await pool.query(
                'SELECT COUNT(*) FROM pacientes WHERE usuario_id=$1 AND activo=true',
                [req.user.id]
            );
            if (parseInt(count.rows[0].count) >= 1)
                return res.status(403).json({ error: 'La versión gratuita permite solo 1 paciente. Actualiza a Premium para agregar más.' });
        }
        const result = await pool.query(
            'INSERT INTO pacientes (usuario_id, nombre, relacion, fecha_nacimiento, notas) VALUES ($1,$2,$3,$4,$5) RETURNING *',
            [req.user.id, nombre, relacion || null, fecha_nacimiento || fechaNacimiento || null, notas || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/pacientes/:id', authMiddleware, async (req, res) => {
    const { nombre, relacion, fecha_nacimiento, fechaNacimiento, notas } = req.body;
    try {
        const current = await pool.query('SELECT * FROM pacientes WHERE id=$1 AND usuario_id=$2', [req.params.id, req.user.id]);
        if (current.rows.length === 0)
            return res.status(404).json({ error: 'Paciente no encontrado' });
        const p = current.rows[0];
        const result = await pool.query(
            'UPDATE pacientes SET nombre=$1, relacion=$2, fecha_nacimiento=$3, notas=$4 WHERE id=$5 AND usuario_id=$6 RETURNING *',
            [
                nombre           !== undefined ? nombre                 : p.nombre,
                relacion         !== undefined ? (relacion || null)     : p.relacion,
                fecha_nacimiento !== undefined ? (fecha_nacimiento || null)
                    : fechaNacimiento !== undefined ? (fechaNacimiento || null) : p.fecha_nacimiento,
                notas            !== undefined ? (notas || null)        : p.notas,
                req.params.id, req.user.id
            ]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/pacientes/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'UPDATE pacientes SET activo=false WHERE id=$1 AND usuario_id=$2 RETURNING *',
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0)
            return res.status(404).json({ error: 'Paciente no encontrado' });
        res.json({ message: 'Paciente eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== MEDICAMENTOS ==========
app.post('/api/medicamentos', authMiddleware, async (req, res) => {
    const { nombre, dosis, frecuencia, horaInicio, hora_inicio, horaFin, hora_fin, recordatorio, notas, horariosCustom, horarios_custom, paciente_id, pacienteId } = req.body;
    try {
        const pid = await resolvePatientId(paciente_id || pacienteId || null, req.user.id);
        if (pid && !(await validatePaciente(pid, req.user.id)))
            return res.status(403).json({ error: 'El paciente no pertenece a este usuario' });
        const result = await pool.query(
            'INSERT INTO medicamentos (usuario_id, paciente_id, nombre, dosis, frecuencia, hora_inicio, hora_fin, recordatorio, notas, horarios_custom) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
            [req.user.id, pid, nombre, dosis, frecuencia, horaInicio || hora_inicio || null, horaFin || hora_fin || null, recordatorio || false, notas || null, horariosCustom || horarios_custom || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/medicamentos', authMiddleware, async (req, res) => {
    const paciente_id = req.query.paciente_id ? parseInt(req.query.paciente_id) : null;
    try {
        const ownerId = await resolveDataOwnerId(req.user.id, paciente_id);
        if (ownerId === null) return res.status(403).json({ error: 'Acceso denegado al paciente' });
        const result = paciente_id
            ? await pool.query('SELECT * FROM medicamentos WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY id DESC', [ownerId, paciente_id])
            : await pool.query('SELECT * FROM medicamentos WHERE usuario_id=$1 ORDER BY id DESC', [ownerId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/medicamentos/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM medicamentos WHERE id=$1 AND usuario_id=$2', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Medicamento no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/medicamentos/:id', authMiddleware, async (req, res) => {
    const { nombre, dosis, frecuencia, horaInicio, hora_inicio, horaFin, hora_fin, recordatorio, notas, horariosCustom, horarios_custom } = req.body;
    try {
        const result = await pool.query(
            'UPDATE medicamentos SET nombre=$1, dosis=$2, frecuencia=$3, hora_inicio=$4, hora_fin=$5, recordatorio=$6, notas=$7, horarios_custom=$8 WHERE id=$9 AND usuario_id=$10 RETURNING *',
            [nombre, dosis, frecuencia, horaInicio || hora_inicio || null, horaFin || hora_fin || null, recordatorio, notas || null, horariosCustom || horarios_custom || null, req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Medicamento no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/medicamentos/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM medicamentos WHERE id=$1 AND usuario_id=$2 RETURNING *', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Medicamento no encontrado' });
        res.json({ message: 'Medicamento eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== CITAS ==========
app.post('/api/citas', authMiddleware, async (req, res) => {
    const { tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio, paciente_id, pacienteId } = req.body;
    try {
        const pid = await resolvePatientId(paciente_id || pacienteId || null, req.user.id);
        if (pid && !(await validatePaciente(pid, req.user.id)))
            return res.status(403).json({ error: 'El paciente no pertenece a este usuario' });
        const result = await pool.query(
            'INSERT INTO citas (usuario_id, paciente_id, tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
            [req.user.id, pid, tipo, titulo, fecha, hora, lugar || null, profesional || null, notas || null, recordatorio || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/citas', authMiddleware, async (req, res) => {
    const paciente_id = req.query.paciente_id ? parseInt(req.query.paciente_id) : null;
    try {
        const ownerId = await resolveDataOwnerId(req.user.id, paciente_id);
        if (ownerId === null) return res.status(403).json({ error: 'Acceso denegado al paciente' });
        const result = paciente_id
            ? await pool.query('SELECT * FROM citas WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha DESC, hora DESC', [ownerId, paciente_id])
            : await pool.query('SELECT * FROM citas WHERE usuario_id=$1 ORDER BY fecha DESC, hora DESC', [ownerId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/citas/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM citas WHERE id=$1 AND usuario_id=$2', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/citas/:id', authMiddleware, async (req, res) => {
    const { tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio } = req.body;
    try {
        const result = await pool.query(
            'UPDATE citas SET tipo=$1, titulo=$2, fecha=$3, hora=$4, lugar=$5, profesional=$6, notas=$7, recordatorio=$8 WHERE id=$9 AND usuario_id=$10 RETURNING *',
            [tipo, titulo, fecha, hora, lugar || null, profesional || null, notas || null, recordatorio || null, req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/citas/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM citas WHERE id=$1 AND usuario_id=$2 RETURNING *', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada' });
        res.json({ message: 'Cita eliminada' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== TAREAS ==========
app.post('/api/tareas', authMiddleware, async (req, res) => {
    const { titulo, categoria, fecha, hora, frecuencia, completada, descripcion, recordatorio, hastaFecha, hasta_fecha, paciente_id, pacienteId } = req.body;
    try {
        const pid = await resolvePatientId(paciente_id || pacienteId || null, req.user.id);
        if (pid && !(await validatePaciente(pid, req.user.id)))
            return res.status(403).json({ error: 'El paciente no pertenece a este usuario' });
        const result = await pool.query(
            'INSERT INTO tareas (usuario_id, paciente_id, titulo, categoria, fecha, hora, frecuencia, completada, descripcion, recordatorio, hasta_fecha) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
            [req.user.id, pid, titulo, categoria, fecha, hora || null, frecuencia, completada || false, descripcion || null, recordatorio || false, hastaFecha || hasta_fecha || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/tareas', authMiddleware, async (req, res) => {
    const paciente_id = req.query.paciente_id ? parseInt(req.query.paciente_id) : null;
    try {
        const ownerId = await resolveDataOwnerId(req.user.id, paciente_id);
        if (ownerId === null) return res.status(403).json({ error: 'Acceso denegado al paciente' });
        const result = paciente_id
            ? await pool.query('SELECT * FROM tareas WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha ASC, hora ASC', [ownerId, paciente_id])
            : await pool.query('SELECT * FROM tareas WHERE usuario_id=$1 ORDER BY fecha ASC, hora ASC', [ownerId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/tareas/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM tareas WHERE id=$1 AND usuario_id=$2', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/tareas/:id', authMiddleware, async (req, res) => {
    try {
        const current = await pool.query('SELECT * FROM tareas WHERE id=$1 AND usuario_id=$2', [req.params.id, req.user.id]);
        if (current.rows.length === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
        const t = current.rows[0];
        const b = req.body;
        const result = await pool.query(
            'UPDATE tareas SET titulo=$1, categoria=$2, fecha=$3, hora=$4, frecuencia=$5, completada=$6, descripcion=$7, recordatorio=$8, hasta_fecha=$9 WHERE id=$10 AND usuario_id=$11 RETURNING *',
            [
                b.titulo       !== undefined ? b.titulo                : t.titulo,
                b.categoria    !== undefined ? b.categoria             : t.categoria,
                b.fecha        !== undefined ? b.fecha                 : t.fecha,
                b.hora         !== undefined ? (b.hora || null)        : t.hora,
                b.frecuencia   !== undefined ? b.frecuencia            : t.frecuencia,
                b.completada   !== undefined ? b.completada            : t.completada,
                b.descripcion  !== undefined ? (b.descripcion || null) : t.descripcion,
                b.recordatorio !== undefined ? b.recordatorio          : t.recordatorio,
                b.hastaFecha   !== undefined ? (b.hastaFecha || null)
                    : b.hasta_fecha !== undefined ? (b.hasta_fecha || null) : t.hasta_fecha,
                req.params.id, req.user.id
            ]
        );
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/tareas/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM tareas WHERE id=$1 AND usuario_id=$2 RETURNING *', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
        res.json({ message: 'Tarea eliminada' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== SÍNTOMAS ==========
app.post('/api/sintomas', authMiddleware, async (req, res) => {
    const { tipo, nombre, intensidad, estadoAnimo, estado_animo, descripcion, fecha, paciente_id, pacienteId } = req.body;
    try {
        const pid = await resolvePatientId(paciente_id || pacienteId || null, req.user.id);
        if (pid && !(await validatePaciente(pid, req.user.id)))
            return res.status(403).json({ error: 'El paciente no pertenece a este usuario' });
        const result = await pool.query(
            'INSERT INTO sintomas (usuario_id, paciente_id, tipo, intensidad, estado_animo, descripcion, fecha) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
            [req.user.id, pid, tipo || nombre, intensidad, estadoAnimo || estado_animo || null, descripcion || null, fecha ? new Date(fecha) : new Date()]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/sintomas', authMiddleware, async (req, res) => {
    const paciente_id = req.query.paciente_id ? parseInt(req.query.paciente_id) : null;
    try {
        const ownerId = await resolveDataOwnerId(req.user.id, paciente_id);
        if (ownerId === null) return res.status(403).json({ error: 'Acceso denegado al paciente' });
        const result = paciente_id
            ? await pool.query('SELECT * FROM sintomas WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha DESC', [ownerId, paciente_id])
            : await pool.query('SELECT * FROM sintomas WHERE usuario_id=$1 ORDER BY fecha DESC', [ownerId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/sintomas/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM sintomas WHERE id=$1 AND usuario_id=$2', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Síntoma no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/sintomas/:id', authMiddleware, async (req, res) => {
    const { tipo, nombre, intensidad, estadoAnimo, estado_animo, descripcion, fecha } = req.body;
    try {
        const result = await pool.query(
            'UPDATE sintomas SET tipo=$1, intensidad=$2, estado_animo=$3, descripcion=$4, fecha=$5 WHERE id=$6 AND usuario_id=$7 RETURNING *',
            [tipo || nombre, intensidad, estadoAnimo || estado_animo || null, descripcion || null, fecha ? new Date(fecha) : new Date(), req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Síntoma no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/sintomas/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM sintomas WHERE id=$1 AND usuario_id=$2 RETURNING *', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Síntoma no encontrado' });
        res.json({ message: 'Síntoma eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== CONTACTOS ==========
app.post('/api/contactos', authMiddleware, async (req, res) => {
    const { nombre, categoria, especialidad, telefono, email, direccion, notas, paciente_id, pacienteId } = req.body;
    try {
        const pid = await resolvePatientId(paciente_id || pacienteId || null, req.user.id);
        if (pid && !(await validatePaciente(pid, req.user.id)))
            return res.status(403).json({ error: 'El paciente no pertenece a este usuario' });
        const result = await pool.query(
            'INSERT INTO contactos (usuario_id, paciente_id, nombre, categoria, especialidad, telefono, email, direccion, notas) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
            [req.user.id, pid, nombre, categoria, especialidad || null, telefono, email || null, direccion || null, notas || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/contactos', authMiddleware, async (req, res) => {
    const paciente_id = req.query.paciente_id ? parseInt(req.query.paciente_id) : null;
    try {
        const ownerId = await resolveDataOwnerId(req.user.id, paciente_id);
        if (ownerId === null) return res.status(403).json({ error: 'Acceso denegado al paciente' });
        const result = paciente_id
            ? await pool.query('SELECT * FROM contactos WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY nombre ASC', [ownerId, paciente_id])
            : await pool.query('SELECT * FROM contactos WHERE usuario_id=$1 ORDER BY nombre ASC', [ownerId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/contactos/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM contactos WHERE id=$1 AND usuario_id=$2', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Contacto no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/contactos/:id', authMiddleware, async (req, res) => {
    const { nombre, categoria, especialidad, telefono, email, direccion, notas } = req.body;
    try {
        const result = await pool.query(
            'UPDATE contactos SET nombre=$1, categoria=$2, especialidad=$3, telefono=$4, email=$5, direccion=$6, notas=$7 WHERE id=$8 AND usuario_id=$9 RETURNING *',
            [nombre, categoria, especialidad || null, telefono, email || null, direccion || null, notas || null, req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Contacto no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/contactos/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM contactos WHERE id=$1 AND usuario_id=$2 RETURNING *', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Contacto no encontrado' });
        res.json({ message: 'Contacto eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== SIGNOS VITALES ==========
app.post('/api/signos-vitales', authMiddleware, async (req, res) => {
    const { tipo, valor, sistolica, diastolica, notas, fecha, paciente_id, pacienteId } = req.body;
    try {
        const pid = await resolvePatientId(paciente_id || pacienteId || null, req.user.id);
        if (pid && !(await validatePaciente(pid, req.user.id)))
            return res.status(403).json({ error: 'El paciente no pertenece a este usuario' });
        const result = await pool.query(
            'INSERT INTO signos_vitales (usuario_id, paciente_id, tipo, valor, sistolica, diastolica, notas, fecha) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
            [req.user.id, pid, tipo, valor || null, sistolica || null, diastolica || null, notas || null, fecha ? new Date(fecha) : new Date()]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/signos-vitales', authMiddleware, async (req, res) => {
    const paciente_id = req.query.paciente_id ? parseInt(req.query.paciente_id) : null;
    try {
        const ownerId = await resolveDataOwnerId(req.user.id, paciente_id);
        if (ownerId === null) return res.status(403).json({ error: 'Acceso denegado al paciente' });
        const result = paciente_id
            ? await pool.query('SELECT * FROM signos_vitales WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha DESC', [ownerId, paciente_id])
            : await pool.query('SELECT * FROM signos_vitales WHERE usuario_id=$1 ORDER BY fecha DESC', [ownerId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/signos-vitales/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM signos_vitales WHERE id=$1 AND usuario_id=$2 RETURNING *', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Signo vital no encontrado' });
        res.json({ message: 'Signo vital eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== HISTORIAL MEDICAMENTOS ==========
app.post('/api/historial-medicamentos', authMiddleware, async (req, res) => {
    const { medicamento_id, medicamentoId, medicamento_nombre, medicamentoNombre, dosis, notas, fecha, paciente_id, pacienteId } = req.body;
    try {
        const pid = await resolvePatientId(paciente_id || pacienteId || null, req.user.id);
        if (pid && !(await validatePaciente(pid, req.user.id)))
            return res.status(403).json({ error: 'El paciente no pertenece a este usuario' });
        const result = await pool.query(
            'INSERT INTO historial_medicamentos (usuario_id, paciente_id, medicamento_id, medicamento_nombre, dosis, notas, fecha) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
            [req.user.id, pid, medicamento_id || medicamentoId || null, medicamento_nombre || medicamentoNombre, dosis || null, notas || null, fecha ? new Date(fecha) : new Date()]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/historial-medicamentos', authMiddleware, async (req, res) => {
    const paciente_id = req.query.paciente_id ? parseInt(req.query.paciente_id) : null;
    try {
        const ownerId = await resolveDataOwnerId(req.user.id, paciente_id);
        if (ownerId === null) return res.status(403).json({ error: 'Acceso denegado al paciente' });
        const result = paciente_id
            ? await pool.query('SELECT * FROM historial_medicamentos WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha DESC LIMIT 100', [ownerId, paciente_id])
            : await pool.query('SELECT * FROM historial_medicamentos WHERE usuario_id=$1 ORDER BY fecha DESC LIMIT 100', [ownerId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/historial-medicamentos/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM historial_medicamentos WHERE id=$1 AND usuario_id=$2 RETURNING *', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Registro no encontrado' });
        res.json({ message: 'Registro eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== HISTORIAL TAREAS ==========
app.post('/api/historial-tareas', authMiddleware, async (req, res) => {
    const { tarea_id, tareaId, tarea_titulo, tareaTitulo, notas, fecha, paciente_id, pacienteId } = req.body;
    try {
        const pid = await resolvePatientId(paciente_id || pacienteId || null, req.user.id);
        if (pid && !(await validatePaciente(pid, req.user.id)))
            return res.status(403).json({ error: 'El paciente no pertenece a este usuario' });
        const result = await pool.query(
            'INSERT INTO historial_tareas (usuario_id, paciente_id, tarea_id, tarea_titulo, notas, fecha) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
            [req.user.id, pid, tarea_id || tareaId || null, tarea_titulo || tareaTitulo || null, notas || null, fecha ? new Date(fecha) : new Date()]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/historial-tareas', authMiddleware, async (req, res) => {
    const paciente_id = req.query.paciente_id ? parseInt(req.query.paciente_id) : null;
    try {
        const ownerId = await resolveDataOwnerId(req.user.id, paciente_id);
        if (ownerId === null) return res.status(403).json({ error: 'Acceso denegado al paciente' });
        const result = paciente_id
            ? await pool.query('SELECT * FROM historial_tareas WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha DESC LIMIT 100', [ownerId, paciente_id])
            : await pool.query('SELECT * FROM historial_tareas WHERE usuario_id=$1 ORDER BY fecha DESC LIMIT 100', [ownerId]);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/historial-tareas/:id', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM historial_tareas WHERE id=$1 AND usuario_id=$2 RETURNING *', [req.params.id, req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Registro no encontrado' });
        res.json({ message: 'Registro eliminado' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/push/vapid-key — devuelve la clave pública VAPID al frontend
app.get('/api/push/vapid-key', (req, res) => {
    if (!VAPID_PUBLIC_KEY) return res.status(503).json({ error: 'Push no configurado' });
    res.json({ publicKey: VAPID_PUBLIC_KEY });
});

// POST /api/push/subscribe — guarda la suscripción push del usuario autenticado
app.post('/api/push/subscribe', authMiddleware, async (req, res) => {
    try {
        const { endpoint, keys } = req.body;
        if (!endpoint || !keys?.p256dh || !keys?.auth)
            return res.status(400).json({ error: 'Suscripción inválida' });
        await pool.query(`
            INSERT INTO push_subscriptions (usuario_id, endpoint, p256dh, auth)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (usuario_id, endpoint) DO UPDATE SET p256dh=$3, auth=$4
        `, [req.user.id, endpoint, keys.p256dh, keys.auth]);
        res.json({ ok: true });
    } catch (err) {
        console.error('Error guardando push subscription:', err);
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/push/unsubscribe — elimina la suscripción push del usuario autenticado
app.delete('/api/push/unsubscribe', authMiddleware, async (req, res) => {
    try {
        const { endpoint } = req.body;
        if (endpoint) {
            await pool.query('DELETE FROM push_subscriptions WHERE usuario_id=$1 AND endpoint=$2', [req.user.id, endpoint]);
        } else {
            await pool.query('DELETE FROM push_subscriptions WHERE usuario_id=$1', [req.user.id]);
        }
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/push/status — devuelve cuántos dispositivos tiene suscritos el usuario
app.get('/api/push/status', authMiddleware, async (req, res) => {
    try {
        const subs = await pool.query(
            'SELECT endpoint, created_at FROM push_subscriptions WHERE usuario_id=$1',
            [req.user.id]
        );
        res.json({
            vapidConfigured: !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY),
            devices: subs.rows.length,
            subscriptions: subs.rows.map(s => ({
                endpoint: s.endpoint.substring(0, 50) + '...',
                since: s.created_at
            }))
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/push/test — envía una notificación push de prueba al usuario autenticado
app.post('/api/push/test', authMiddleware, async (req, res) => {
    try {
        if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
            return res.status(503).json({
                error: 'VAPID keys no configuradas en el servidor. Ejecutá setup-vapid.js y agregá las variables a Railway.'
            });
        }
        const subs = await pool.query(
            'SELECT endpoint FROM push_subscriptions WHERE usuario_id=$1',
            [req.user.id]
        );
        if (subs.rows.length === 0) {
            return res.status(404).json({
                error: 'No hay suscripción push para este dispositivo. Activá las notificaciones primero.',
                devices: 0
            });
        }
        await sendPushToUser(req.user.id, {
            title: '✅ ¡Notificaciones funcionando!',
            body: 'Si ves esto, los recordatorios van a llegar aunque tengas la app cerrada.',
            tag: `test-${req.user.id}-${Date.now()}`,
            url: '/'
        });
        res.json({ ok: true, devices: subs.rows.length });
    } catch (err) {
        console.error('[Push] Error en test push:', err);
        res.status(500).json({ error: err.message });
    }
});

// Helper: envía una notificación push a TODOS los dispositivos de un usuario.
//
// Parámetros:
//   userId              — ID del usuario destino
//   payload             — objeto { title, body, tag, url } de la notificación
//   deduplicationBaseTag — CLAVE PARA DEDUP POR DISPOSITIVO (opcional pero recomendado).
//
// Cómo funciona el dedup por dispositivo:
//   En vez de un solo tag global por usuario, se crea un tag único para
//   cada dispositivo (“baseTag:d:sufijo_endpoint”). Esto significa que:
//     • Si notebook recibe la notificación → se marca solo para notebook.
//     • Si celular falla (transitoriamente) → NO se marca → el siguiente ciclo
//       del cron (8 min después) reintenta solo el celular.
//     • Si celular expira (410) → se borra de la DB → cuando el usuario abre
//       la app, el frontend la renueva automáticamente.
//
// urgency 'high' + TTL 86400: entrega inmediata en Android con pantalla apagada.
// TTL = 24 horas: si el dispositivo está apagado/hibernando toda la noche,
// cuando vuelva a conectarse recibe las notificaciones pendientes del día.
const PUSH_OPTIONS = {
    urgency: 'high',
    TTL: 86400
};

// ── DEDUPLICACIÓN A NIVEL MÓDULO ──
// CRÍTICO: deben estar aquí (módulo) para que sendPushToUser pueda accederlas.
// Estaban dentro de startPushReminders() — eso causaba ReferenceError silencioso
// y ninguna notificación era enviada.
async function wasAlreadySent(tag) {
    try {
        const r = await pool.query(
            "SELECT 1 FROM push_sent WHERE tag=$1 AND sent_at > NOW() - INTERVAL '25 minutes'",
            [tag]
        );
        return r.rows.length > 0;
    } catch { return false; }
}

async function markAsSent(tag) {
    try {
        await pool.query('INSERT INTO push_sent (tag, sent_at) VALUES ($1, NOW())', [tag]);
    } catch { /* OK — entrada duplicada ignorada */ }
}

async function sendPushToUser(userId, payload, deduplicationBaseTag = null) {
    if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return { sent: 0, failed: 0, skipped: 0, total: 0 };
    try {
        const subs = await pool.query(
            'SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE usuario_id=$1',
            [userId]
        );
        let sent = 0, failed = 0, skipped = 0;

        // Procesar cada dispositivo individualmente (no Promise.all) para que el dedup
        // por dispositivo sea correcto y no haya race conditions en los INSERT de push_sent.
        for (const sub of subs.rows) {
            // Tag único para este dispositivo: sufijo del endpoint lo identifica
            const deviceTag = deduplicationBaseTag
                ? `${deduplicationBaseTag}:d:${sub.endpoint.slice(-20)}`
                : null;

            // ¿Este dispositivo específico ya recibió la notificación en este ciclo?
            if (deviceTag && await wasAlreadySent(deviceTag)) {
                skipped++;
                continue;
            }

            const subscription = {
                endpoint: sub.endpoint,
                keys: { p256dh: sub.p256dh, auth: sub.auth }
            };

            try {
                await webPush.sendNotification(subscription, JSON.stringify(payload), PUSH_OPTIONS);
                sent++;
                // Marcar ESTE dispositivo como notificado (dedup)
                if (deviceTag) await markAsSent(deviceTag);
                // Registrar último éxito (para cleanup de endpoints obsoletos)
                await pool.query(
                    'UPDATE push_subscriptions SET last_success_at = NOW() WHERE endpoint=$1',
                    [sub.endpoint]
                ).catch(() => {});
            } catch (err) {
                if (err.statusCode === 410 || err.statusCode === 404 ||
                    err.statusCode === 400 || err.statusCode === 401 || err.statusCode === 403) {
                    // Suscripción permanentemente inválida → borrar de DB.
                    // 410/404 = expirada. 400/401/403 = clave VAPID no coincide con la
                    // que se usó al crear la suscripción (el device se suscribió con
                    // otras claves). En ambos casos, reintentar es inútil — hay que
                    // borrarla y dejar que el frontend la re-registre al abrir la app.
                    await pool.query('DELETE FROM push_subscriptions WHERE endpoint=$1', [sub.endpoint]);
                    console.warn(`[Push] Suscripción inválida eliminada (HTTP ${err.statusCode}): ${sub.endpoint.substring(0, 60)}`);
                } else {
                    // Error transitorio (red, rate limit, servidor del operador caído, etc.)
                    // NO marcar deviceTag → el próximo ciclo del cron reintenta este dispositivo
                    failed++;
                    console.warn(`[Push] Error transitorio dispositivo ${sub.endpoint.substring(0, 50)}: HTTP ${err.statusCode || 'N/A'} — ${err.message}`);
                }
            }
        }

        if (subs.rows.length > 0) {
            console.log(`[Push] userId=${userId} → ${sent} enviados, ${failed} fallidos (reintentarán), ${skipped} ya enviados (de ${subs.rows.length} dispositivos)`);
        }
        return { sent, failed, skipped, total: subs.rows.length };
    } catch (err) {
        console.error('[Push] Error en sendPushToUser:', err.message);
        return { sent: 0, failed: 0, skipped: 0, total: 0 };
    }
}

// Estado del cron (para endpoint de debug)
let _cronLastRun = null;
let _cronRunCount = 0;
let _cronStartedAt = null;

// GET /health — keep-alive y health check (Railway, UptimeRobot, etc.)
app.get('/health', (req, res) => {
    res.json({ status: 'ok', uptime: process.uptime(), time: new Date().toISOString() });
});

// GET /api/push/debug — diagnóstico del sistema de push (requiere auth)
app.get('/api/push/debug', authMiddleware, async (req, res) => {
    try {
        const subsCount = await pool.query('SELECT COUNT(*) AS c FROM push_subscriptions');
        const medsCount = await pool.query('SELECT COUNT(*) AS c FROM medicamentos WHERE recordatorio = true');
        const citasCount = await pool.query('SELECT COUNT(*) AS c FROM citas WHERE recordatorio IS NOT NULL AND recordatorio <> \'0\'');
        const tareasCount = await pool.query('SELECT COUNT(*) AS c FROM tareas WHERE recordatorio = true AND completada = false');
        res.json({
            vapidConfigured: !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY),
            cronRunning: _cronStartedAt !== null,
            cronStartedAt: _cronStartedAt,
            cronLastRun: _cronLastRun,
            cronRunCount: _cronRunCount,
            subscriptions: parseInt(subsCount.rows[0].c),
            medicamentosConRecordatorio: parseInt(medsCount.rows[0].c),
            citasConRecordatorio: parseInt(citasCount.rows[0].c),
            tareasConRecordatorio: parseInt(tareasCount.rows[0].c),
            serverTime: new Date().toISOString(),
            timezoneAR: new Intl.DateTimeFormat('sv-SE', {
                timeZone: 'America/Argentina/Buenos_Aires',
                hour: '2-digit', minute: '2-digit', second: '2-digit'
            }).format(new Date())
        });
    } catch (err) {
        res.status(500).json({ error: err.message, vapidConfigured: !!(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) });
    }
});

// Chequeo periódico de recordatorios — corre cada 8 minutos en el servidor
function startPushReminders() {
    if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
        console.log('ℹ️  Push reminders desactivados (VAPID keys no configuradas)');
        return;
    }

    // Helper: hora actual en cualquier zona horaria (usando Intl.DateTimeFormat)
    function nowInTZ(tz) {
        const timezone = tz || 'America/Argentina/Buenos_Aires';
        try {
            const fmt = new Intl.DateTimeFormat('sv-SE', {
                timeZone: timezone,
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit'
            });
            const str = fmt.format(new Date()); // "2024-02-27 15:30"
            const [date, time] = str.split(' ');
            const [h, m] = time.split(':').map(Number);
            return { hours: h, minutes: m, totalMinutes: h * 60 + m, dateStr: date };
        } catch {
            const utc = Date.now() + new Date().getTimezoneOffset() * 60000;
            const ar  = new Date(utc - 3 * 3600000);
            return {
                hours: ar.getHours(), minutes: ar.getMinutes(),
                totalMinutes: ar.getHours() * 60 + ar.getMinutes(),
                dateStr: ar.toISOString().split('T')[0]
            };
        }
    }

    // Genera todos los horarios del día de un medicamento respetando la ventana de vigilia.
    // hora_inicio (def. 08:00) → hora_fin (def. 22:00). No genera horarios fuera de esa ventana.
    // Ejemplo: inicio=12:00, cada-6h, fin=22:00 → [12:00, 18:00]
    function getMedHorarios(med) {
        if (med.frecuencia === 'custom' && med.horarios_custom) {
            return med.horarios_custom.split(',').map(h => h.trim()).filter(Boolean);
        }
        const frecuencias = { 'cada-4h': 4, 'cada-6h': 6, 'cada-8h': 8, 'cada-12h': 12, 'diaria': 24 };
        const intervaloHoras = frecuencias[med.frecuencia] || 24;

        const horaInicioStr = (med.hora_inicio && med.hora_inicio !== '') ? med.hora_inicio : '08:00';
        const horaFinStr    = (med.hora_fin    && med.hora_fin    !== '') ? med.hora_fin    : '22:00';
        const [hI, mI] = horaInicioStr.split(':').map(n => parseInt(n) || 0);
        const [hF, mF] = horaFinStr.split(':').map(n => parseInt(n) || 0);
        const inicioMin = hI * 60 + mI;
        let finMin      = hF * 60 + mF;

        // 23:59 = fin de día → extender a 1440 para incluir toma de medianoche (00:00)
        if (finMin === 1439) finMin = 1440;
        // Detectar ventana que cruza medianoche (ej. 23:39 → 06:00)
        const crossesMidnight = inicioMin > finMin;
        const windowMinutes = crossesMidnight
            ? (1440 - inicioMin) + finMin + 1
            : finMin - inicioMin + 1;

        const horarios = [];
        let elapsed = 0;
        while (elapsed < windowMinutes) {
            const t = (inicioMin + elapsed) % 1440;
            const h = Math.floor(t / 60);
            const m = t % 60;
            horarios.push(`${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}`);
            elapsed += intervaloHoras * 60;
        }
        // Garantizar al menos un horario aunque hora_inicio sea >= hora_fin
        if (horarios.length === 0) {
            horarios.push(`${String(hI).padStart(2,'0')}:${String(mI).padStart(2,'0')}`);
        }
        return horarios;
    }

    async function checkAndSendReminders() {
        try {
            // Limpiar entradas viejas de deduplicación (> 24h)
            await pool.query("DELETE FROM push_sent WHERE sent_at < NOW() - INTERVAL '24 hours'").catch(() => {});

            // Limpiar suscripciones que llevan 14+ días sin entrega exitosa (expiradas silenciosamente)
            // Esto previene acumulación de endpoints obsoletos en la tabla push_subscriptions
            await pool.query(`
                DELETE FROM push_subscriptions
                WHERE last_success_at IS NOT NULL
                  AND last_success_at < NOW() - INTERVAL '14 days'
            `).catch(() => {});

            // ── 1. Medicamentos — todos los de recordatorio activo ──
            // getMedHorarios() calcula los horarios del día según frecuencia.
            // Si el med no tiene hora_inicio, usa 08:00 como inicio por defecto.
            const allMeds = await pool.query(`
                SELECT DISTINCT ON (m.id)
                    m.usuario_id, m.nombre, m.dosis,
                    m.hora_inicio, m.hora_fin, m.frecuencia, m.horarios_custom,
                    COALESCE(u.timezone, 'America/Argentina/Buenos_Aires') AS timezone
                FROM medicamentos m
                INNER JOIN push_subscriptions ps ON ps.usuario_id = m.usuario_id
                INNER JOIN usuarios u ON u.id = m.usuario_id
                WHERE m.recordatorio = true
            `);

            for (const med of allMeds.rows) {
                const horarios = getMedHorarios(med);
                if (!horarios.length) continue;
                const tzNow = nowInTZ(med.timezone);
                const tzMin = tzNow.totalMinutes;
                const horaMatch = horarios.find(h => {
                    const [hh, mm] = h.split(':').map(Number);
                    const medMin = hh * 60 + mm;
                    // Ventana de cobertura circular sobre 1440 min/día:
                    //   diff < 15  → hasta 15 min ANTES del horario (cron anticipa la toma)
                    //   diff >= 1420 → hasta 20 min DESPUÉS del horario (cubre reinicios de Railway)
                    // La ventana de deduplicación (25 min) garantiza que no haya duplicados.
                    const diff = (medMin - tzMin + 1440) % 1440;
                    return diff < 15 || diff >= 1420;
                });
                if (!horaMatch) continue;
                const tag = `med-${med.usuario_id}-${med.nombre}-${horaMatch}-${tzNow.dateStr}`;
                // sendPushToUser maneja el dedup por dispositivo internamente.
                // Cada dispositivo tiene su propio tag → si uno falla, el siguiente ciclo lo reintenta.
                await sendPushToUser(med.usuario_id, {
                    title: '💊 Recordatorio de medicamento',
                    body: `${med.nombre} — ${med.dosis} a las ${horaMatch}`,
                    tag, url: '/'
                }, tag);
            }

            // ── 2. Citas: recordatorio vence en la ventana actual (±20/+15 min por timezone) ──
            // Ventana: -20 min (cubre reinicios de Railway) + 15 min adelante.
            const citas = await pool.query(`
                SELECT c.usuario_id, c.titulo, c.fecha, c.hora, c.recordatorio, c.lugar
                FROM citas c
                INNER JOIN push_subscriptions ps ON ps.usuario_id = c.usuario_id
                INNER JOIN usuarios u ON u.id = c.usuario_id
                WHERE c.recordatorio IS NOT NULL
                  AND c.recordatorio <> '0'
                  AND c.hora IS NOT NULL
                  AND (c.fecha::date + c.hora::time)
                      - (CAST(c.recordatorio AS integer) * INTERVAL '1 minute')
                      BETWEEN (NOW() AT TIME ZONE COALESCE(u.timezone,'America/Argentina/Buenos_Aires'))
                              - INTERVAL '20 minutes'
                          AND (NOW() AT TIME ZONE COALESCE(u.timezone,'America/Argentina/Buenos_Aires'))
                              + INTERVAL '15 minutes'
            `);
            for (const cita of citas.rows) {
                const tag = `cita-${cita.usuario_id}-${cita.fecha}-${cita.hora}`;
                const mins = parseInt(cita.recordatorio);
                const tiempoTexto = mins < 60 ? `en ${mins} min`
                    : mins === 60 ? 'en 1 hora'
                    : mins === 1440 ? 'mañana'
                    : `en ${Math.round(mins / 60)}h`;
                await sendPushToUser(cita.usuario_id, {
                    title: '📅 Recordatorio de cita',
                    body: `${cita.titulo} — ${tiempoTexto}${cita.lugar ? ' en ' + cita.lugar : ''}`,
                    tag, url: '/'
                }, tag);
            }

            // ── 3. Tareas ÚNICAS: el datetime exacto (fecha + hora) cae en la ventana actual ──
            // Funciona igual que citas: dispara una única vez cuando fecha+hora coincide.
            const tareasUnicas = await pool.query(`
                SELECT t.id, t.usuario_id, t.titulo, t.hora, t.fecha
                FROM tareas t
                INNER JOIN push_subscriptions ps ON ps.usuario_id = t.usuario_id
                INNER JOIN usuarios u ON u.id = t.usuario_id
                WHERE t.completada = false
                  AND t.recordatorio = true
                  AND t.frecuencia = 'unica'
                  AND t.hora IS NOT NULL
                  AND (t.fecha::date + t.hora::time)
                      BETWEEN (NOW() AT TIME ZONE COALESCE(u.timezone,'America/Argentina/Buenos_Aires'))
                              - INTERVAL '20 minutes'
                          AND (NOW() AT TIME ZONE COALESCE(u.timezone,'America/Argentina/Buenos_Aires'))
                              + INTERVAL '15 minutes'
            `);
            for (const tarea of tareasUnicas.rows) {
                // Tag fijo con fecha+hora: solo dispara una vez en toda la vida de esta tarea
                const tag = `tarea-unica-${tarea.usuario_id}-${tarea.id}-${tarea.fecha}-${tarea.hora.substring(0,5)}`;
                await sendPushToUser(tarea.usuario_id, {
                    title: '✓ Recordatorio de tarea',
                    body: `${tarea.titulo} — a las ${tarea.hora.substring(0, 5)}`,
                    tag, url: '/'
                }, tag);
            }

            // ── 4. Tareas DIARIAS: la hora coincide con la ventana actual Y hoy está dentro del rango activo ──
            // fecha = fecha de inicio (primer día), hasta_fecha = último día (NULL = indefinido).
            // El tag incluye tzNow.dateStr → se resetea cada día → notifica todos los días del rango.
            const tareasDiarias = await pool.query(`
                SELECT t.id, t.usuario_id, t.titulo, t.hora, t.fecha, t.hasta_fecha,
                       COALESCE(u.timezone,'America/Argentina/Buenos_Aires') AS timezone
                FROM tareas t
                INNER JOIN push_subscriptions ps ON ps.usuario_id = t.usuario_id
                INNER JOIN usuarios u ON u.id = t.usuario_id
                WHERE t.completada = false
                  AND t.recordatorio = true
                  AND t.frecuencia = 'diaria'
                  AND t.hora IS NOT NULL
            `);
            for (const tarea of tareasDiarias.rows) {
                const tzNow = nowInTZ(tarea.timezone);
                // ¿Hoy está dentro del rango activo?
                if (tarea.fecha > tzNow.dateStr) continue;       // aún no empezó
                if (tarea.hasta_fecha && tarea.hasta_fecha < tzNow.dateStr) continue; // ya terminó
                // ¿La hora coincide con la ventana actual? (igual que medicamentos, ventana circular)
                const [hh, mm] = tarea.hora.substring(0, 5).split(':').map(Number);
                const tareaMin = hh * 60 + mm;
                const diff = (tareaMin - tzNow.totalMinutes + 1440) % 1440;
                if (!(diff < 15 || diff >= 1420)) continue;
                // Tag con fecha de hoy → se resetea cada día garantizando notificación diaria
                const tag = `tarea-diaria-${tarea.usuario_id}-${tarea.id}-${tzNow.dateStr}`;
                await sendPushToUser(tarea.usuario_id, {
                    title: '✓ Recordatorio de tarea',
                    body: `${tarea.titulo} — a las ${tarea.hora.substring(0, 5)}`,
                    tag, url: '/'
                }, tag);
            }

            const log = nowInTZ('America/Argentina/Buenos_Aires');
            _cronLastRun = new Date().toISOString();
            _cronRunCount++;
            console.log(`[Push Reminders] Chequeo OK — ${String(log.hours).padStart(2,'0')}:${String(log.minutes).padStart(2,'0')} AR — #${_cronRunCount}`);
        } catch (err) {
            console.error('[Push Reminders] Error:', err.message);
        }
    }

    checkAndSendReminders();
    _cronStartedAt = new Date().toISOString();
    setInterval(checkAndSendReminders, 8 * 60 * 1000); // cada 8 minutos — ventana de 20 min atrás + 15 min adelante garantiza cobertura total
    console.log('✅ Push reminders iniciados (chequeo cada 8 minutos)');
}

// ========== CO-CUIDADOR: COMPARTIR ACCESO A PACIENTE (PREMIUM) ==========

// POST /api/share/:pacienteId/invite — el dueño invita a otro email
app.post('/api/share/:pacienteId/invite', authMiddleware, async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'El email del invitado es requerido' });
        const pacienteId = parseInt(req.params.pacienteId);
        // Verificar que el paciente pertenece al usuario
        const pac = await pool.query('SELECT * FROM pacientes WHERE id=$1 AND usuario_id=$2 AND activo=true', [pacienteId, req.user.id]);
        if (pac.rows.length === 0) return res.status(404).json({ error: 'Paciente no encontrado' });
        // Solo premium puede compartir
        const userRes = await pool.query('SELECT premium, nombre FROM usuarios WHERE id=$1', [req.user.id]);
        if (!userRes.rows[0]?.premium) return res.status(403).json({ error: 'El co-cuidador es una función exclusiva de Premium' });
        // Verificar que no se invita a sí mismo
        const propietario = await pool.query('SELECT email FROM usuarios WHERE id=$1', [req.user.id]);
        if (propietario.rows[0]?.email === email) return res.status(400).json({ error: 'No podés invitarte a vos mismo' });
        // Generar token de invitación
        const inviteToken = crypto.randomBytes(32).toString('hex');
        // Buscar si el invitado ya tiene cuenta
        const invitado = await pool.query('SELECT id FROM usuarios WHERE email=$1', [email]);
        const invitadoId = invitado.rows[0]?.id || null;
        // Insertar o actualizar invitación (ON CONFLICT actualiza token)
        await pool.query(
            `INSERT INTO paciente_compartidos (paciente_id, propietario_id, invitado_email, invitado_id, token)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (paciente_id, invitado_email) DO UPDATE SET token=$5, aceptado=FALSE, invitado_id=$4`,
            [pacienteId, req.user.id, email, invitadoId, inviteToken]
        );
        // Enviar email de invitación
        const acceptLink = `${FRONTEND_URL || 'https://cuidadiario.edensoftwork.com'}/index.html?share=${inviteToken}`;
        try {
            await sendEmail({
                to: email,
                subject: `👨‍👩‍👧 ${userRes.rows[0].nombre} te invitó a CuidaDiario`,
                html: `
                    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:24px;border:1px solid #e0e0e0;border-radius:8px;">
                        <h2 style="color:#667eea;">CuidaDiario</h2>
                        <p><strong>${userRes.rows[0].nombre}</strong> te invitó a colaborar en el cuidado de <strong>${pac.rows[0].nombre}</strong>.</p>
                        <p>Con este acceso, podrás ver medicamentos, citas, tareas y más.</p>
                        <div style="text-align:center;margin:28px 0;">
                            <a href="${acceptLink}" style="background:linear-gradient(135deg,#667eea,#764ba2);color:white;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;">Aceptar invitación</a>
                        </div>
                        <p style="color:#777;font-size:0.85rem;">Si no conocés a ${userRes.rows[0].nombre}, podés ignorar este email.</p>
                        <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
                        <p style="color:#aaa;font-size:0.78rem;">CuidaDiario by EDEN SoftWork</p>
                    </div>
                `
            });
        } catch (emailErr) {
            console.warn('[Share] Email no enviado:', emailErr.message);
        }
        res.json({ ok: true, message: `Invitación enviada a ${email}` });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Ya existe una invitación para ese email y paciente' });
        res.status(500).json({ error: err.message });
    }
});

// GET /api/share/accept?token=... — el invitado acepta la invitación
app.get('/api/share/accept', authMiddleware, async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(400).json({ error: 'Token requerido' });
    try {
        const share = await pool.query('SELECT * FROM paciente_compartidos WHERE token=$1', [token]);
        if (share.rows.length === 0) return res.status(404).json({ error: 'Invitación no encontrada o ya utilizada' });
        const s = share.rows[0];
        // Verificar que el email del usuario autenticado coincide con la invitación
        const userEmail = await pool.query('SELECT email FROM usuarios WHERE id=$1', [req.user.id]);
        if (userEmail.rows[0]?.email !== s.invitado_email)
            return res.status(403).json({ error: 'Esta invitación no es para tu cuenta' });
        await pool.query(
            'UPDATE paciente_compartidos SET aceptado=TRUE, invitado_id=$1, token=NULL WHERE id=$2',
            [req.user.id, s.id]
        );
        // Obtener datos del paciente para mostrarlo al aceptar
        const pac = await pool.query('SELECT nombre FROM pacientes WHERE id=$1', [s.paciente_id]);
        res.json({ ok: true, paciente: pac.rows[0]?.nombre || 'Paciente', mensaje: '¡Invitación aceptada! Ya podés ver los datos del paciente.' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/share/list/:pacienteId — lista los co-cuidadores de un paciente
app.get('/api/share/list/:pacienteId', authMiddleware, async (req, res) => {
    try {
        const pac = await pool.query('SELECT id FROM pacientes WHERE id=$1 AND usuario_id=$2', [req.params.pacienteId, req.user.id]);
        if (pac.rows.length === 0) return res.status(403).json({ error: 'No tenés permiso para ver este paciente' });
        const result = await pool.query(
            'SELECT id, invitado_email, aceptado, created_at FROM paciente_compartidos WHERE paciente_id=$1 ORDER BY created_at DESC',
            [req.params.pacienteId]
        );
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/share/:id — el dueño revoca el acceso de un co-cuidador
app.delete('/api/share/:id', authMiddleware, async (req, res) => {
    try {
        // Verificar que el share pertenece a un paciente del usuario
        const result = await pool.query(
            `DELETE FROM paciente_compartidos pc USING pacientes p
             WHERE pc.id=$1 AND pc.paciente_id=p.id AND p.usuario_id=$2 RETURNING pc.id`,
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Acceso compartido no encontrado' });
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== MERCADOPAGO ==========
// ========== MERCADOPAGO B2B (CuidaDiario PRO) ==========
// Endpoints: /api/b2b/create-subscription, /api/b2b/webhook/mercadopago, /api/b2b/verify-subscription
// El external_reference es el id de la institución (instituciones_b2b)

// POST /api/b2b/create-subscription — Crea suscripción MercadoPago para la institución
app.post('/api/b2b/create-subscription', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        // Obtener datos de la institución
        const instRes = await pool.query('SELECT id, nombre, email FROM instituciones_b2b WHERE id=$1', [req.b2bUser.institucion_id]);
        if (instRes.rows.length === 0) return res.status(404).json({ error: 'Institución no encontrada' });
        const inst = instRes.rows[0];
        const PLANES_MP = {
            pro:    { reason: 'CuidaDiario PRO — Plan PRO',    amount: 15000, amount_full: 30000 },
            basico: { reason: 'CuidaDiario PRO — Plan Básico', amount: 10000, amount_full: 20000 }
        };
        const planKey  = Object.keys(PLANES_MP).includes(req.body.plan) ? req.body.plan : 'pro';
        const testMode = req.body.test_mode === true;
        const planInfo = PLANES_MP[planKey];
        const payload = {
            reason: planInfo.reason,
            auto_recurring: { frequency: 1, frequency_type: 'months', transaction_amount: planInfo.amount, currency_id: 'ARS' },
            back_url: `${FRONTEND_URL_PRO}/pages/configuracion.html?mp_success=1&plan=${planKey}`,
            payer_email: inst.email || req.b2bUser.email,
            external_reference: String(inst.id),
            ...(testMode ? { free_trial: { frequency: 1, frequency_type: 'days' } } : {})
        };
        console.log(`[MP B2B] create-subscription — institución ${inst.id}, plan: ${planKey}, testMode: ${testMode}`);
        const mp = await mpRequest('/preapproval', 'POST', payload);
        if (mp.status !== 200 && mp.status !== 201) {
            console.error('Error MP B2B create-subscription:', mp.body);
            return res.status(400).json({ error: mp.body?.message || 'Error al crear suscripción en MercadoPago' });
        }
        res.json({ init_point: mp.body.init_point, preapproval_id: mp.body.id });
    } catch (err) {
        console.error('Error B2B create-subscription:', err);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/b2b/webhook/mercadopago — Webhook MercadoPago para B2B
app.post('/api/b2b/webhook/mercadopago', async (req, res) => {
    try {
        if (!verifyMPWebhookSignature(req)) {
            console.warn('[MP Webhook B2B] Firma inválida — request rechazado');
            return res.sendStatus(401);
        }
        const body = req.body || {};
        const type  = body.type  || null;
        const topic = req.query.topic || body.topic || null;
        const dataId = body.data?.id || req.query['data.id'] || req.query.id || null;
        const isPreapprovalEvent =
            type  === 'subscription_preapproval' ||
            type  === 'preapproval'              ||
            topic === 'preapproval';
        console.log(`[MP Webhook B2B] Recibido — type="${type}" topic="${topic}" dataId="${dataId}"`);
        if (isPreapprovalEvent && dataId) {
            const mp = await mpRequest(`/preapproval/${dataId}`);
            if (mp.status === 200) {
                const preapproval = mp.body;
                const instId = parseInt(preapproval.external_reference);
                if (instId && !isNaN(instId)) {
                    if (preapproval.status === 'authorized') {
                        const plan = _mpPlanFromPreapproval(preapproval);
                        await pool.query(
                            `UPDATE instituciones_b2b
                             SET plan=$1, mp_preapproval_id=$3,
                                 discount_expires_at = CASE WHEN discount_expires_at IS NULL THEN NOW() + INTERVAL '6 months' ELSE discount_expires_at END
                             WHERE id=$2`,
                            [plan, instId, preapproval.id]
                        );
                        console.log(`[MP Webhook B2B] ✅ Institución ${instId} → plan: ${plan.toUpperCase()} (estado MP: "${preapproval.status}")`);
                        // Auto-escalate price if discount period has expired
                        const discountCheck = await pool.query('SELECT discount_expires_at FROM instituciones_b2b WHERE id=$1', [instId]);
                        const expiry = discountCheck.rows[0]?.discount_expires_at;
                        if (expiry && new Date() > new Date(expiry)) {
                            const fullAmounts = { pro: 30000, basico: 20000 };
                            const fullAmount = fullAmounts[plan];
                            const currentAmount = preapproval?.auto_recurring?.transaction_amount;
                            if (fullAmount && currentAmount < fullAmount) {
                                await mpRequest(`/preapproval/${preapproval.id}`, 'PATCH', { auto_recurring: { transaction_amount: fullAmount } });
                                console.log(`[MP Webhook B2B] 💰 Período promocional expirado — institución ${instId} actualizada a $${fullAmount}/mes`);
                            }
                        }
                    } else if (['cancelled', 'paused', 'expired'].includes(preapproval.status)) {
                        await pool.query('UPDATE instituciones_b2b SET plan=$1 WHERE id=$2', ['free', instId]);
                        console.log(`[MP Webhook B2B] 🔻 Institución ${instId} → plan: free (estado MP: "${preapproval.status}")`);
                    } else {
                        console.log(`[MP Webhook B2B] ℹ️ Institución ${instId} — estado MP: "${preapproval.status}" (sin cambio de plan)`);
                    }
                } else {
                    console.warn(`[MP Webhook B2B] external_reference inválido: "${preapproval.external_reference}"`);
                }
            } else {
                console.warn(`[MP Webhook B2B] No se pudo obtener preapproval "${dataId}" — HTTP ${mp.status}`);
            }
        } else {
            console.log(`[MP Webhook B2B] Evento ignorado (no es preapproval)`);
        }
        res.sendStatus(200);
    } catch (err) {
        console.error('[MP Webhook B2B] Error:', err.message);
        res.sendStatus(200);
    }
});

// Helper: determina el plan (pro/basico) a partir de un objeto preapproval de MP
function _mpPlanFromPreapproval(preapproval) {
    const reason = (preapproval?.reason || '').toLowerCase();
    const amount = preapproval?.auto_recurring?.transaction_amount;
    // Detectar por descripción (más fiable — los precios intro y completo se superponen)
    if (reason.includes('plan pro')) return 'pro';
    if (reason.includes('básico') || reason.includes('basico')) return 'basico';
    // Fallback por monto: PRO intro=15000, full=30000; Básico intro=10000, full=20000
    // Umbral conservador: ≥25000 → PRO full; resto → básico
    if (amount >= 25000) return 'pro';
    return 'basico';
}

// GET /api/b2b/verify-subscription — Verifica el estado de la suscripción MP y actualiza el plan
// Requiere preapproval_id en el query para actualizar; sin él solo devuelve el plan actual de la DB.
app.get('/api/b2b/verify-subscription', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    const instId = req.b2bUser.institucion_id;
    try {
        const preapprovalId = req.query.preapproval_id;

        // Sin preapproval_id → solo reportar el plan actual, sin consultar ni modificar MP
        if (!preapprovalId) {
            const instRes = await pool.query('SELECT plan FROM instituciones_b2b WHERE id=$1', [instId]);
            const currentPlan = instRes.rows[0]?.plan || 'free';
            return res.json({ plan: currentPlan, status: 'current' });
        }

        if (!MP_ACCESS_TOKEN) {
            return res.status(400).json({ error: 'MercadoPago no configurado en el servidor' });
        }

        // Con preapproval_id: verificar el pago real en MP
        const mp = await mpRequest(`/preapproval/${preapprovalId}`);
        if (mp.status !== 200) {
            console.warn(`[MP Verify B2B] No se pudo obtener preapproval ${preapprovalId} — HTTP ${mp.status}`);
            return res.json({ plan: 'free', status: 'not_found', message: 'No se pudo verificar el pago. Intentá nuevamente en unos minutos.' });
        }

        const preapproval = mp.body;
        const ref = parseInt(preapproval.external_reference);
        if (ref !== instId) {
            console.warn(`[MP Verify B2B] preapproval ${preapprovalId}: external_reference="${preapproval.external_reference}" no coincide con institucion ${instId}`);
            return res.status(403).json({ error: 'Este pago no corresponde a tu institución' });
        }

        if (preapproval.status === 'authorized') {
            const plan = _mpPlanFromPreapproval(preapproval);
            await pool.query(
                `UPDATE instituciones_b2b
                 SET plan=$1, mp_preapproval_id=$3,
                     discount_expires_at = CASE WHEN discount_expires_at IS NULL THEN NOW() + INTERVAL '6 months' ELSE discount_expires_at END
                 WHERE id=$2`,
                [plan, instId, preapproval.id]
            );
            console.log(`[MP Verify B2B] ✅ Institución ${instId} → plan: ${plan.toUpperCase()} (preapproval: ${preapproval.id})`);
            return res.json({ plan, status: 'authorized' });
        }

        if (preapproval.status === 'pending') {
            return res.json({ plan: 'free', status: 'pending', message: 'El pago está siendo procesado. Puede demorar unos minutos.' });
        }

        // Cancelado / expirado / pausado
        console.log(`[MP Verify B2B] Institución ${instId} — estado MP: "${preapproval.status}"`);
        return res.json({ plan: 'free', status: preapproval.status, message: 'La suscripción no está activa.' });

    } catch (err) {
        console.error('[MP Verify B2B] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

const MP_ACCESS_TOKEN = process.env.MP_ACCESS_TOKEN;

function mpRequest(path, method = 'GET', body = null) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: 'api.mercadopago.com',
            path,
            method,
            headers: { 'Authorization': `Bearer ${MP_ACCESS_TOKEN}`, 'Content-Type': 'application/json' }
        };
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
                catch (e) { resolve({ status: res.statusCode, body: data }); }
            });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

app.post('/api/create-subscription', authMiddleware, async (req, res) => {
    try {
        const userResult = await pool.query('SELECT nombre, email FROM usuarios WHERE id=$1', [req.user.id]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        const user = userResult.rows[0];
        const payload = {
            reason: 'CuidaDiario Premium',
            auto_recurring: { frequency: 1, frequency_type: 'months', transaction_amount: 1500, currency_id: 'ARS' },
            back_url: 'https://cuidadiario.edensoftwork.com/pages/premium-success.html',
            payer_email: user.email,
            external_reference: String(req.user.id)
        };
        const mp = await mpRequest('/preapproval', 'POST', payload);
        if (mp.status !== 200 && mp.status !== 201) {
            console.error('Error MP create-subscription:', mp.body);
            return res.status(400).json({ error: mp.body?.message || 'Error al crear suscripción en MercadoPago' });
        }
        res.json({ init_point: mp.body.init_point, preapproval_id: mp.body.id });
    } catch (err) {
        console.error('Error create-subscription:', err);
        res.status(500).json({ error: err.message });
    }
});

// Helper: verifica firma HMAC-SHA256 del webhook de MercadoPago
// IMPORTANTE: aunque la firma no sea válida NO bloqueamos el request,
// porque siempre re-verificamos el estado con la API de MP.
// Bloquear aquí solo causaría que cancelaciones no se procesen si el secret está mal configurado.
function verifyMPWebhookSignature(req) {
    const MP_WEBHOOK_SECRET = process.env.MP_WEBHOOK_SECRET;
    if (!MP_WEBHOOK_SECRET) return true; // Sin secret: siempre aceptar
    const signature = req.headers['x-signature'];
    const requestId = req.headers['x-request-id'] || '';
    if (!signature) return true; // Sin firma: aceptar igualmente
    const ts = (signature.split(',').find(p => p.startsWith('ts=')) || '').replace('ts=', '');
    const v1 = (signature.split(',').find(p => p.startsWith('v1=')) || '').replace('v1=', '');
    if (!ts || !v1) return true;
    const dataId = req.query['data.id'] || (req.body?.data?.id) || '';
    const manifest = `id:${dataId};request-id:${requestId};ts:${ts}`;
    const expected = crypto.createHmac('sha256', MP_WEBHOOK_SECRET).update(manifest).digest('hex');
    try {
        const valid = crypto.timingSafeEqual(Buffer.from(v1, 'hex'), Buffer.from(expected, 'hex'));
        if (!valid) console.warn('[MP Webhook] ⚠️ Firma inválida — procesando igual (MP_WEBHOOK_SECRET puede estar mal configurado)');
        return true; // Siempre procesar — la re-verificación con MP API garantiza seguridad
    } catch { return true; }
}

app.post('/api/webhook/mercadopago', async (req, res) => {
    try {
        if (!verifyMPWebhookSignature(req)) {
            console.warn('[MP Webhook] Firma inválida — request rechazado');
            return res.sendStatus(401);
        }

        const body = req.body || {};

        // ── Soporta AMBOS sistemas de notificación de MercadoPago ──────────────
        // 1) Nuevo sistema (Webhooks API): body JSON con type y data.id
        // 2) IPN clásico: query params ?topic=preapproval&id=PREAPPROVAL_ID
        const type  = body.type  || null;
        const topic = req.query.topic || body.topic || null;

        // ID del preapproval: viene en body (nuevo) O en query params (IPN)
        const dataId = body.data?.id
            || req.query['data.id']
            || req.query.id
            || null;

        const isPreapprovalEvent =
            type  === 'subscription_preapproval' ||
            type  === 'preapproval'              ||
            topic === 'preapproval';

        console.log(`[MP Webhook] Recibido — type="${type}" topic="${topic}" dataId="${dataId}"`);

        if (isPreapprovalEvent && dataId) {
            const mp = await mpRequest(`/preapproval/${dataId}`);
            if (mp.status === 200) {
                const preapproval = mp.body;
                const userId = parseInt(preapproval.external_reference);
                if (userId && !isNaN(userId)) {
                    const isPremium = preapproval.status === 'authorized';
                    if (isPremium) {
                        await pool.query('UPDATE usuarios SET premium=TRUE, premium_welcome_pending=TRUE WHERE id=$1', [userId]);
                    } else {
                        await pool.query('UPDATE usuarios SET premium=FALSE WHERE id=$1', [userId]);
                    }
                    console.log(`[MP Webhook] ✅ Usuario ${userId} → premium: ${isPremium} (estado MP: "${preapproval.status}")`);
                } else {
                    console.warn(`[MP Webhook] external_reference inválido: "${preapproval.external_reference}"`);
                }
            } else {
                console.warn(`[MP Webhook] No se pudo obtener preapproval "${dataId}" — HTTP ${mp.status}`);
            }
        } else {
            // Evento que no es de preapproval (pagos, etc.) — ignorar silenciosamente
            console.log(`[MP Webhook] Evento ignorado (no es preapproval)`);
        }

        res.sendStatus(200);
    } catch (err) {
        console.error('[MP Webhook] Error:', err.message);
        res.sendStatus(200);
    }
});

// ========== VERIFICACIÓN MANUAL DE SUSCRIPCIÓN MP ==========
// GET /api/verify-subscription — activa premium si MercadoPago tiene una suscripción autorizada.
// Usado por premium-success.html tras el redirect de MP, y como fallback desde la app.
// Acepta opcionalmente ?preapproval_id=XXX (viene en el back_url de MP).
app.get('/api/verify-subscription', authMiddleware, async (req, res) => {
    if (!MP_ACCESS_TOKEN) {
        return res.status(400).json({ error: 'MercadoPago no configurado en el servidor' });
    }
    try {
        let authorized = null;

        // Intento 1: preapproval_id específico enviado por el frontend (viene del back_url de MP)
        const preapprovalId = req.query.preapproval_id;
        if (preapprovalId) {
            const mp = await mpRequest(`/preapproval/${preapprovalId}`);
            if (mp.status === 200 && mp.body.status === 'authorized') {
                const ref = parseInt(mp.body.external_reference);
                if (ref === req.user.id) {
                    authorized = mp.body;
                } else {
                    console.warn(`[MP Verify] preapproval ${preapprovalId}: external_reference="${mp.body.external_reference}" no coincide con usuario ${req.user.id}`);
                }
            }
        }

        // Intento 2: buscar por external_reference (cubre cualquier suscripción del usuario)
        if (!authorized) {
            const search = await mpRequest(`/preapproval/search?external_reference=${req.user.id}&status=authorized`);
            if (search.status === 200) {
                const results = search.body?.results || [];
                // CRÍTICO: verificar que external_reference coincide con el usuario solicitante.
                // Sin esta verificación, un bug de la API de MP podría retornar suscripciones ajenas
                // (ej: en entornos de prueba), otorgando premium a co-cuidadores sin suscripción.
                authorized = results.find(p =>
                    p.status === 'authorized' &&
                    parseInt(p.external_reference) === req.user.id
                ) || null;
            }
        }

        if (authorized) {
            await pool.query('UPDATE usuarios SET premium=TRUE, premium_welcome_pending=TRUE WHERE id=$1', [req.user.id]);
            console.log(`[MP Verify] ✅ Usuario ${req.user.id} → premium: TRUE (preapproval: ${authorized.id})`);
            return res.json({ premium: true, status: 'authorized' });
        }

        // Sin suscripción autorizada — buscar todas para saber el estado real
        const searchAll = await mpRequest(`/preapproval/search?external_reference=${req.user.id}`);
        const allResults = searchAll.body?.results || [];
        const pending    = allResults.find(p => p.status === 'pending');
        const cancelled  = allResults.find(p => ['cancelled', 'paused', 'expired'].includes(p.status));

        // Si hay una cancelada/pausada/expirada y ninguna autorizada → bajar premium
        if (cancelled && !pending) {
            await pool.query('UPDATE usuarios SET premium=FALSE WHERE id=$1', [req.user.id]);
            console.log(`[MP Verify] 🔻 Usuario ${req.user.id} → premium: FALSE (estado MP: "${cancelled.status}")`);
            return res.json({ premium: false, status: cancelled.status,
                message: 'Tu suscripción fue cancelada o expiró.' });
        }

        console.log(`[MP Verify] Usuario ${req.user.id} — estados: ${allResults.map(p => p.status).join(', ') || 'ninguna'}`);
        return res.json({
            premium: false,
            status: pending ? 'pending' : 'not_found',
            message: pending
                ? 'Tu pago está siendo procesado. Puede demorar unos minutos.'
                : 'No se encontró suscripción activa en MercadoPago.'
        });
    } catch (err) {
        console.error('[MP Verify] Error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// ========== PERFIL Y USUARIO ==========
app.get('/api/me', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            "SELECT id, nombre, email, premium, COALESCE(premium_welcome_pending,FALSE) AS premium_welcome_pending, COALESCE(timezone,'America/Argentina/Buenos_Aires') AS timezone FROM usuarios WHERE id=$1",
            [req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json({ usuario: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/premium/acknowledge-welcome — el frontend lo llama tras mostrar el modal.
// Evita que el modal se repita en otras sesiones/dispositivos del mismo usuario.
app.post('/api/premium/acknowledge-welcome', authMiddleware, async (req, res) => {
    try {
        await pool.query('UPDATE usuarios SET premium_welcome_pending=FALSE WHERE id=$1', [req.user.id]);
        res.json({ ok: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/profile', authMiddleware, async (req, res) => {
    try {
        const { nombre, email, password, timezone } = req.body;
        if (!nombre || !email) return res.status(400).json({ error: 'Nombre y email son requeridos' });
        const existing = await pool.query('SELECT id FROM usuarios WHERE email=$1 AND id!=$2', [email, req.user.id]);
        if (existing.rows.length > 0) return res.status(400).json({ error: 'El email ya está en uso por otra cuenta' });
        const tz = timezone || 'America/Argentina/Buenos_Aires';
        let result;
        if (password) {
            const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
            result = await pool.query(
                'UPDATE usuarios SET nombre=$1, email=$2, password_hash=$3, timezone=$4 WHERE id=$5 RETURNING id, nombre, email, premium, timezone',
                [nombre, email, password_hash, tz, req.user.id]
            );
        } else {
            result = await pool.query(
                'UPDATE usuarios SET nombre=$1, email=$2, timezone=$3 WHERE id=$4 RETURNING id, nombre, email, premium, timezone',
                [nombre, email, tz, req.user.id]
            );
        }
        res.json({ mensaje: 'Perfil actualizado', usuario: result.rows[0] });
    } catch (err) {
        console.error('Error actualizando perfil:', err);
        res.status(500).json({ error: err.message });
    }
});

// ========== PAYPAL — deshabilitado temporalmente (restricciones para Argentina) ==========
// Para reactivar: descomentar todo este bloque y los endpoints de abajo,
// y habilitar window.PAYPAL_CLIENT_ID/PLAN_ID en index.html
/*
const PAYPAL_CLIENT_ID     = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_MODE          = process.env.PAYPAL_MODE || 'sandbox';
const PAYPAL_API_HOST      = PAYPAL_MODE === 'live' ? 'api-m.paypal.com' : 'api-m.sandbox.paypal.com';

function getPayPalAccessToken() {
    return new Promise((resolve, reject) => {
        const credentials = Buffer.from(`${PAYPAL_CLIENT_ID}:${PAYPAL_CLIENT_SECRET}`).toString('base64');
        const postData = 'grant_type=client_credentials';
        const options = {
            hostname: PAYPAL_API_HOST, path: '/v1/oauth2/token', method: 'POST',
            headers: { 'Authorization': `Basic ${credentials}`, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(postData) }
        };
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => { try { resolve(JSON.parse(data).access_token); } catch (e) { reject(e); } });
        });
        req.on('error', reject);
        req.write(postData);
        req.end();
    });
}

async function paypalRequest(path, method, body = null) {
    const accessToken = await getPayPalAccessToken();
    return new Promise((resolve, reject) => {
        const options = {
            hostname: PAYPAL_API_HOST, path, method,
            headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' }
        };
        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => { try { resolve({ status: res.statusCode, body: JSON.parse(data) }); } catch (e) { resolve({ status: res.statusCode, body: data }); } });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}
*/

/* PAYPAL ENDPOINTS — deshabilitado temporalmente (restricciones para Argentina)
 * Para reactivar: descomentar este bloque completo y el bloque de funciones de arriba.

app.post('/api/paypal/create-order', authMiddleware, async (req, res) => {
    try {
        const { amount, currency } = req.body;
        const result = await paypalRequest('/v2/checkout/orders', 'POST', {
            intent: 'CAPTURE',
            purchase_units: [{ amount: { currency_code: currency || 'USD', value: String(amount || '3.00') }, description: 'CuidaDiario Premium' }]
        });
        if (result.status !== 201) return res.status(400).json({ error: result.body?.message || 'Error al crear orden en PayPal' });
        res.json({ orderID: result.body.id });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/paypal/capture-order/:orderID', authMiddleware, async (req, res) => {
    try {
        const result = await paypalRequest(`/v2/checkout/orders/${req.params.orderID}/capture`, 'POST');
        if (result.status !== 201 && result.status !== 200) return res.status(400).json({ error: result.body?.message || 'Error al capturar pago en PayPal' });
        await pool.query('UPDATE usuarios SET premium=$1 WHERE id=$2', [true, req.user.id]);
        console.log(`[PayPal] Usuario ${req.user.id} → premium: true`);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/paypal/activate-subscription', authMiddleware, async (req, res) => {
    try {
        const { subscriptionID } = req.body;
        if (!subscriptionID) return res.status(400).json({ error: 'subscriptionID requerido' });
        await pool.query('UPDATE usuarios SET premium=$1, paypal_subscription_id=$2 WHERE id=$3', [true, subscriptionID, req.user.id]);
        console.log(`[PayPal Subscription] Usuario ${req.user.id} → premium: true (sub: ${subscriptionID})`);
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/paypal/webhook', async (req, res) => {
    try {
        const rawBody = req.body;
        const event = JSON.parse(Buffer.isBuffer(rawBody) ? rawBody.toString() : rawBody);
        console.log('🔔 PayPal webhook recibido:', event.event_type, event.id);
        const CANCEL_EVENTS = ['BILLING.SUBSCRIPTION.CANCELLED', 'BILLING.SUBSCRIPTION.SUSPENDED', 'BILLING.SUBSCRIPTION.EXPIRED'];
        if (CANCEL_EVENTS.includes(event.event_type)) {
            const subscriptionId = event.resource?.id;
            if (subscriptionId) {
                const result = await pool.query(
                    'UPDATE usuarios SET premium=FALSE WHERE paypal_subscription_id=$1 RETURNING id, email',
                    [subscriptionId]
                );
                if (result.rows.length > 0) {
                    console.log(`🔻 Premium desactivado para usuario ${result.rows[0].id} — ${event.event_type}`);
                }
            }
        }
        res.status(200).json({ received: true });
    } catch (err) {
        console.error('Error procesando PayPal webhook:', err);
        res.status(200).json({ received: true });
    }
});
*/

// ========== INICIAR SERVIDOR ==========

// Sincronización periódica de estados de suscripción con MercadoPago.
// Garantiza que cancelaciones/pausas se reflejen aunque el webhook haya fallado.
// Corre cada 4 horas. Si MP_ACCESS_TOKEN no está configurado, no hace nada.
async function syncMPSubscriptions() {
    if (!MP_ACCESS_TOKEN) return;
    try {
        const premiumUsers = await pool.query('SELECT id FROM usuarios WHERE premium = TRUE');
        if (premiumUsers.rows.length === 0) return;
        console.log(`[MP Sync] Verificando ${premiumUsers.rows.length} usuario(s) premium...`);
        let deactivated = 0;
        for (const user of premiumUsers.rows) {
            try {
                const search = await mpRequest(`/preapproval/search?external_reference=${user.id}&status=authorized`);
                if (search.status !== 200) continue;
                const hasAuthorized = (search.body?.results || []).some(p => p.status === 'authorized');
                if (!hasAuthorized) {
                    await pool.query('UPDATE usuarios SET premium=FALSE WHERE id=$1', [user.id]);
                    console.log(`[MP Sync] 🔻 Usuario ${user.id} → premium: FALSE (sin suscripción autorizada)`);
                    deactivated++;
                }
                // Pequeña pausa entre requests para no saturar la API de MP
                await new Promise(r => setTimeout(r, 300));
            } catch (e) {
                console.warn(`[MP Sync] Error verificando usuario ${user.id}:`, e.message);
            }
        }
        console.log(`[MP Sync] ✅ Sync completado — ${deactivated} usuario(s) desactivado(s)`);
    } catch (e) {
        console.error('[MP Sync] Error:', e.message);
    }

    // B2B — sincronizar instituciones con planes pagos
    try {
        const b2bInsts = await pool.query("SELECT id FROM instituciones_b2b WHERE plan IN ('basico','pro')");
        if (b2bInsts.rows.length > 0) {
            console.log(`[MP Sync B2B] Verificando ${b2bInsts.rows.length} institución(es) con plan activo...`);
            let b2bDeactivated = 0;
            for (const inst of b2bInsts.rows) {
                try {
                    const search = await mpRequest(`/preapproval/search?external_reference=b2b_${inst.id}&status=authorized`);
                    if (search.status !== 200) continue;
                    const hasAuthorized = (search.body?.results || []).some(p => p.status === 'authorized');
                    if (!hasAuthorized) {
                        await pool.query("UPDATE instituciones_b2b SET plan='free' WHERE id=$1", [inst.id]);
                        console.log(`[MP Sync B2B] 🔻 Institución ${inst.id} → plan: free (sin suscripción autorizada)`);
                        b2bDeactivated++;
                    }
                    await new Promise(r => setTimeout(r, 300));
                } catch (e) {
                    console.warn(`[MP Sync B2B] Error verificando institución ${inst.id}:`, e.message);
                }
            }
            console.log(`[MP Sync B2B] ✅ Sync B2B completado — ${b2bDeactivated} institución(es) desactivada(s)`);
        }
    } catch (e) {
        console.warn('[MP Sync B2B] Error en sync B2B:', e.message);
    }
}

// ========== RECORDATORIOS DE VENCIMIENTO DE TRIAL ==========
// Envía emails de aviso a instituciones en período de prueba que están por vencer.
// Se llama diariamente desde el servidor.
async function checkTrialReminders() {
    if (!RESEND_API_KEY) return; // sin email configurado, saltar silenciosamente
    try {
        // Aviso a los 45 días (15 días restantes) — ventana de ±12h para no duplicar
        const warn15 = await pool.query(`
            SELECT id, nombre, email FROM instituciones_b2b
            WHERE plan = 'free' AND trial_started_at IS NOT NULL
              AND email IS NOT NULL AND email <> ''
              AND NOW() - trial_started_at BETWEEN INTERVAL '44 days 12 hours' AND INTERVAL '45 days 12 hours'
        `);
        for (const inst of warn15.rows) {
            try {
                await sendEmail({
                    to: inst.email,
                    subject: 'Tu prueba gratuita de CuidaDiario PRO vence en 15 días',
                    html: `<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:520px;margin:auto;padding:28px;border:1px solid #e5e7eb;border-radius:12px">
                        <h2 style="color:#1565C0;margin-top:0">⏳ Te quedan 15 días de prueba</h2>
                        <p>Hola <strong>${inst.nombre}</strong>,</p>
                        <p>Tu período de prueba gratuito de <strong>CuidaDiario PRO</strong> vence en <strong>15 días</strong>.</p>
                        <p>Para seguir usando todas las funciones sin interrupciones, activá un plan desde la sección <em>Configuración → Mi Plan</em>.</p>
                        <a href="${FRONTEND_URL_PRO}/pages/configuracion.html" style="display:inline-block;background:#1565C0;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;margin-top:12px">Ver planes →</a>
                        <p style="color:#9CA3AF;font-size:.8rem;margin-top:24px">CuidaDiario PRO · EDEN SoftWork · <a href="mailto:edensoftwarework@gmail.com" style="color:#9CA3AF">soporte</a></p>
                    </div>`
                });
                console.log(`[Trial Reminder] ⏳ Aviso 15 días enviado a ${inst.email} (institución ${inst.id})`);
            } catch (e) { console.warn(`[Trial Reminder] No se pudo enviar a ${inst.email}:`, e.message); }
        }

        // Aviso final a los 55 días (5 días restantes) — ventana de ±12h
        const warn5 = await pool.query(`
            SELECT id, nombre, email FROM instituciones_b2b
            WHERE plan = 'free' AND trial_started_at IS NOT NULL
              AND email IS NOT NULL AND email <> ''
              AND NOW() - trial_started_at BETWEEN INTERVAL '54 days 12 hours' AND INTERVAL '55 days 12 hours'
        `);
        for (const inst of warn5.rows) {
            try {
                await sendEmail({
                    to: inst.email,
                    subject: '⚠️ Tu prueba de CuidaDiario PRO vence en 5 días',
                    html: `<div style="font-family:'Segoe UI',Arial,sans-serif;max-width:520px;margin:auto;padding:28px;border:1px solid #e5e7eb;border-radius:12px">
                        <h2 style="color:#DC2626;margin-top:0">⚠️ ¡Solo quedan 5 días!</h2>
                        <p>Hola <strong>${inst.nombre}</strong>,</p>
                        <p>Tu período de prueba gratuito de <strong>CuidaDiario PRO</strong> vence en <strong>5 días</strong>.</p>
                        <p>Después de esa fecha, no podrás agregar nuevos registros. Tus datos existentes estarán seguros.</p>
                        <a href="${FRONTEND_URL_PRO}/pages/configuracion.html" style="display:inline-block;background:#DC2626;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:700;margin-top:12px">Activar plan ahora →</a>
                        <p style="color:#9CA3AF;font-size:.8rem;margin-top:24px">CuidaDiario PRO · EDEN SoftWork · <a href="mailto:edensoftwarework@gmail.com" style="color:#9CA3AF">soporte</a></p>
                    </div>`
                });
                console.log(`[Trial Reminder] ⚠️ Aviso final 5 días enviado a ${inst.email} (institución ${inst.id})`);
            } catch (e) { console.warn(`[Trial Reminder] No se pudo enviar a ${inst.email}:`, e.message); }
        }
    } catch (e) {
        console.error('[Trial Reminders] Error:', e.message);
    }
}

// ========== NOTAS ==========
app.get('/api/notas', authMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = 'SELECT * FROM notas WHERE usuario_id = $1';
        const params = [req.user.id];
        if (paciente_id) {
            query += ' AND paciente_id = $2';
            params.push(paciente_id);
        }
        query += ' ORDER BY created_at DESC';
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('GET /api/notas:', err.message);
        res.status(500).json({ error: 'Error al obtener notas' });
    }
});

app.post('/api/notas', authMiddleware, async (req, res) => {
    try {
        const { paciente_id, titulo, contenido, color, recordatorio } = req.body;
        const result = await pool.query(
            `INSERT INTO notas (usuario_id, paciente_id, titulo, contenido, color, recordatorio)
             VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [
                req.user.id,
                paciente_id || null,
                titulo || null,
                contenido || null,
                color || 'amarillo',
                recordatorio || null
            ]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/notas:', err.message);
        res.status(500).json({ error: 'Error al guardar nota' });
    }
});

app.patch('/api/notas/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const { titulo, contenido, color, recordatorio } = req.body;
        const result = await pool.query(
            `UPDATE notas
             SET titulo = $1, contenido = $2, color = $3, recordatorio = $4
             WHERE id = $5 AND usuario_id = $6
             RETURNING *`,
            [titulo || null, contenido || null, color || 'amarillo', recordatorio || null, id, req.user.id]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Nota no encontrada' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('PATCH /api/notas:', err.message);
        res.status(500).json({ error: 'Error al actualizar nota' });
    }
});

app.delete('/api/notas/:id', authMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            'DELETE FROM notas WHERE id = $1 AND usuario_id = $2 RETURNING id',
            [id, req.user.id]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Nota no encontrada' });
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/notas:', err.message);
        res.status(500).json({ error: 'Error al eliminar nota' });
    }
});

// ============================================================
// ========== B2B — MÓDULO INSTITUCIONAL ==========
// ============================================================

// ---------- B2B: Helper de límites de plan y expiración del trial ----------
/**
 * Verifica si una institución puede realizar una acción según su plan y trial.
 * Retorna { allowed: true } o { allowed: false, error, code? }
 */
async function checkInstPlanForAction(instId, action) {
    const r = await pool.query(
        `SELECT plan, trial_started_at,
            (SELECT COUNT(*) FROM pacientes_b2b WHERE institucion_id=$1 AND activo=TRUE AND fecha_egreso IS NULL) AS pacientes_count,
            (SELECT COUNT(*) FROM usuarios_b2b WHERE institucion_id=$1 AND activo=TRUE) AS staff_count
         FROM instituciones_b2b WHERE id=$1`,
        [instId]
    );
    const inst = r.rows[0];
    if (!inst) return { allowed: false, error: 'Institución no encontrada' };

    const pacientesCount = parseInt(inst.pacientes_count) || 0;
    const staffCount = parseInt(inst.staff_count) || 0;

    // Verificar expiración del trial (plan 'free' = período de prueba)
    if (inst.plan === 'free') {
        const started = inst.trial_started_at ? new Date(inst.trial_started_at) : new Date();
        const daysDiff = (Date.now() - started.getTime()) / (1000 * 60 * 60 * 24);
        if (daysDiff > 60) {
            // Permitir solo lectura y modificaciones/eliminaciones de pacientes y staff
            // (para que puedan reducir el conteo antes de contratar Básico)
            const allowedInExpiredTrial = ['editar_paciente', 'eliminar_paciente', 'archivar_paciente', 'editar_staff', 'eliminar_staff'];
            if (!allowedInExpiredTrial.includes(action)) {
                return {
                    allowed: false,
                    code: 'TRIAL_EXPIRED',
                    pacientes_count: pacientesCount,
                    staff_count: staffCount,
                    can_use_basico: pacientesCount <= 20 && staffCount <= 5,
                    error: 'Tu período de prueba de 60 días ha vencido. Activá un plan desde Configuración para continuar.'
                };
            }
        }
    }

    // Verificar límites del plan Básico
    if (inst.plan === 'basico') {
        if (action === 'crear_paciente') {
            if (pacientesCount >= 20) {
                return { allowed: false, error: 'Tu plan Básico permite hasta 20 pacientes activos. Actualizá a PRO para agregar más.' };
            }
        }
        if (action === 'crear_staff') {
            if (staffCount >= 5) {
                return { allowed: false, error: 'Tu plan Básico permite hasta 5 miembros del equipo. Actualizá a PRO para agregar más.' };
            }
        }
    }

    return { allowed: true };
}

/**
 * Middleware Express: bloquea cualquier escritura clínica si el trial expiró.
 * Se aplica a todos los endpoints POST/PATCH/PUT de datos clínicos.
 */
async function requireActivePlan(req, res, next) {
    try {
        const check = await checkInstPlanForAction(req.b2bUser.institucion_id, 'accion_clinica');
        if (!check.allowed) {
            return res.status(403).json({
                error: check.error,
                code: check.code || 'PLAN_REQUIRED',
                pacientes_count: check.pacientes_count,
                staff_count: check.staff_count,
                can_use_basico: check.can_use_basico
            });
        }
        next();
    } catch (err) {
        console.error('requireActivePlan:', err.message);
        next(); // ante fallo de la verificación, no bloquear
    }
}

// ---------- B2B: Middleware de autenticación ----------
function authB2BMiddleware(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ error: 'Token B2B requerido' });
    const token = auth.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.b2b) return res.status(401).json({ error: 'Token no es B2B' });
        // Bloquear usuarios cuyo email_verified sea explícitamente false (en el JWT).
        // === false es intencional: undefined (tokens viejos sin el campo) pasa sin problemas.
        if (decoded.email_verified === false) {
            return res.status(401).json({ error: 'Email no verificado. Revisá tu bandeja de entrada o solicitá un nuevo enlace desde el login.', code: 'EMAIL_NOT_VERIFIED' });
        }
        req.b2bUser = decoded;
        next();
    } catch (e) {
        return res.status(401).json({ error: 'Token B2B inválido o expirado' });
    }
}

function requireB2BRole(...roles) {
    return (req, res, next) => {
        if (!roles.includes(req.b2bUser.rol)) {
            return res.status(403).json({ error: 'No tenés permisos para esta acción' });
        }
        next();
    };
}

// Helper: verifica si el usuario B2B puede acceder a un paciente
async function checkB2BPacienteAccess(b2bUser, paciente_id) {
    if (b2bUser.rol === 'admin_institucion' || b2bUser.rol === 'medico') {
        const r = await pool.query('SELECT id FROM pacientes_b2b WHERE id=$1 AND institucion_id=$2 AND activo=TRUE', [paciente_id, b2bUser.institucion_id]);
        return r.rowCount > 0;
    }
    const r = await pool.query('SELECT id FROM asignaciones_b2b WHERE cuidador_id=$1 AND paciente_id=$2 AND activa=TRUE', [b2bUser.id, paciente_id]);
    return r.rowCount > 0;
}

// Helper: verifica si el usuario B2B tiene permiso para una acción según configuración de la institución en DB
async function checkB2BCanDo(b2bUser, action) {
    if (b2bUser.rol === 'admin_institucion') return true;
    if (b2bUser.rol === 'familiar') return false;
    const defaults = {
        crear_paciente:    { medico: true,  cuidador_staff: true  },
        editar_paciente:   { medico: true,  cuidador_staff: true  },
        dar_alta:          { medico: true,  cuidador_staff: false },
        eliminar_paciente: { medico: false, cuidador_staff: false },
    };
    try {
        const r = await pool.query('SELECT permisos_equipo FROM instituciones_b2b WHERE id=$1', [b2bUser.institucion_id]);
        const perms = r.rows[0]?.permisos_equipo || {};
        const key = `${b2bUser.rol}_${action}`;
        if (key in perms) return !!perms[key];
    } catch {}
    return defaults[action]?.[b2bUser.rol] ?? false;
}

// ---------- B2B: AUTH ----------

// POST /api/b2b/auth/register — registrar institución + primer admin
app.post('/api/b2b/auth/register', authRateLimit, async (req, res) => {
    try {
        const { nombre_institucion, tipo_institucion, nombre_admin, email, password, telefono } = req.body;
        if (!nombre_institucion || !email || !password || !nombre_admin)
            return res.status(400).json({ error: 'Faltan datos obligatorios' });

        const exists = await pool.query('SELECT id FROM usuarios_b2b WHERE email=$1', [email.toLowerCase()]);
        if (exists.rowCount > 0) return res.status(409).json({ error: 'El email ya está registrado' });

        const inst = await pool.query(
            `INSERT INTO instituciones_b2b (nombre, tipo, telefono, email, plan, trial_started_at)
             VALUES ($1,$2,$3,$4,'free',NOW()) RETURNING id, plan`,
            [nombre_institucion, tipo_institucion || 'geriatrico', telefono || null, email.toLowerCase()]
        );
        const institucion_id = inst.rows[0].id;

        // Emails de prueba (test@test, test1@test1 ... test9@test9): se verifican automáticamente
        const isTestEmail = /^test\d*@test\d*$/i.test(email.trim());
        let verificationToken = null;
        let verificationExpiry = null;
        let emailVerified = isTestEmail;

        if (!isTestEmail) {
            verificationToken = require('crypto').randomBytes(32).toString('hex');
            verificationExpiry = new Date(Date.now() + 72 * 60 * 60 * 1000); // 72 horas
        }

        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        const user = await pool.query(
            `INSERT INTO usuarios_b2b (institucion_id, nombre, email, password_hash, rol)
             VALUES ($1,$2,$3,$4,'admin_institucion') RETURNING id, nombre, email, rol`,
            [institucion_id, nombre_admin, email.toLowerCase(), hash]
        );

        // Intentar guardar los campos de verificación de email (requieren migración v6).
        // Wrapped en try/catch para que el registro funcione aunque la migración aún no haya corrido.
        let emailVerifiedFinal = isTestEmail;
        if (!isTestEmail) {
            try {
                await pool.query(
                    `UPDATE usuarios_b2b
                     SET email_verified=FALSE, email_verification_token=$1, email_verification_expiry=$2
                     WHERE id=$3`,
                    [verificationToken, verificationExpiry, user.rows[0].id]
                );
            } catch (verErr) {
                // Las columnas aún no existen — el usuario puede verificar más tarde
                console.warn('[B2B] Columnas de verificación no disponibles (migración pendiente):', verErr.message);
                emailVerifiedFinal = true; // tratarlo como verificado para no bloquear el flujo
            }
        } else {
            // Email de prueba: marcar verificado directamente
            await pool.query('UPDATE usuarios_b2b SET email_verified=TRUE WHERE id=$1', [user.rows[0].id]).catch(() => {});
        }

        // Enviar email de verificación (solo para emails reales y si la actualización de token fue exitosa)
        if (!isTestEmail && emailVerifiedFinal === false) {
            if (!process.env.RESEND_API_KEY) {
                console.error('[B2B] ⚠️  RESEND_API_KEY no está configurada en Railway. El email de verificación NO fue enviado a', email, '\u2014 Configurá la variable de entorno RESEND_API_KEY para habilitar el envío de emails.');
            } else {
                const verifyUrl = `${FRONTEND_URL_PRO}/verify-email.html?token=${verificationToken}&b2b=1`;
                try {
                    await fetch('https://api.resend.com/emails', {
                    method: 'POST',
                    headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        from: process.env.EMAIL_FROM || 'CuidaDiario PRO <noreply@cuidadiario.com>',
                        to: email,
                        subject: 'Confirmá tu cuenta — CuidaDiario PRO',
                        html: `
                            <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px;border:1px solid #e0e0e0;border-radius:10px">
                                <h2 style="color:#4F46E5;margin-bottom:4px">CuidaDiario <strong>PRO</strong></h2>
                                <p style="color:#6B7280;font-size:.88rem;margin-top:0">Plataforma de gestión institucional</p>
                                <hr style="border:none;border-top:1px solid #eee;margin:16px 0">
                                <p>Hola <strong>${nombre_admin}</strong>,</p>
                                <p>Tu cuenta para la institución <strong>${nombre_institucion}</strong> fue creada correctamente.</p>
                                <p>Para activarla y poder usar todas las funciones, confirmá tu email haciendo clic en el botón de abajo:</p>
                                <div style="text-align:center;margin:28px 0">
                                    <a href="${verifyUrl}"
                                       style="background:#4F46E5;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:1rem;display:inline-block">
                                        Confirmar mi cuenta
                                    </a>
                                </div>
                                <p style="color:#9CA3AF;font-size:.82rem">Este enlace vence en <strong>72 horas</strong>. Si no creaste esta cuenta, podés ignorar este email.</p>
                                <hr style="border:none;border-top:1px solid #eee;margin:20px 0">
                                <p style="color:#D1D5DB;font-size:.75rem">CuidaDiario PRO — EDEN SoftWork</p>
                            </div>
                        `
                    })
                });
                console.log(`[B2B] Email de verificación enviado a ${email}`);
                } catch (emailErr) {
                    console.warn(`[B2B] Email de verificación no enviado a ${email}:`, emailErr.message);
                }
            } // end if RESEND_API_KEY
        } // end if !isTestEmail && emailVerifiedFinal === false

        const token = jwt.sign(
            { id: user.rows[0].id, institucion_id, rol: 'admin_institucion', email: user.rows[0].email, nombre: user.rows[0].nombre, b2b: true, email_verified: emailVerifiedFinal },
            JWT_SECRET, { expiresIn: '30d' }
        );
        res.status(201).json({
            token,
            user: {
                id: user.rows[0].id,
                nombre: user.rows[0].nombre,
                email: user.rows[0].email,
                rol: user.rows[0].rol,
                institucion_id,
                institucion_nombre: nombre_institucion,
                plan: inst.rows[0].plan,
                institucion_permisos: {},
                onboarding_done: false,
                email_verified: emailVerifiedFinal
            }
        });
    } catch (err) {
        console.error('POST /api/b2b/auth/register:', err.message);
        res.status(500).json({ error: 'Error al registrar institución' });
    }
});

// POST /api/b2b/auth/login
app.post('/api/b2b/auth/login', authRateLimit, async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email y contraseña requeridos' });

        const result = await pool.query(
            `SELECT u.*, i.nombre as institucion_nombre, i.plan, i.activa as institucion_activa, i.permisos_equipo, i.onboarding_done, i.stock_modelo, i.shared_mode, i.trial_started_at, i.discount_expires_at
             FROM usuarios_b2b u JOIN instituciones_b2b i ON u.institucion_id = i.id
             WHERE u.email = $1`,
            [email.toLowerCase()]
        );
        if (result.rowCount === 0) return res.status(401).json({ error: 'Credenciales inválidas' });

        const user = result.rows[0];
        if (!user.activo) return res.status(401).json({ error: 'Usuario desactivado' });
        if (!user.institucion_activa) return res.status(401).json({ error: 'Institución desactivada' });

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return res.status(401).json({ error: 'Credenciales inválidas' });

        const token = jwt.sign(
            { id: user.id, institucion_id: user.institucion_id, rol: user.rol, email: user.email, nombre: user.nombre, b2b: true, email_verified: !!user.email_verified },
            JWT_SECRET, { expiresIn: '30d' }
        );
        res.json({ token, user: { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol, institucion_id: user.institucion_id, institucion_nombre: user.institucion_nombre, plan: user.plan, institucion_permisos: user.permisos_equipo || {}, onboarding_done: !!user.onboarding_done, email_verified: !!user.email_verified, stock_modelo: user.stock_modelo || 'familiar', shared_mode: !!user.shared_mode, trial_started_at: user.trial_started_at || null, notif_prefs: user.notif_prefs || {}, discount_expires_at: user.discount_expires_at || null } });
    } catch (err) {
        console.error('POST /api/b2b/auth/login:', err.message);
        res.status(500).json({ error: 'Error al iniciar sesión' });
    }
});

// GET /api/b2b/auth/me
app.get('/api/b2b/auth/me', authB2BMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT u.id, u.nombre, u.email, u.rol, u.created_at, u.email_verified,
                    i.id as institucion_id, i.nombre as institucion_nombre, i.tipo, i.plan, i.direccion, i.telefono,
                    i.stock_modelo, i.shared_mode, i.trial_started_at
             FROM usuarios_b2b u JOIN instituciones_b2b i ON u.institucion_id = i.id
             WHERE u.id = $1`,
            [req.b2bUser.id]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('GET /api/b2b/auth/me:', err.message);
        res.status(500).json({ error: 'Error al obtener perfil' });
    }
});

// PATCH /api/b2b/auth/me
app.patch('/api/b2b/auth/me', authB2BMiddleware, async (req, res) => {
    try {
        const { nombre, email, password, password_actual, password_nueva } = req.body;
        if (nombre) await pool.query('UPDATE usuarios_b2b SET nombre=$1 WHERE id=$2', [nombre, req.b2bUser.id]);
        if (email) {
            const exists = await pool.query('SELECT id FROM usuarios_b2b WHERE email=$1 AND id!=$2', [email.toLowerCase(), req.b2bUser.id]);
            if (exists.rowCount > 0) return res.status(409).json({ error: 'El email ya está en uso' });
            await pool.query('UPDATE usuarios_b2b SET email=$1 WHERE id=$2', [email.toLowerCase(), req.b2bUser.id]);
        }
        // Support both: direct password (legacy) and password_actual + password_nueva (secure)
        if (password_nueva && password_actual) {
            const userRow = await pool.query('SELECT password_hash FROM usuarios_b2b WHERE id=$1', [req.b2bUser.id]);
            const valid = await bcrypt.compare(password_actual, userRow.rows[0].password_hash);
            if (!valid) return res.status(400).json({ error: 'La contraseña actual es incorrecta' });
            const hash = await bcrypt.hash(password_nueva, SALT_ROUNDS);
            await pool.query('UPDATE usuarios_b2b SET password_hash=$1 WHERE id=$2', [hash, req.b2bUser.id]);
        } else if (password) {
            const hash = await bcrypt.hash(password, SALT_ROUNDS);
            await pool.query('UPDATE usuarios_b2b SET password_hash=$1 WHERE id=$2', [hash, req.b2bUser.id]);
        }
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /api/b2b/auth/me:', err.message);
        res.status(500).json({ error: 'Error al actualizar perfil' });
    }
});

// GET /api/b2b/me/notif-prefs — Obtener preferencias de alertas del dashboard
app.get('/api/b2b/me/notif-prefs', authB2BMiddleware, async (req, res) => {
    try {
        const r = await pool.query('SELECT notif_prefs FROM usuarios_b2b WHERE id=$1', [req.b2bUser.id]);
        res.json(r.rows[0]?.notif_prefs || {});
    } catch (err) {
        console.error('GET /api/b2b/me/notif-prefs:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// PATCH /api/b2b/me/notif-prefs — Guardar preferencias de alertas del dashboard
app.patch('/api/b2b/me/notif-prefs', authB2BMiddleware, async (req, res) => {
    try {
        const prefs = req.body;
        if (typeof prefs !== 'object' || Array.isArray(prefs))
            return res.status(400).json({ error: 'Formato de preferencias inválido' });
        await pool.query('UPDATE usuarios_b2b SET notif_prefs=$1 WHERE id=$2', [JSON.stringify(prefs), req.b2bUser.id]);
        res.json({ ok: true });
    } catch (err) {
        console.error('PATCH /api/b2b/me/notif-prefs:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/b2b/auth/forgot-password
app.post('/api/b2b/auth/forgot-password', authRateLimit, async (req, res) => {
    try {
        const { email } = req.body;
        const user = await pool.query('SELECT * FROM usuarios_b2b WHERE email=$1', [email.toLowerCase()]);
        if (user.rowCount === 0) return res.json({ success: true }); // no revelar si existe
        const token = require('crypto').randomBytes(32).toString('hex');
        const expiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hora
        await pool.query('UPDATE usuarios_b2b SET reset_token=$1, reset_token_expiry=$2 WHERE id=$3', [token, expiry, user.rows[0].id]);
        const resetUrl = `https://cuidadiario-pro.edensoftwork.com/reset-password.html?token=${token}&b2b=1`;
        // Envío de email via Resend (mismo sistema que B2C)
        if (process.env.RESEND_API_KEY) {
            await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({ from: process.env.EMAIL_FROM || 'CuidaDiario PRO <noreply@cuidadiario.com>', to: email, subject: 'Recuperar contraseña — CuidaDiario PRO', html: `<p>Hacé clic para restablecer tu contraseña:</p><a href="${resetUrl}">${resetUrl}</a><p>El link vence en 1 hora.</p>` })
            });
        }
        res.json({ success: true });
    } catch (err) {
        console.error('POST /api/b2b/auth/forgot-password:', err.message);
        res.status(500).json({ error: 'Error al enviar email' });
    }
});

// POST /api/b2b/auth/reset-password
app.post('/api/b2b/auth/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;
        const user = await pool.query('SELECT * FROM usuarios_b2b WHERE reset_token=$1 AND reset_token_expiry > NOW()', [token]);
        if (user.rowCount === 0) return res.status(400).json({ error: 'Token inválido o expirado' });
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        await pool.query('UPDATE usuarios_b2b SET password_hash=$1, reset_token=NULL, reset_token_expiry=NULL WHERE id=$2', [hash, user.rows[0].id]);
        res.json({ success: true });
    } catch (err) {
        console.error('POST /api/b2b/auth/reset-password:', err.message);
        res.status(500).json({ error: 'Error al restablecer contraseña' });
    }
});

// GET /api/b2b/auth/verify-email?token=XXX — activa la cuenta tras hacer clic en el link del email
app.get('/api/b2b/auth/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) return res.status(400).json({ error: 'Token de verificación requerido' });

        const result = await pool.query(
            'SELECT id, email, nombre FROM usuarios_b2b WHERE email_verification_token=$1 AND email_verification_expiry > NOW()',
            [token]
        );
        if (result.rowCount === 0)
            return res.status(400).json({ error: 'El link de verificación es inválido o ya expiró. Solícita uno nuevo desde la aplicación.' });

        await pool.query(
            'UPDATE usuarios_b2b SET email_verified=TRUE, email_verification_token=NULL, email_verification_expiry=NULL WHERE id=$1',
            [result.rows[0].id]
        );
        console.log(`[B2B] Email verificado: ${result.rows[0].email} (id=${result.rows[0].id})`);
        res.json({ success: true, message: 'Email confirmado correctamente. Ya podés usar todas las funciones de CuidaDiario PRO.' });
    } catch (err) {
        console.error('GET /api/b2b/auth/verify-email:', err.message);
        res.status(500).json({ error: 'Error al verificar email' });
    }
});

// POST /api/b2b/auth/resend-verification — reenvía el email de verificación
app.post('/api/b2b/auth/resend-verification', authB2BMiddleware, async (req, res) => {
    try {
        const userRow = await pool.query(
            'SELECT id, nombre, email, email_verified FROM usuarios_b2b WHERE id=$1',
            [req.b2bUser.id]
        );
        if (userRow.rowCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        const user = userRow.rows[0];

        if (user.email_verified)
            return res.json({ success: true, already_verified: true, message: 'Tu email ya está verificado.' });

        const isTestEmail = /^test\d*@test\d*$/i.test(user.email);
        if (isTestEmail) {
            await pool.query('UPDATE usuarios_b2b SET email_verified=TRUE WHERE id=$1', [user.id]);
            return res.json({ success: true, message: 'Email de prueba verificado automáticamente.' });
        }

        const newToken = require('crypto').randomBytes(32).toString('hex');
        const newExpiry = new Date(Date.now() + 72 * 60 * 60 * 1000);
        await pool.query(
            'UPDATE usuarios_b2b SET email_verification_token=$1, email_verification_expiry=$2 WHERE id=$3',
            [newToken, newExpiry, user.id]
        );

        if (process.env.RESEND_API_KEY) {
            const verifyUrl = `${FRONTEND_URL_PRO}/verify-email.html?token=${newToken}&b2b=1`;
            await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    from: process.env.EMAIL_FROM || 'CuidaDiario PRO <noreply@cuidadiario.com>',
                    to: user.email,
                    subject: 'Confirmá tu cuenta — CuidaDiario PRO',
                    html: `
                        <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;padding:28px;border:1px solid #e0e0e0;border-radius:10px">
                            <h2 style="color:#4F46E5">CuidaDiario <strong>PRO</strong></h2>
                            <p>Hola <strong>${user.nombre}</strong>, re-envíamos tu link de confirmación de cuenta:</p>
                            <div style="text-align:center;margin:28px 0">
                                <a href="${verifyUrl}" style="background:#4F46E5;color:#fff;padding:14px 32px;border-radius:8px;text-decoration:none;font-weight:700;font-size:1rem;display:inline-block">
                                    Confirmar mi cuenta
                                </a>
                            </div>
                            <p style="color:#9CA3AF;font-size:.82rem">Este enlace vence en <strong>72 horas</strong>.</p>
                            <p style="color:#D1D5DB;font-size:.75rem">CuidaDiario PRO — EDEN SoftWork</p>
                        </div>
                    `
                })
            }).catch(e => console.warn('[B2B] Resend error:', e.message));
        }
        res.json({ success: true, message: `Email de verificación reenviado a ${user.email}.` });
    } catch (err) {
        console.error('POST /api/b2b/auth/resend-verification:', err.message);
        res.status(500).json({ error: 'Error al reenviar verificación' });
    }
});

// ---------- B2B: INSTITUCIÓN ----------

// GET /api/b2b/institucion
app.get('/api/b2b/institucion', authB2BMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT i.*,
                (SELECT COUNT(*) FROM pacientes_b2b WHERE institucion_id=i.id AND activo=TRUE AND fecha_egreso IS NULL) AS pacientes_count,
                (SELECT COUNT(*) FROM usuarios_b2b WHERE institucion_id=i.id AND activo=TRUE) AS staff_count
             FROM instituciones_b2b i WHERE i.id=$1`,
            [req.b2bUser.institucion_id]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Institución no encontrada' });
        const inst = result.rows[0];
        inst.pacientes_count = parseInt(inst.pacientes_count) || 0;
        inst.staff_count = parseInt(inst.staff_count) || 0;
        res.json(inst);
    } catch (err) {
        console.error('GET /api/b2b/institucion:', err.message);
        res.status(500).json({ error: 'Error al obtener institución' });
    }
});

// PATCH /api/b2b/institucion
app.patch('/api/b2b/institucion', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        const { nombre, tipo, direccion, telefono, email, stock_modelo, permisos_equipo, onboarding_done, shared_mode } = req.body;
        await pool.query(
            `UPDATE instituciones_b2b SET nombre=COALESCE($1,nombre), tipo=COALESCE($2,tipo),
             direccion=COALESCE($3,direccion), telefono=COALESCE($4,telefono), email=COALESCE($5,email),
             stock_modelo=COALESCE($6,stock_modelo),
             permisos_equipo=COALESCE($7::jsonb,permisos_equipo),
             onboarding_done=COALESCE($9,onboarding_done),
             shared_mode=COALESCE($10,shared_mode) WHERE id=$8`,
            [nombre, tipo, direccion, telefono, email, stock_modelo,
             permisos_equipo ? JSON.stringify(permisos_equipo) : null,
             req.b2bUser.institucion_id,
             onboarding_done !== undefined ? onboarding_done : null,
             shared_mode !== undefined ? shared_mode : null]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /api/b2b/institucion:', err.message);
        res.status(500).json({ error: 'Error al actualizar institución' });
    }
});

// ---------- B2B: STAFF ----------

// GET /api/b2b/staff
app.get('/api/b2b/staff', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, nombre, email, rol, activo, created_at FROM usuarios_b2b WHERE institucion_id=$1 ORDER BY nombre',
            [req.b2bUser.institucion_id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('GET /api/b2b/staff:', err.message);
        res.status(500).json({ error: 'Error al obtener staff' });
    }
});

// POST /api/b2b/staff — crear miembro del staff
app.post('/api/b2b/staff', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        const { nombre, email, password, rol } = req.body;
        if (!nombre || !email || !password) return res.status(400).json({ error: 'Faltan datos obligatorios' });
        const exists = await pool.query('SELECT id FROM usuarios_b2b WHERE email=$1', [email.toLowerCase()]);
        if (exists.rowCount > 0) return res.status(409).json({ error: 'El email ya está registrado' });
        // Verificar límite de plan y expiración del trial
        const planCheck = await checkInstPlanForAction(req.b2bUser.institucion_id, 'crear_staff');
        if (!planCheck.allowed) return res.status(planCheck.code === 'TRIAL_EXPIRED' ? 402 : 403).json({ error: planCheck.error, code: planCheck.code });
        const hash = await bcrypt.hash(password, SALT_ROUNDS);
        const validRoles = ['cuidador_staff', 'familiar', 'medico', 'admin_institucion'];
        const userRol = validRoles.includes(rol) ? rol : 'cuidador_staff';
        // email_verified=TRUE: el admin confía en el email que ingresó, no se envía verificación
        const result = await pool.query(
            `INSERT INTO usuarios_b2b (institucion_id, nombre, email, password_hash, rol, email_verified) VALUES ($1,$2,$3,$4,$5,TRUE) RETURNING id, nombre, email, rol`,
            [req.b2bUser.institucion_id, nombre, email.toLowerCase(), hash, userRol]
        );
        // Enviar email de bienvenida al nuevo miembro del staff
        try {
            const instRes2 = await pool.query('SELECT nombre FROM instituciones_b2b WHERE id=$1', [req.b2bUser.institucion_id]);
            const instNombre = instRes2.rows[0]?.nombre || 'tu institución';
            const rolLabels = { admin_institucion: 'Administrador', cuidador_staff: 'Personal / Operativo', familiar: 'Familiar (solo lectura)', medico: 'Médico / Profesional' };
            const rolLabel = rolLabels[userRol] || userRol;
            const loginUrl = `${FRONTEND_URL_PRO}/index.html`;
            await sendEmail({
                to: email.toLowerCase(),
                subject: `¡Bienvenido/a a CuidaDiario PRO! Tu cuenta está lista`,
                html: `
                    <div style="font-family:'Segoe UI',Arial,sans-serif;max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;border:1px solid #E5E7EB">
                        <div style="background:linear-gradient(135deg,#0D2B6B,#1565C0);padding:28px 32px;text-align:center">
                            <div style="font-size:2.5rem;margin-bottom:8px">🏥</div>
                            <div style="color:#fff;font-size:1.3rem;font-weight:800">CuidaDiario PRO</div>
                        </div>
                        <div style="padding:28px 32px">
                            <h2 style="font-size:1.2rem;color:#1F2937;margin-bottom:12px">¡Hola ${nombre}!</h2>
                            <p style="color:#374151;line-height:1.6;margin-bottom:16px">
                                El administrador de <strong>${instNombre}</strong> creó tu cuenta en <strong>CuidaDiario PRO</strong>.
                                Ya podés iniciar sesión con tus credenciales.
                            </p>
                            <div style="background:#F0F4FF;border-radius:10px;padding:16px 20px;margin-bottom:20px">
                                <div style="font-size:.85rem;color:#4B5563;margin-bottom:6px;font-weight:600">Tus datos de acceso:</div>
                                <div style="color:#1E40AF;margin-bottom:4px">📧 <strong>Email:</strong> ${email.toLowerCase()}</div>
                                <div style="color:#1E40AF;margin-bottom:4px">🔑 <strong>Contraseña:</strong> la que te compartió el administrador</div>
                                <div style="color:#1E40AF">👤 <strong>Rol:</strong> ${rolLabel}</div>
                            </div>
                            <a href="${loginUrl}" style="display:block;background:#1565C0;color:#fff;text-decoration:none;text-align:center;padding:14px 24px;border-radius:8px;font-weight:700;font-size:1rem;margin-bottom:20px">
                                Iniciar sesión →
                            </a>
                            <p style="font-size:.82rem;color:#9CA3AF">
                                Si no esperabas este mensaje, ignoralo sin problema.<br>
                                ¿Necesitás ayuda? <a href="mailto:edensoftwarework@gmail.com" style="color:#1565C0">edensoftwarework@gmail.com</a>
                            </p>
                        </div>
                    </div>`
            });
        } catch (emailErr) {
            console.warn('POST /api/b2b/staff — email de bienvenida no enviado:', emailErr.message);
        }
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/staff:', err.message);
        res.status(500).json({ error: 'Error al crear miembro del staff' });
    }
});

// PATCH /api/b2b/staff/:id
app.patch('/api/b2b/staff/:id', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre, email, rol, activo, password } = req.body;
        const check = await pool.query('SELECT id FROM usuarios_b2b WHERE id=$1 AND institucion_id=$2', [id, req.b2bUser.institucion_id]);
        if (check.rowCount === 0) return res.status(404).json({ error: 'Staff no encontrado' });
        if (nombre) await pool.query('UPDATE usuarios_b2b SET nombre=$1 WHERE id=$2', [nombre, id]);
        if (email) {
            const emailLower = email.toLowerCase().trim();
            const conflict = await pool.query('SELECT id FROM usuarios_b2b WHERE email=$1 AND id<>$2', [emailLower, id]);
            if (conflict.rowCount > 0) return res.status(409).json({ error: 'El email ya está en uso por otro usuario' });
            await pool.query('UPDATE usuarios_b2b SET email=$1 WHERE id=$2', [emailLower, id]);
        }
        if (rol) await pool.query('UPDATE usuarios_b2b SET rol=$1 WHERE id=$2', [rol, id]);
        if (activo !== undefined) await pool.query('UPDATE usuarios_b2b SET activo=$1 WHERE id=$2', [activo, id]);
        if (password) { const h = await bcrypt.hash(password, SALT_ROUNDS); await pool.query('UPDATE usuarios_b2b SET password_hash=$1 WHERE id=$2', [h, id]); }
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /api/b2b/staff/:id:', err.message);
        res.status(500).json({ error: 'Error al actualizar staff' });
    }
});

// DELETE /api/b2b/staff/:id — desactivar (no borrar)
app.delete('/api/b2b/staff/:id', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        const { id } = req.params;
        if (parseInt(id) === req.b2bUser.id) return res.status(400).json({ error: 'No podés desactivar tu propio usuario' });
        const result = await pool.query('UPDATE usuarios_b2b SET activo=FALSE WHERE id=$1 AND institucion_id=$2 RETURNING id', [id, req.b2bUser.institucion_id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Staff no encontrado' });
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/staff/:id:', err.message);
        res.status(500).json({ error: 'Error al desactivar staff' });
    }
});

// ---------- B2B: PACIENTES ----------

// GET /api/b2b/pacientes
app.get('/api/b2b/pacientes', authB2BMiddleware, async (req, res) => {
    try {
        let query, params;
        if (req.b2bUser.rol === 'admin_institucion' || req.b2bUser.rol === 'medico') {
            query = 'SELECT * FROM pacientes_b2b WHERE institucion_id=$1 AND activo=TRUE ORDER BY apellido, nombre';
            params = [req.b2bUser.institucion_id];
        } else {
            query = `SELECT p.* FROM pacientes_b2b p JOIN asignaciones_b2b a ON a.paciente_id = p.id
                     WHERE a.cuidador_id=$1 AND a.activa=TRUE AND p.activo=TRUE ORDER BY p.apellido, p.nombre`;
            params = [req.b2bUser.id];
        }
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('GET /api/b2b/pacientes:', err.message);
        res.status(500).json({ error: 'Error al obtener pacientes' });
    }
});

// GET /api/b2b/pacientes/:id — single patient (used by paciente.html)
app.get('/api/b2b/pacientes/:id', authB2BMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        let result;
        if (req.b2bUser.rol === 'admin_institucion' || req.b2bUser.rol === 'medico') {
            result = await pool.query(
                'SELECT * FROM pacientes_b2b WHERE id=$1 AND institucion_id=$2 AND activo=TRUE',
                [id, req.b2bUser.institucion_id]
            );
        } else {
            result = await pool.query(
                `SELECT p.* FROM pacientes_b2b p JOIN asignaciones_b2b a ON a.paciente_id = p.id
                 WHERE p.id=$1 AND a.cuidador_id=$2 AND a.activa=TRUE AND p.activo=TRUE`,
                [id, req.b2bUser.id]
            );
        }
        if (result.rowCount === 0) return res.status(404).json({ error: 'Paciente no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('GET /api/b2b/pacientes/:id:', err.message);
        res.status(500).json({ error: 'Error al obtener paciente' });
    }
});

// POST /api/b2b/pacientes
app.post('/api/b2b/pacientes', authB2BMiddleware, async (req, res) => {
    try {
        if (!await checkB2BCanDo(req.b2bUser, 'crear_paciente'))
            return res.status(403).json({ error: 'No tenés permisos para crear pacientes' });
        // Verificar límite de plan y expiración del trial
        const planCheck = await checkInstPlanForAction(req.b2bUser.institucion_id, 'crear_paciente');
        if (!planCheck.allowed) return res.status(planCheck.code === 'TRIAL_EXPIRED' ? 402 : 403).json({ error: planCheck.error, code: planCheck.code });
        const { nombre, apellido, fecha_nacimiento, dni, habitacion, diagnostico, obra_social, num_afiliado, contacto_familiar_nombre, contacto_familiar_tel, notas_ingreso, fecha_ingreso, alergias, medico_cabecera, antecedentes } = req.body;
        if (!nombre) return res.status(400).json({ error: 'El nombre es obligatorio' });
        const result = await pool.query(
            `INSERT INTO pacientes_b2b (institucion_id, nombre, apellido, fecha_nacimiento, dni, habitacion, diagnostico, obra_social, num_afiliado, contacto_familiar_nombre, contacto_familiar_tel, notas_ingreso, fecha_ingreso, alergias, medico_cabecera, antecedentes)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING *`,
            [req.b2bUser.institucion_id, nombre, apellido, fecha_nacimiento||null, dni, habitacion, diagnostico, obra_social, num_afiliado, contacto_familiar_nombre, contacto_familiar_tel, notas_ingreso, fecha_ingreso||null, alergias||null, medico_cabecera||null, antecedentes||null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/pacientes:', err.message);
        res.status(500).json({ error: 'Error al crear paciente' });
    }
});

// PATCH /api/b2b/pacientes/:id
app.patch('/api/b2b/pacientes/:id', authB2BMiddleware, async (req, res) => {
    try {
        const { id } = req.params;
        // dar_alta requires specific permission; general edits use editar_paciente
        const isEgreso = req.body.fecha_egreso !== undefined || req.body.motivo_egreso !== undefined;
        const action = isEgreso ? 'dar_alta' : 'editar_paciente';
        if (!await checkB2BCanDo(req.b2bUser, action))
            return res.status(403).json({ error: 'No tenés permisos para esta acción' });
        const fields = ['nombre','apellido','fecha_nacimiento','dni','habitacion','diagnostico','obra_social','num_afiliado','contacto_familiar_nombre','contacto_familiar_tel','notas_ingreso','fecha_ingreso','foto_url','alergias','medico_cabecera','antecedentes','fecha_egreso','motivo_egreso'];
        const updates = []; const values = []; let i = 1;
        for (const f of fields) { if (req.body[f] !== undefined) { updates.push(`${f}=$${i++}`); values.push(req.body[f]); } }
        if (updates.length === 0) return res.status(400).json({ error: 'Nada que actualizar' });
        values.push(id, req.b2bUser.institucion_id);
        await pool.query(`UPDATE pacientes_b2b SET ${updates.join(',')} WHERE id=$${i++} AND institucion_id=$${i}`, values);
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /api/b2b/pacientes/:id:', err.message);
        res.status(500).json({ error: 'Error al actualizar paciente' });
    }
});

// DELETE /api/b2b/pacientes/:id — soft delete
app.delete('/api/b2b/pacientes/:id', authB2BMiddleware, async (req, res) => {
    try {
        if (!await checkB2BCanDo(req.b2bUser, 'eliminar_paciente'))
            return res.status(403).json({ error: 'No tenés permisos para eliminar pacientes' });
        const { id } = req.params;
        const result = await pool.query('UPDATE pacientes_b2b SET activo=FALSE WHERE id=$1 AND institucion_id=$2 RETURNING id', [id, req.b2bUser.institucion_id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Paciente no encontrado' });
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/pacientes/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar paciente' });
    }
});

// ---------- B2B: ASIGNACIONES ----------

// GET /api/b2b/asignaciones
app.get('/api/b2b/asignaciones', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT a.*, u.nombre as cuidador_nombre, u.rol as cuidador_rol,
                    p.nombre as paciente_nombre, p.apellido as paciente_apellido, p.habitacion
             FROM asignaciones_b2b a JOIN usuarios_b2b u ON a.cuidador_id=u.id JOIN pacientes_b2b p ON a.paciente_id=p.id
             WHERE a.institucion_id=$1 AND a.activa=TRUE ORDER BY p.apellido, p.nombre`,
            [req.b2bUser.institucion_id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('GET /api/b2b/asignaciones:', err.message);
        res.status(500).json({ error: 'Error al obtener asignaciones' });
    }
});

// POST /api/b2b/asignaciones
app.post('/api/b2b/asignaciones', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        const { cuidador_id, paciente_id } = req.body;
        if (!cuidador_id || !paciente_id) return res.status(400).json({ error: 'cuidador_id y paciente_id requeridos' });
        const [uc, up] = await Promise.all([
            pool.query('SELECT id FROM usuarios_b2b WHERE id=$1 AND institucion_id=$2', [cuidador_id, req.b2bUser.institucion_id]),
            pool.query('SELECT id FROM pacientes_b2b WHERE id=$1 AND institucion_id=$2', [paciente_id, req.b2bUser.institucion_id])
        ]);
        if (uc.rowCount === 0) return res.status(400).json({ error: 'Cuidador no pertenece a la institución' });
        if (up.rowCount === 0) return res.status(400).json({ error: 'Paciente no pertenece a la institución' });
        const result = await pool.query(
            `INSERT INTO asignaciones_b2b (institucion_id, cuidador_id, paciente_id)
             VALUES ($1,$2,$3) ON CONFLICT (cuidador_id, paciente_id) DO UPDATE SET activa=TRUE RETURNING *`,
            [req.b2bUser.institucion_id, cuidador_id, paciente_id]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/asignaciones:', err.message);
        res.status(500).json({ error: 'Error al crear asignación' });
    }
});

// DELETE /api/b2b/asignaciones/:id
app.delete('/api/b2b/asignaciones/:id', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        await pool.query('UPDATE asignaciones_b2b SET activa=FALSE WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/asignaciones/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar asignación' });
    }
});

// ---------- B2B: MEDICAMENTOS ----------

// GET /api/b2b/medicamentos/historial  (debe ir ANTES de /:id)
app.get('/api/b2b/medicamentos/historial', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = 'SELECT * FROM historial_medicamentos_b2b WHERE institucion_id=$1';
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND paciente_id=$2`; params.push(paciente_id); }
        query += ' ORDER BY fecha DESC LIMIT 100';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/medicamentos/historial:', err.message);
        res.status(500).json({ error: 'Error al obtener historial' });
    }
});

// GET /api/b2b/medicamentos
app.get('/api/b2b/medicamentos', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = `SELECT m.*,
                     c.nombre AS catalogo_nombre, c.stock_actual AS catalogo_stock,
                     c.stock_minimo AS catalogo_stock_minimo, c.unidad AS catalogo_unidad
                     FROM medicamentos_b2b m
                     LEFT JOIN catalogo_medicamentos_b2b c ON m.catalogo_id = c.id
                     WHERE m.institucion_id=$1 AND m.activo=TRUE`;
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND m.paciente_id=$2`; params.push(paciente_id); }
        query += ' ORDER BY m.nombre';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/medicamentos:', err.message);
        res.status(500).json({ error: 'Error al obtener medicamentos' });
    }
});

// POST /api/b2b/medicamentos
app.post('/api/b2b/medicamentos', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), requireActivePlan, async (req, res) => {
    try {
        const { paciente_id, nombre, dosis, frecuencia, hora_inicio, hora_fin, horarios_custom, instrucciones, stock, catalogo_id } = req.body;
        if (!paciente_id || !nombre) return res.status(400).json({ error: 'paciente_id y nombre obligatorios' });
        if (!(await checkB2BPacienteAccess(req.b2bUser, paciente_id))) return res.status(403).json({ error: 'Sin acceso a este paciente' });
        const result = await pool.query(
            `INSERT INTO medicamentos_b2b (institucion_id, paciente_id, nombre, dosis, frecuencia, hora_inicio, hora_fin, horarios_custom, instrucciones, stock, catalogo_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
            [req.b2bUser.institucion_id, paciente_id, nombre, dosis, frecuencia, hora_inicio||null, hora_fin||null, horarios_custom, instrucciones, stock||null, catalogo_id||null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/medicamentos:', err.message);
        res.status(500).json({ error: 'Error al crear medicamento' });
    }
});

// POST /api/b2b/medicamentos/:id/toma
app.post('/api/b2b/medicamentos/:id/toma', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), requireActivePlan, async (req, res) => {
    try {
        const med = await pool.query('SELECT * FROM medicamentos_b2b WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        if (med.rowCount === 0) return res.status(404).json({ error: 'Medicamento no encontrado' });
        const m = med.rows[0];

        // STOCK GUARD: block toma if there is no stock remaining
        // Hybrid model: if linked to a catalog item, check catalog stock regardless of stock_modelo field
        if (m.catalogo_id) {
            const catRow = await pool.query(
                'SELECT stock_actual FROM catalogo_medicamentos_b2b WHERE id=$1 AND institucion_id=$2',
                [m.catalogo_id, req.b2bUser.institucion_id]
            );
            const catStock = catRow.rows[0]?.stock_actual ?? 0;
            if (catStock <= 0) {
                return res.status(400).json({ error: 'Sin stock disponible en el cat\u00e1logo. Repon\u00e9 el insumo antes de registrar una toma.', code: 'STOCK_ZERO' });
            }
        } else if (m.stock !== null && m.stock <= 0) {
            return res.status(400).json({ error: 'Sin stock disponible. Actualiz\u00e1 el stock antes de registrar una toma.', code: 'STOCK_ZERO' });
        }

        // Register the toma in history.
        // Use NOW() AT TIME ZONE 'America/Argentina/Buenos_Aires' so the stored naive
        // TIMESTAMP reflects local Argentine time and displays correctly on the frontend.
        const _adminNombre = (req.body._quien && typeof req.body._quien === 'string' && req.body._quien.trim()) ? req.body._quien.trim() : req.b2bUser.nombre;
        const result = await pool.query(
            `INSERT INTO historial_medicamentos_b2b
             (institucion_id, paciente_id, medicamento_id, medicamento_nombre, dosis, administrado_por, administrador_nombre, notas, fecha)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8, NOW() AT TIME ZONE 'America/Argentina/Buenos_Aires') RETURNING *`,
            [req.b2bUser.institucion_id, m.paciente_id, m.id, m.nombre, m.dosis, req.b2bUser.id, _adminNombre, req.body.notas||null]
        );
        // Auto-decrement stock — hybrid model: catalog wins when linked, else per-patient/individual stock
        if (m.catalogo_id) {
            // Decrement catalog stock (institutional or patient-specific), never below 0
            await pool.query(
                'UPDATE catalogo_medicamentos_b2b SET stock_actual = GREATEST(0, stock_actual - 1), updated_at = NOW() WHERE id=$1 AND institucion_id=$2',
                [m.catalogo_id, req.b2bUser.institucion_id]
            );
        } else if (m.stock !== null && m.stock > 0) {
            // Decrement individual/manual stock (non-cataloged)
            await pool.query(
                'UPDATE medicamentos_b2b SET stock = GREATEST(0, stock - 1) WHERE id=$1 AND institucion_id=$2',
                [m.id, req.b2bUser.institucion_id]
            );
        }
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/medicamentos/:id/toma:', err.message);
        res.status(500).json({ error: 'Error al registrar toma' });
    }
});

// PATCH /api/b2b/medicamentos/:id
app.patch('/api/b2b/medicamentos/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        const { nombre, dosis, frecuencia, hora_inicio, hora_fin, horarios_custom, instrucciones, stock, activo, catalogo_id } = req.body;
        // catalogo_id can be explicitly set to null (unlink) or a number (link), hence no COALESCE
        const hasCatalogoId = Object.prototype.hasOwnProperty.call(req.body, 'catalogo_id');
        await pool.query(
            `UPDATE medicamentos_b2b SET nombre=COALESCE($1,nombre), dosis=COALESCE($2,dosis), frecuencia=COALESCE($3,frecuencia),
             hora_inicio=COALESCE($4,hora_inicio), hora_fin=COALESCE($5,hora_fin), horarios_custom=COALESCE($6,horarios_custom),
             instrucciones=COALESCE($7,instrucciones), stock=COALESCE($8,stock), activo=COALESCE($9,activo),
             catalogo_id = CASE WHEN $10 THEN $11::integer ELSE catalogo_id END
             WHERE id=$12 AND institucion_id=$13`,
            [nombre, dosis, frecuencia, hora_inicio, hora_fin, horarios_custom, instrucciones, stock, activo,
             hasCatalogoId, hasCatalogoId ? catalogo_id : null, req.params.id, req.b2bUser.institucion_id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /api/b2b/medicamentos/:id:', err.message);
        res.status(500).json({ error: 'Error al actualizar medicamento' });
    }
});

// DELETE /api/b2b/medicamentos/:id
app.delete('/api/b2b/medicamentos/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        await pool.query('UPDATE medicamentos_b2b SET activo=FALSE WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/medicamentos/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar medicamento' });
    }
});

// ---------- B2B: CATÁLOGO DE MEDICAMENTOS ----------

// GET /api/b2b/catalogo/stock-bajo  (must come BEFORE /:id)
app.get('/api/b2b/catalogo/stock-bajo', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, p.nombre AS paciente_nombre, p.apellido AS paciente_apellido
             FROM catalogo_medicamentos_b2b c
             LEFT JOIN pacientes_b2b p ON c.paciente_id = p.id
             WHERE c.institucion_id=$1 AND c.activo=TRUE AND c.stock_actual <= c.stock_minimo
             ORDER BY c.stock_actual ASC`,
            [req.b2bUser.institucion_id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('GET /api/b2b/catalogo/stock-bajo:', err.message);
        res.status(500).json({ error: 'Error' });
    }
});

// GET /api/b2b/catalogo
// ?paciente_id=X → insumos específicos del paciente X
// sin parámetro   → insumos institucionales (paciente_id IS NULL)
app.get('/api/b2b/catalogo', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query, params;
        if (paciente_id) {
            query = `SELECT c.*, p.nombre AS paciente_nombre, p.apellido AS paciente_apellido
                     FROM catalogo_medicamentos_b2b c
                     LEFT JOIN pacientes_b2b p ON c.paciente_id = p.id
                     WHERE c.institucion_id=$1 AND c.activo=TRUE AND c.paciente_id=$2
                     ORDER BY c.nombre`;
            params = [req.b2bUser.institucion_id, paciente_id];
        } else {
            query = `SELECT c.*, NULL::TEXT AS paciente_nombre, NULL::TEXT AS paciente_apellido
                     FROM catalogo_medicamentos_b2b c
                     WHERE c.institucion_id=$1 AND c.activo=TRUE AND c.paciente_id IS NULL
                     ORDER BY c.nombre`;
            params = [req.b2bUser.institucion_id];
        }
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/catalogo:', err.message);
        res.status(500).json({ error: 'Error al obtener catálogo' });
    }
});

// POST /api/b2b/catalogo
app.post('/api/b2b/catalogo', authB2BMiddleware, requireB2BRole('admin_institucion'), requireActivePlan, async (req, res) => {
    try {
        const { nombre, principio_activo, presentacion, unidad, stock_actual, stock_minimo, paciente_id } = req.body;
        if (!nombre) return res.status(400).json({ error: 'nombre obligatorio' });
        // Si se especifica paciente_id, validar que pertenece a la institución
        if (paciente_id) {
            const pCheck = await pool.query('SELECT id FROM pacientes_b2b WHERE id=$1 AND institucion_id=$2', [paciente_id, req.b2bUser.institucion_id]);
            if (pCheck.rowCount === 0) return res.status(403).json({ error: 'Paciente no pertenece a la institución' });
        }
        const result = await pool.query(
            `INSERT INTO catalogo_medicamentos_b2b (institucion_id, nombre, principio_activo, presentacion, unidad, stock_actual, stock_minimo, paciente_id)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
            [req.b2bUser.institucion_id, nombre, principio_activo||null, presentacion||null, unidad||'comprimido', stock_actual||0, stock_minimo||5, paciente_id||null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/catalogo:', err.message);
        res.status(500).json({ error: 'Error al agregar al catálogo' });
    }
});

// PATCH /api/b2b/catalogo/:id
app.patch('/api/b2b/catalogo/:id', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        const { nombre, principio_activo, presentacion, unidad, stock_actual, stock_minimo, notas_restock } = req.body;
        const iid = req.b2bUser.institucion_id;
        // Fetch current state to detect stock changes for restock log
        const curRes = await pool.query('SELECT * FROM catalogo_medicamentos_b2b WHERE id=$1 AND institucion_id=$2', [req.params.id, iid]);
        if (curRes.rowCount === 0) return res.status(404).json({ error: 'Ítem no encontrado' });
        const cur = curRes.rows[0];
        const result = await pool.query(
            `UPDATE catalogo_medicamentos_b2b
             SET nombre=COALESCE($1,nombre), principio_activo=COALESCE($2,principio_activo),
                 presentacion=COALESCE($3,presentacion), unidad=COALESCE($4,unidad),
                 stock_actual=COALESCE($5,stock_actual), stock_minimo=COALESCE($6,stock_minimo),
                 updated_at=NOW()
             WHERE id=$7 AND institucion_id=$8 RETURNING *`,
            [nombre, principio_activo, presentacion, unidad, stock_actual, stock_minimo, req.params.id, iid]
        );
        // Log restock entry if stock_actual was increased
        if (stock_actual !== undefined && stock_actual !== null) {
            const prev = parseInt(cur.stock_actual) || 0;
            const nuevo = parseInt(stock_actual);
            if (!isNaN(nuevo) && nuevo > prev) {
                await pool.query(
                    `INSERT INTO historial_restock_b2b
                     (institucion_id, catalogo_id, paciente_id, nombre_item, stock_anterior, cantidad_repuesta, stock_nuevo, notas, registrado_por, registrado_nombre)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
                    [iid, cur.id, cur.paciente_id || null, cur.nombre, prev, nuevo - prev, nuevo,
                     notas_restock || null, req.b2bUser.id, req.b2bUser.nombre || null]
                ).catch(e => console.error('restock log insert:', e.message));
            }
        }
        res.json(result.rows[0]);
    } catch (err) {
        console.error('PATCH /api/b2b/catalogo/:id:', err.message);
        res.status(500).json({ error: 'Error al actualizar ítem del catálogo' });
    }
});

// GET /api/b2b/catalogo/restock-historial
// ?catalogo_id=X → historial de un ítem específico
// ?paciente_id=X → historial de todos los ítems de un paciente
app.get('/api/b2b/catalogo/restock-historial', authB2BMiddleware, async (req, res) => {
    try {
        const { catalogo_id, paciente_id } = req.query;
        const iid = req.b2bUser.institucion_id;
        let query = `SELECT h.*, COALESCE(h.registrado_nombre, u.nombre, 'Sistema') AS registrador
                     FROM historial_restock_b2b h
                     LEFT JOIN usuarios_b2b u ON h.registrado_por = u.id
                     WHERE h.institucion_id=$1`;
        const params = [iid];
        if (catalogo_id) { query += ` AND h.catalogo_id=$${params.length + 1}`; params.push(catalogo_id); }
        if (paciente_id) { query += ` AND h.paciente_id=$${params.length + 1}`; params.push(paciente_id); }
        query += ' ORDER BY h.created_at DESC LIMIT 50';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/catalogo/restock-historial:', err.message);
        res.status(500).json({ error: 'Error al obtener historial de restock' });
    }
});

// DELETE /api/b2b/catalogo/:id
app.delete('/api/b2b/catalogo/:id', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
    try {
        await pool.query('UPDATE catalogo_medicamentos_b2b SET activo=FALSE WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/catalogo/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar ítem del catálogo' });
    }
});

// ---------- B2B: CITAS ----------

// GET /api/b2b/citas
app.get('/api/b2b/citas', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = `SELECT c.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
                     FROM citas_b2b c JOIN pacientes_b2b p ON c.paciente_id=p.id WHERE c.institucion_id=$1`;
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND c.paciente_id=$2`; params.push(paciente_id); }
        query += ' ORDER BY c.fecha';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/citas:', err.message);
        res.status(500).json({ error: 'Error al obtener citas' });
    }
});

// POST /api/b2b/citas
app.post('/api/b2b/citas', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), requireActivePlan, async (req, res) => {
    try {
        const { paciente_id, titulo, descripcion, fecha, medico, especialidad, lugar } = req.body;
        if (!paciente_id || !titulo || !fecha) return res.status(400).json({ error: 'paciente_id, titulo y fecha obligatorios' });
        const result = await pool.query(
            `INSERT INTO citas_b2b (institucion_id, paciente_id, titulo, descripcion, fecha, medico, especialidad, lugar, created_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
            [req.b2bUser.institucion_id, paciente_id, titulo, descripcion, fecha, medico, especialidad, lugar, req.b2bUser.id]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/citas:', err.message);
        res.status(500).json({ error: 'Error al crear cita' });
    }
});

// PATCH /api/b2b/citas/:id
app.patch('/api/b2b/citas/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        const { titulo, descripcion, fecha, medico, especialidad, lugar, estado } = req.body;
        // Auto-archivar en historial si la cita estaba como 'realizada' y se reutiliza (cambia fecha o estado)
        const curRes = await pool.query(
            'SELECT * FROM citas_b2b WHERE id=$1 AND institucion_id=$2',
            [req.params.id, req.b2bUser.institucion_id]
        );
        const cur = curRes.rows[0];
        if (cur && cur.estado === 'realizada' && (fecha || (estado && estado !== 'realizada'))) {
            await pool.query(
                `INSERT INTO historial_citas_b2b
                 (institucion_id, cita_id, paciente_id, titulo, descripcion, fecha, medico, especialidad, lugar, estado, archivado_por)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
                [cur.institucion_id, cur.id, cur.paciente_id, cur.titulo, cur.descripcion,
                 cur.fecha, cur.medico, cur.especialidad, cur.lugar, cur.estado, req.b2bUser.id]
            ).catch(e => console.error('historial_citas insert error:', e.message));
        }
        await pool.query(
            `UPDATE citas_b2b SET titulo=COALESCE($1,titulo), descripcion=COALESCE($2,descripcion), fecha=COALESCE($3,fecha),
             medico=COALESCE($4,medico), especialidad=COALESCE($5,especialidad), lugar=COALESCE($6,lugar), estado=COALESCE($7,estado)
             WHERE id=$8 AND institucion_id=$9`,
            [titulo, descripcion, fecha, medico, especialidad, lugar, estado, req.params.id, req.b2bUser.institucion_id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /api/b2b/citas/:id:', err.message);
        res.status(500).json({ error: 'Error al actualizar cita' });
    }
});

// GET /api/b2b/citas/historial?paciente_id=X  — historial de citas archivadas
app.get('/api/b2b/citas/historial', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = `SELECT h.*, u.nombre as archivado_por_nombre
                     FROM historial_citas_b2b h
                     LEFT JOIN usuarios_b2b u ON h.archivado_por = u.id
                     WHERE h.institucion_id=$1`;
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND h.paciente_id=$2`; params.push(paciente_id); }
        query += ' ORDER BY h.fecha DESC';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/citas/historial:', err.message);
        res.status(500).json({ error: 'Error al obtener historial de citas' });
    }
});

// DELETE /api/b2b/citas/:id
app.delete('/api/b2b/citas/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        await pool.query('DELETE FROM citas_b2b WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/citas/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar cita' });
    }
});

// ---------- B2B: TAREAS ----------

// GET /api/b2b/tareas/historial (debe ir ANTES de /:id)
app.get('/api/b2b/tareas/historial', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = 'SELECT * FROM historial_tareas_b2b WHERE institucion_id=$1';
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND paciente_id=$2`; params.push(paciente_id); }
        query += ' ORDER BY fecha DESC LIMIT 100';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/tareas/historial:', err.message);
        res.status(500).json({ error: 'Error al obtener historial de tareas' });
    }
});

// GET /api/b2b/tareas
app.get('/api/b2b/tareas', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = `SELECT t.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
                     FROM tareas_b2b t JOIN pacientes_b2b p ON t.paciente_id=p.id
                     WHERE t.institucion_id=$1 AND t.activa=TRUE`;
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND t.paciente_id=$2`; params.push(paciente_id); }
        query += ' ORDER BY t.hora NULLS LAST, t.titulo';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/tareas:', err.message);
        res.status(500).json({ error: 'Error al obtener tareas' });
    }
});

// POST /api/b2b/tareas
app.post('/api/b2b/tareas', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), requireActivePlan, async (req, res) => {
    try {
        const { paciente_id, titulo, descripcion, categoria, frecuencia, hora } = req.body;
        if (!paciente_id || !titulo) return res.status(400).json({ error: 'paciente_id y titulo obligatorios' });
        const result = await pool.query(
            `INSERT INTO tareas_b2b (institucion_id, paciente_id, titulo, descripcion, categoria, frecuencia, hora, created_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
            [req.b2bUser.institucion_id, paciente_id, titulo, descripcion, categoria, frecuencia, hora||null, req.b2bUser.id]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/tareas:', err.message);
        res.status(500).json({ error: 'Error al crear tarea' });
    }
});

// POST /api/b2b/tareas/:id/completar
app.post('/api/b2b/tareas/:id/completar', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), requireActivePlan, async (req, res) => {
    try {
        const tarea = await pool.query('SELECT * FROM tareas_b2b WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        if (tarea.rowCount === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
        const t = tarea.rows[0];
        const _compNombre = (req.body._quien && typeof req.body._quien === 'string' && req.body._quien.trim()) ? req.body._quien.trim() : req.b2bUser.nombre;
        const result = await pool.query(
            `INSERT INTO historial_tareas_b2b (institucion_id, paciente_id, tarea_id, tarea_titulo, completado_por, completador_nombre, notas, fecha)
             VALUES ($1,$2,$3,$4,$5,$6,$7, NOW() AT TIME ZONE 'America/Argentina/Buenos_Aires') RETURNING *`,
            [req.b2bUser.institucion_id, t.paciente_id, t.id, t.titulo, req.b2bUser.id, _compNombre, req.body.notas||null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/tareas/:id/completar:', err.message);
        res.status(500).json({ error: 'Error al completar tarea' });
    }
});

// PATCH /api/b2b/tareas/:id
app.patch('/api/b2b/tareas/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        const { titulo, descripcion, categoria, frecuencia, hora, activa } = req.body;
        await pool.query(
            `UPDATE tareas_b2b SET titulo=COALESCE($1,titulo), descripcion=COALESCE($2,descripcion),
             categoria=COALESCE($3,categoria), frecuencia=COALESCE($4,frecuencia), hora=COALESCE($5,hora), activa=COALESCE($6,activa)
             WHERE id=$7 AND institucion_id=$8`,
            [titulo, descripcion, categoria, frecuencia, hora, activa, req.params.id, req.b2bUser.institucion_id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /api/b2b/tareas/:id:', err.message);
        res.status(500).json({ error: 'Error al actualizar tarea' });
    }
});

// DELETE /api/b2b/tareas/:id
app.delete('/api/b2b/tareas/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        await pool.query('UPDATE tareas_b2b SET activa=FALSE WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/tareas/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar tarea' });
    }
});

// ---------- B2B: SÍNTOMAS ----------

// GET /api/b2b/sintomas
app.get('/api/b2b/sintomas', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = `SELECT s.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
                     FROM sintomas_b2b s JOIN pacientes_b2b p ON s.paciente_id=p.id WHERE s.institucion_id=$1`;
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND s.paciente_id=$2`; params.push(paciente_id); }
        query += ' ORDER BY s.fecha DESC LIMIT 100';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/sintomas:', err.message);
        res.status(500).json({ error: 'Error al obtener síntomas' });
    }
});

// POST /api/b2b/sintomas
app.post('/api/b2b/sintomas', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), requireActivePlan, async (req, res) => {
    try {
        const { paciente_id, descripcion, intensidad } = req.body;
        if (!paciente_id || !descripcion) return res.status(400).json({ error: 'paciente_id y descripcion obligatorios' });
        const _regNombreSint = (req.body._quien && typeof req.body._quien === 'string' && req.body._quien.trim()) ? req.body._quien.trim() : req.b2bUser.nombre;
        const result = await pool.query(
            `INSERT INTO sintomas_b2b (institucion_id, paciente_id, descripcion, intensidad, registrado_por, registrador_nombre)
             VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
            [req.b2bUser.institucion_id, paciente_id, descripcion, intensidad||null, req.b2bUser.id, _regNombreSint]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/sintomas:', err.message);
        res.status(500).json({ error: 'Error al crear síntoma' });
    }
});

// PATCH /api/b2b/sintomas/:id
app.patch('/api/b2b/sintomas/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        const { descripcion, intensidad } = req.body;
        if (!descripcion) return res.status(400).json({ error: 'descripcion obligatoria' });
        const result = await pool.query(
            'UPDATE sintomas_b2b SET descripcion=$1, intensidad=$2 WHERE id=$3 AND institucion_id=$4 RETURNING *',
            [descripcion, intensidad ?? null, req.params.id, req.b2bUser.institucion_id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Síntoma no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('PATCH /api/b2b/sintomas/:id:', err.message);
        res.status(500).json({ error: 'Error al actualizar síntoma' });
    }
});

// DELETE /api/b2b/sintomas/:id
app.delete('/api/b2b/sintomas/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        await pool.query('DELETE FROM sintomas_b2b WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/sintomas/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar síntoma' });
    }
});

// ---------- B2B: SIGNOS VITALES ----------

// GET /api/b2b/signos-vitales
app.get('/api/b2b/signos-vitales', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id, tipo } = req.query;
        let query = `SELECT sv.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
                     FROM signos_vitales_b2b sv JOIN pacientes_b2b p ON sv.paciente_id=p.id WHERE sv.institucion_id=$1`;
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND sv.paciente_id=$${params.length+1}`; params.push(paciente_id); }
        if (tipo) { query += ` AND sv.tipo=$${params.length+1}`; params.push(tipo); }
        query += ' ORDER BY sv.fecha DESC LIMIT 100';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/signos-vitales:', err.message);
        res.status(500).json({ error: 'Error al obtener signos vitales' });
    }
});

// POST /api/b2b/signos-vitales
app.post('/api/b2b/signos-vitales', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), requireActivePlan, async (req, res) => {
    try {
        const { paciente_id, tipo, valor, unidad, notas } = req.body;
        if (!paciente_id || !tipo || !valor) return res.status(400).json({ error: 'paciente_id, tipo y valor obligatorios' });
        const _regNombreSigno = (req.body._quien && typeof req.body._quien === 'string' && req.body._quien.trim()) ? req.body._quien.trim() : req.b2bUser.nombre;
        const result = await pool.query(
            `INSERT INTO signos_vitales_b2b (institucion_id, paciente_id, tipo, valor, unidad, notas, registrado_por, registrador_nombre)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
            [req.b2bUser.institucion_id, paciente_id, tipo, valor, unidad, notas, req.b2bUser.id, _regNombreSigno]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/signos-vitales:', err.message);
        res.status(500).json({ error: 'Error al crear signo vital' });
    }
});

// DELETE /api/b2b/signos-vitales/:id
app.delete('/api/b2b/signos-vitales/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        await pool.query('DELETE FROM signos_vitales_b2b WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/signos-vitales/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar signo vital' });
    }
});

// ---------- B2B: CONTACTOS DE EMERGENCIA ----------

// GET /api/b2b/contactos
app.get('/api/b2b/contactos', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = 'SELECT * FROM contactos_b2b WHERE institucion_id=$1';
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND paciente_id=$2`; params.push(paciente_id); }
        query += ' ORDER BY es_principal DESC, nombre';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/contactos:', err.message);
        res.status(500).json({ error: 'Error al obtener contactos' });
    }
});

// POST /api/b2b/contactos
app.post('/api/b2b/contactos', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        const { paciente_id, nombre, relacion, telefono, email, es_principal } = req.body;
        if (!paciente_id || !nombre) return res.status(400).json({ error: 'paciente_id y nombre obligatorios' });
        const result = await pool.query(
            `INSERT INTO contactos_b2b (institucion_id, paciente_id, nombre, relacion, telefono, email, es_principal)
             VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
            [req.b2bUser.institucion_id, paciente_id, nombre, relacion, telefono, email, es_principal||false]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/contactos:', err.message);
        res.status(500).json({ error: 'Error al crear contacto' });
    }
});

// PATCH /api/b2b/contactos/:id
app.patch('/api/b2b/contactos/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        const { nombre, relacion, telefono, email, es_principal } = req.body;
        await pool.query(
            `UPDATE contactos_b2b SET nombre=COALESCE($1,nombre), relacion=COALESCE($2,relacion),
             telefono=COALESCE($3,telefono), email=COALESCE($4,email), es_principal=COALESCE($5,es_principal)
             WHERE id=$6 AND institucion_id=$7`,
            [nombre, relacion, telefono, email, es_principal, req.params.id, req.b2bUser.institucion_id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /api/b2b/contactos/:id:', err.message);
        res.status(500).json({ error: 'Error al actualizar contacto' });
    }
});

// DELETE /api/b2b/contactos/:id
app.delete('/api/b2b/contactos/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        await pool.query('DELETE FROM contactos_b2b WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/contactos/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar contacto' });
    }
});

// ---------- B2B: NOTAS INTERNAS ----------

// GET /api/b2b/notas
app.get('/api/b2b/notas', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = `SELECT n.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
                     FROM notas_b2b n JOIN pacientes_b2b p ON n.paciente_id=p.id WHERE n.institucion_id=$1`;
        const params = [req.b2bUser.institucion_id];
        if (paciente_id) { query += ` AND n.paciente_id=$2`; params.push(paciente_id); }
        query += ' ORDER BY n.urgente DESC, n.created_at DESC';
        res.json((await pool.query(query, params)).rows);
    } catch (err) {
        console.error('GET /api/b2b/notas:', err.message);
        res.status(500).json({ error: 'Error al obtener notas' });
    }
});

// POST /api/b2b/notas
app.post('/api/b2b/notas', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), requireActivePlan, async (req, res) => {
    try {
        const { paciente_id, titulo, contenido, urgente } = req.body;
        if (!paciente_id) return res.status(400).json({ error: 'paciente_id obligatorio' });
        const _autorNombre = (req.body._quien && typeof req.body._quien === 'string' && req.body._quien.trim()) ? req.body._quien.trim() : req.b2bUser.nombre;
        const result = await pool.query(
            `INSERT INTO notas_b2b (institucion_id, paciente_id, titulo, contenido, urgente, autor_id, autor_nombre)
             VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
            [req.b2bUser.institucion_id, paciente_id, titulo, contenido, urgente||false, req.b2bUser.id, _autorNombre]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/notas:', err.message);
        res.status(500).json({ error: 'Error al crear nota' });
    }
});

// PATCH /api/b2b/notas/:id
app.patch('/api/b2b/notas/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        const { titulo, contenido, urgente } = req.body;
        await pool.query(
            `UPDATE notas_b2b SET titulo=COALESCE($1,titulo), contenido=COALESCE($2,contenido), urgente=COALESCE($3,urgente)
             WHERE id=$4 AND institucion_id=$5`,
            [titulo, contenido, urgente, req.params.id, req.b2bUser.institucion_id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('PATCH /api/b2b/notas/:id:', err.message);
        res.status(500).json({ error: 'Error al actualizar nota' });
    }
});

// DELETE /api/b2b/notas/:id
app.delete('/api/b2b/notas/:id', authB2BMiddleware, requireB2BRole('admin_institucion','cuidador_staff'), async (req, res) => {
    try {
        await pool.query('DELETE FROM notas_b2b WHERE id=$1 AND institucion_id=$2', [req.params.id, req.b2bUser.institucion_id]);
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/notas/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar nota' });
    }
});

// ---------- B2B: NOTIFICACIONES ----------

// GET /api/b2b/notificaciones — devuelve alertas agrupadas + conteo de no vistas
app.get('/api/b2b/notificaciones', authB2BMiddleware, async (req, res) => {
    try {
        const iid = req.b2bUser.institucion_id;
        const uid = req.b2bUser.id;
        // Obtener cuándo abrió la campana por última vez este usuario
        const lsRes = await pool.query('SELECT notif_last_seen_at FROM usuarios_b2b WHERE id=$1', [uid]);
        const lastSeen = lsRes.rows[0]?.notif_last_seen_at || new Date(0);
        const [citasR, notasR, sintomasR, stockR, cumpleR, ingresosR, egresosR] = await Promise.all([
            // Citas próximas (15 días) pendientes
            pool.query(`SELECT c.id, c.titulo, c.fecha, c.created_at, p.nombre||' '||p.apellido AS paciente_nombre, p.id AS paciente_id
                        FROM citas_b2b c JOIN pacientes_b2b p ON c.paciente_id=p.id
                        WHERE c.institucion_id=$1 AND c.estado='pendiente' AND c.fecha BETWEEN NOW() AND NOW()+INTERVAL '15 days'
                        AND p.fecha_egreso IS NULL ORDER BY c.fecha LIMIT 20`, [iid]).catch(() => ({ rows: [] })),
            // Notas urgentes activas (no archivadas — usa solo columnas existentes)
            pool.query(`SELECT n.id, n.contenido, n.created_at, p.nombre||' '||p.apellido AS paciente_nombre, p.id AS paciente_id
                        FROM notas_b2b n JOIN pacientes_b2b p ON n.paciente_id=p.id
                        WHERE n.institucion_id=$1 AND n.urgente=TRUE
                        AND p.fecha_egreso IS NULL ORDER BY n.created_at DESC LIMIT 10`, [iid]).catch(() => ({ rows: [] })),
            // Síntomas registrados en las últimas 24h
            pool.query(`SELECT s.id, s.tipo, s.descripcion, s.created_at, p.nombre||' '||p.apellido AS paciente_nombre, p.id AS paciente_id
                        FROM sintomas_b2b s JOIN pacientes_b2b p ON s.paciente_id=p.id
                        WHERE s.institucion_id=$1 AND s.created_at > NOW()-INTERVAL '24 hours'
                        AND p.fecha_egreso IS NULL ORDER BY s.created_at DESC LIMIT 10`, [iid]).catch(() => ({ rows: [] })),
            // Insumos con stock bajo
            pool.query(`SELECT id, nombre, stock_actual, stock_minimo, paciente_id
                        FROM catalogo_medicamentos_b2b
                        WHERE institucion_id=$1 AND activo=TRUE AND stock_actual < stock_minimo
                        ORDER BY (stock_minimo - stock_actual) DESC LIMIT 20`, [iid]).catch(() => ({ rows: [] })),
            // Cumpleaños en los próximos 7 días
            pool.query(`SELECT id, nombre, apellido, fecha_nacimiento
                        FROM pacientes_b2b
                        WHERE institucion_id=$1 AND activo=TRUE AND fecha_egreso IS NULL AND fecha_nacimiento IS NOT NULL
                        AND TO_CHAR(fecha_nacimiento::date, 'MM-DD') BETWEEN TO_CHAR(NOW(), 'MM-DD') AND TO_CHAR(NOW()+INTERVAL '7 days', 'MM-DD')
                        ORDER BY TO_CHAR(fecha_nacimiento::date, 'MM-DD') LIMIT 10`, [iid]).catch(() => ({ rows: [] })),
            // Ingresos recientes (últimas 24h)
            pool.query(`SELECT id, nombre, apellido, created_at FROM pacientes_b2b
                        WHERE institucion_id=$1 AND created_at > NOW()-INTERVAL '24 hours'
                        ORDER BY created_at DESC LIMIT 10`, [iid]).catch(() => ({ rows: [] })),
            // Egresos recientes (últimas 24h)
            pool.query(`SELECT id, nombre, apellido, fecha_egreso FROM pacientes_b2b
                        WHERE institucion_id=$1 AND fecha_egreso IS NOT NULL
                        AND fecha_egreso::timestamptz > NOW()-INTERVAL '24 hours'
                        ORDER BY fecha_egreso DESC LIMIT 10`, [iid]).catch(() => ({ rows: [] })),
        ]);
        const items = [];
        citasR.rows.forEach(c => items.push({ tipo: 'cita', icono: '📅', titulo: c.titulo, descripcion: `${c.paciente_nombre} · ${new Date(c.fecha).toLocaleDateString('es-AR', { day: '2-digit', month: '2-digit' })}`, href: `paciente.html?id=${c.paciente_id}`, ts: c.created_at, es_nuevo: new Date(c.created_at) > new Date(lastSeen) }));
        notasR.rows.forEach(n => items.push({ tipo: 'nota_urgente', icono: '🚨', titulo: 'Nota urgente', descripcion: `${n.paciente_nombre}: ${String(n.contenido || '').slice(0, 70)}`, href: `paciente.html?id=${n.paciente_id}`, ts: n.created_at, es_nuevo: new Date(n.created_at) > new Date(lastSeen) }));
        sintomasR.rows.forEach(s => items.push({ tipo: 'sintoma', icono: '🤒', titulo: `Síntoma: ${s.tipo}`, descripcion: s.paciente_nombre, href: `paciente.html?id=${s.paciente_id}`, ts: s.created_at, es_nuevo: new Date(s.created_at) > new Date(lastSeen) }));
        stockR.rows.forEach(s => items.push({ tipo: 'stock_bajo', icono: '⚠️', titulo: `Stock bajo: ${s.nombre}`, descripcion: `Actual: ${s.stock_actual} / Mínimo: ${s.stock_minimo}`, href: s.paciente_id ? `paciente.html?id=${s.paciente_id}` : 'catalogo.html', ts: null, es_nuevo: false }));
        cumpleR.rows.forEach(p => items.push({ tipo: 'cumpleanos', icono: '🎂', titulo: `Cumpleaños: ${p.nombre} ${p.apellido}`, descripcion: new Date(String(p.fecha_nacimiento).slice(0, 10) + 'T12:00:00').toLocaleDateString('es-AR', { day: '2-digit', month: 'long' }), href: `paciente.html?id=${p.id}`, ts: null, es_nuevo: false }));
        ingresosR.rows.forEach(p => items.push({ tipo: 'ingreso', icono: '🏥', titulo: `Nuevo ingreso: ${p.nombre} ${p.apellido}`, descripcion: 'Residente dado de alta recientemente', href: `paciente.html?id=${p.id}`, ts: p.created_at, es_nuevo: new Date(p.created_at) > new Date(lastSeen) }));
        egresosR.rows.forEach(p => items.push({ tipo: 'egreso', icono: '🏠', titulo: `Egreso: ${p.nombre} ${p.apellido}`, descripcion: 'Residente dado de egreso recientemente', href: `paciente.html?id=${p.id}`, ts: p.fecha_egreso, es_nuevo: p.fecha_egreso && new Date(p.fecha_egreso) > new Date(lastSeen) }));
        res.json({ unread: items.filter(i => i.es_nuevo).length, items });
    } catch (err) {
        console.error('GET /api/b2b/notificaciones:', err.message);
        res.status(500).json({ error: 'Error al obtener notificaciones' });
    }
});

// POST /api/b2b/notificaciones/vistas — marca la campana como vista (actualiza timestamp)
app.post('/api/b2b/notificaciones/vistas', authB2BMiddleware, async (req, res) => {
    try {
        await pool.query('UPDATE usuarios_b2b SET notif_last_seen_at=NOW() WHERE id=$1', [req.b2bUser.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('POST /api/b2b/notificaciones/vistas:', err.message);
        res.status(500).json({ error: 'Error al marcar notificaciones como vistas' });
    }
});

// ---------- B2B: DASHBOARD ----------

// GET /api/b2b/dashboard
app.get('/api/b2b/dashboard', authB2BMiddleware, async (req, res) => {
    try {
        const iid = req.b2bUser.institucion_id;
        const [pacientes, staff, citasProximas, sintomasRecientes, notasUrgentes, tomasHoy, tareasHoy, cumpleanosHoy, stockBajo] = await Promise.all([
            pool.query('SELECT COUNT(*) as total FROM pacientes_b2b WHERE institucion_id=$1 AND activo=TRUE AND fecha_egreso IS NULL', [iid]),
            pool.query('SELECT COUNT(*) as total, rol FROM usuarios_b2b WHERE institucion_id=$1 AND activo=TRUE GROUP BY rol', [iid]),
            pool.query(`SELECT c.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
                        FROM citas_b2b c JOIN pacientes_b2b p ON c.paciente_id=p.id
                        WHERE c.institucion_id=$1 AND c.fecha BETWEEN NOW() AND NOW()+INTERVAL '15 days' AND c.estado='pendiente'
                        AND p.fecha_egreso IS NULL
                        ORDER BY c.fecha LIMIT 10`, [iid]),
            pool.query(`SELECT s.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
                        FROM sintomas_b2b s JOIN pacientes_b2b p ON s.paciente_id=p.id
                        WHERE s.institucion_id=$1 AND s.fecha > NOW()-INTERVAL '24 hours'
                        AND p.fecha_egreso IS NULL
                        ORDER BY s.fecha DESC LIMIT 10`, [iid]),
            pool.query(`SELECT n.*, p.nombre as paciente_nombre, p.apellido as paciente_apellido
                        FROM notas_b2b n JOIN pacientes_b2b p ON n.paciente_id=p.id
                        WHERE n.institucion_id=$1 AND n.urgente=TRUE
                        AND p.fecha_egreso IS NULL
                        ORDER BY n.created_at DESC LIMIT 10`, [iid]),
            pool.query('SELECT COUNT(*) as total FROM historial_medicamentos_b2b WHERE institucion_id=$1 AND fecha>CURRENT_DATE', [iid]),
            pool.query('SELECT COUNT(*) as total FROM historial_tareas_b2b WHERE institucion_id=$1 AND fecha>CURRENT_DATE', [iid]),
            pool.query(`SELECT id, nombre, apellido, fecha_nacimiento,
                        EXTRACT(YEAR FROM AGE(fecha_nacimiento)) AS edad
                        FROM pacientes_b2b
                        WHERE institucion_id=$1 AND activo=TRUE AND fecha_egreso IS NULL
                        AND TO_CHAR(fecha_nacimiento,'MM-DD') = TO_CHAR(NOW(),'MM-DD')`, [iid]),
            pool.query(`
                SELECT * FROM (
                    -- Insumos individuales con stock bajo (no vinculados a catálogo)
                    SELECT m.id::INTEGER, m.nombre,
                        TRIM(COALESCE(m.dosis,'') || CASE WHEN m.frecuencia IS NOT NULL AND m.frecuencia <> '' THEN ' · ' || m.frecuencia ELSE '' END) AS dosis_horario,
                        m.stock, NULL::TEXT AS unidad, 'individual'::TEXT AS tipo,
                        m.paciente_id, p.nombre AS paciente_nombre, p.apellido AS paciente_apellido
                    FROM medicamentos_b2b m
                    LEFT JOIN pacientes_b2b p ON m.paciente_id = p.id
                    WHERE m.institucion_id=$1 AND m.activo=TRUE AND m.catalogo_id IS NULL
                      AND m.stock IS NOT NULL AND m.stock < 10
                    UNION ALL
                    -- Insumos del catálogo (institucional y por paciente) con stock bajo
                    SELECT c.id::INTEGER, c.nombre, c.presentacion AS dosis_horario,
                        c.stock_actual AS stock, c.unidad,
                        CASE WHEN c.paciente_id IS NULL THEN 'catalogo'::TEXT ELSE 'catalogo_paciente'::TEXT END AS tipo,
                        c.paciente_id, p.nombre AS paciente_nombre, p.apellido AS paciente_apellido
                    FROM catalogo_medicamentos_b2b c
                    LEFT JOIN pacientes_b2b p ON c.paciente_id = p.id
                    WHERE c.institucion_id=$1 AND c.stock_actual IS NOT NULL
                      AND c.stock_actual <= COALESCE(c.stock_minimo, 5)
                ) combinado
                ORDER BY stock ASC LIMIT 15`, [iid])
        ]);
        res.json({
            resumen: { pacientes_activos: parseInt(pacientes.rows[0].total), tomas_hoy: parseInt(tomasHoy.rows[0].total), tareas_completadas_hoy: parseInt(tareasHoy.rows[0].total), staff: staff.rows },
            citas_proximas: citasProximas.rows,
            sintomas_recientes: sintomasRecientes.rows,
            notas_urgentes: notasUrgentes.rows,
            cumpleanos_hoy: cumpleanosHoy.rows,
            stock_bajo: stockBajo.rows
        });
    } catch (err) {
        console.error('GET /api/b2b/dashboard:', err.message);
        res.status(500).json({ error: 'Error al obtener dashboard' });
    }
});

// GET /api/b2b/reportes?paciente_id=&desde=&hasta=
app.get('/api/b2b/reportes', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id, desde, hasta } = req.query;
        if (!paciente_id) return res.status(400).json({ error: 'paciente_id requerido' });
        const iid = req.b2bUser.institucion_id;
        const d = desde || new Date(Date.now() - 30*24*60*60*1000).toISOString();
        const h = hasta || new Date().toISOString();
        const [paciente, medicamentos, histMeds, citas, histTareas, sintomas, signos, contactos, notas] = await Promise.all([
            pool.query('SELECT * FROM pacientes_b2b WHERE id=$1 AND institucion_id=$2', [paciente_id, iid]),
            pool.query('SELECT * FROM medicamentos_b2b WHERE paciente_id=$1 AND activo=TRUE', [paciente_id]),
            pool.query('SELECT * FROM historial_medicamentos_b2b WHERE paciente_id=$1 AND fecha BETWEEN $2 AND $3 ORDER BY fecha DESC', [paciente_id, d, h]),
            pool.query('SELECT * FROM citas_b2b WHERE paciente_id=$1 AND fecha BETWEEN $2 AND $3 ORDER BY fecha', [paciente_id, d, h]),
            pool.query('SELECT * FROM historial_tareas_b2b WHERE paciente_id=$1 AND fecha BETWEEN $2 AND $3 ORDER BY fecha DESC', [paciente_id, d, h]),
            pool.query('SELECT * FROM sintomas_b2b WHERE paciente_id=$1 AND fecha BETWEEN $2 AND $3 ORDER BY fecha DESC', [paciente_id, d, h]),
            pool.query('SELECT * FROM signos_vitales_b2b WHERE paciente_id=$1 AND fecha BETWEEN $2 AND $3 ORDER BY fecha DESC', [paciente_id, d, h]),
            pool.query('SELECT * FROM contactos_b2b WHERE paciente_id=$1 ORDER BY es_principal DESC', [paciente_id]),
            pool.query('SELECT * FROM notas_b2b WHERE paciente_id=$1 AND created_at BETWEEN $2 AND $3 ORDER BY created_at DESC', [paciente_id, d, h])
        ]);
        if (paciente.rowCount === 0) return res.status(404).json({ error: 'Paciente no encontrado' });
        res.json({
            paciente: paciente.rows[0], periodo: { desde: d, hasta: h },
            medicamentos: medicamentos.rows, historial_medicamentos: histMeds.rows,
            citas: citas.rows, historial_tareas: histTareas.rows,
            sintomas: sintomas.rows, signos_vitales: signos.rows,
            contactos: contactos.rows, notas: notas.rows
        });
    } catch (err) {
        console.error('GET /api/b2b/reportes:', err.message);
        res.status(500).json({ error: 'Error al generar reporte' });
    }
});

// GET /api/b2b/reporte/export — backup completo de la institución (solo admin)
app.get('/api/b2b/reporte/export', authB2BMiddleware, async (req, res) => {
    try {
        if (req.b2bUser.rol !== 'admin_institucion') {
            return res.status(403).json({ error: 'Solo el administrador puede exportar datos' });
        }
        const iid = req.b2bUser.institucion_id;
        const [institucion, pacientes, staff, medicamentos, histMeds, citas, histTareas, sintomas, signos, contactos, notas] = await Promise.all([
            pool.query('SELECT id, nombre, tipo, telefono, email, direccion, created_at FROM instituciones_b2b WHERE id=$1', [iid]),
            pool.query('SELECT * FROM pacientes_b2b WHERE institucion_id=$1 ORDER BY apellido, nombre', [iid]),
            pool.query('SELECT id, nombre, email, rol, turno, activo, created_at FROM usuarios_b2b WHERE institucion_id=$1 ORDER BY rol, nombre', [iid]),
            pool.query('SELECT * FROM medicamentos_b2b WHERE institucion_id=$1 ORDER BY paciente_id', [iid]),
            pool.query('SELECT * FROM historial_medicamentos_b2b WHERE institucion_id=$1 ORDER BY fecha DESC', [iid]),
            pool.query('SELECT * FROM citas_b2b WHERE institucion_id=$1 ORDER BY fecha DESC', [iid]),
            pool.query('SELECT * FROM historial_tareas_b2b WHERE institucion_id=$1 ORDER BY fecha DESC', [iid]),
            pool.query('SELECT * FROM sintomas_b2b WHERE institucion_id=$1 ORDER BY fecha DESC', [iid]),
            pool.query('SELECT * FROM signos_vitales_b2b WHERE institucion_id=$1 ORDER BY fecha DESC', [iid]),
            pool.query('SELECT * FROM contactos_b2b WHERE institucion_id=$1', [iid]),
            pool.query('SELECT * FROM notas_b2b WHERE institucion_id=$1 ORDER BY created_at DESC', [iid]),
        ]);
        res.json({
            exportado_en: new Date().toISOString(),
            version: '1.0',
            institucion: institucion.rows[0],
            resumen: {
                total_pacientes: pacientes.rowCount,
                total_staff: staff.rowCount,
                total_medicamentos: medicamentos.rowCount,
                total_tomas: histMeds.rowCount,
                total_citas: citas.rowCount,
                total_sintomas: sintomas.rowCount,
            },
            pacientes: pacientes.rows,
            staff: staff.rows,
            medicamentos: medicamentos.rows,
            historial_medicamentos: histMeds.rows,
            citas: citas.rows,
            historial_tareas: histTareas.rows,
            sintomas: sintomas.rows,
            signos_vitales: signos.rows,
            contactos: contactos.rows,
            notas: notas.rows,
        });
    } catch (err) {
        console.error('GET /api/b2b/reporte/export:', err.message);
        res.status(500).json({ error: 'Error al exportar datos' });
    }
});

// ---------- B2B: DOCUMENTOS ADJUNTOS ----------

// POST /api/b2b/documentos — subir documento (base64) para un paciente (máx 5 MB)
app.post('/api/b2b/documentos', authB2BMiddleware, requireActivePlan, async (req, res) => {
    try {
        const { paciente_id, nombre_archivo, tipo_mime, datos } = req.body;
        if (!paciente_id || !nombre_archivo || !datos)
            return res.status(400).json({ error: 'paciente_id, nombre_archivo y datos son requeridos' });
        const hasAccess = await checkB2BPacienteAccess(req.b2bUser, parseInt(paciente_id));
        if (!hasAccess) return res.status(403).json({ error: 'Sin acceso a este paciente' });
        // Base64 de 5 MB ≈ 6.8 MB de texto; con margen: 7 MB de chars
        if (datos.length > 7 * 1024 * 1024)
            return res.status(413).json({ error: 'El archivo supera el límite de 5 MB' });
        // Límite de almacenamiento por institución: 200 MB de datos base64
        // (Railway Hobby plan: 5 GB total — 200 MB/institución deja margen para muchas instituciones)
        const DOC_LIMIT = 200 * 1024 * 1024;
        const storageCheck = await pool.query(
            `SELECT COALESCE(SUM(LENGTH(datos)), 0) AS total FROM documentos_b2b WHERE institucion_id=$1`,
            [req.b2bUser.institucion_id]
        );
        const usedBytes = parseInt(storageCheck.rows[0].total);
        if (usedBytes + datos.length > DOC_LIMIT) {
            const usedMB = (usedBytes / 1024 / 1024).toFixed(1);
            return res.status(413).json({ error: `Límite de almacenamiento alcanzado (${usedMB} MB de 200 MB usados). Eliminá documentos anteriores para liberar espacio.` });
        }
        const tamanio_bytes = Math.round(datos.length * 0.75);
        const result = await pool.query(
            `INSERT INTO documentos_b2b (institucion_id, paciente_id, nombre_archivo, tipo_mime, tamanio_bytes, datos, subido_por, subido_nombre)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
             RETURNING id, nombre_archivo, tipo_mime, tamanio_bytes, subido_nombre, created_at`,
            [req.b2bUser.institucion_id, paciente_id, nombre_archivo, tipo_mime || null,
             tamanio_bytes, datos, req.b2bUser.id, req.b2bUser.nombre]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('POST /api/b2b/documentos:', err.message);
        res.status(500).json({ error: 'Error al guardar documento' });
    }
});

// GET /api/b2b/documentos?paciente_id=X — listar documentos (sin datos binarios para listado rápido)
app.get('/api/b2b/documentos', authB2BMiddleware, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        if (!paciente_id) return res.status(400).json({ error: 'paciente_id requerido' });
        const hasAccess = await checkB2BPacienteAccess(req.b2bUser, parseInt(paciente_id));
        if (!hasAccess) return res.status(403).json({ error: 'Sin acceso a este paciente' });
        const result = await pool.query(
            `SELECT id, nombre_archivo, tipo_mime, tamanio_bytes, subido_nombre, created_at
             FROM documentos_b2b WHERE paciente_id=$1 AND institucion_id=$2 ORDER BY created_at DESC`,
            [paciente_id, req.b2bUser.institucion_id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('GET /api/b2b/documentos:', err.message);
        res.status(500).json({ error: 'Error al obtener documentos' });
    }
});

// GET /api/b2b/documentos/:id/download — descargar documento completo con headers
app.get('/api/b2b/documentos/:id/download', authB2BMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM documentos_b2b WHERE id=$1 AND institucion_id=$2',
            [req.params.id, req.b2bUser.institucion_id]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Documento no encontrado' });
        const doc = result.rows[0];
        const buf = Buffer.from(doc.datos, 'base64');
        res.setHeader('Content-Type', doc.tipo_mime || 'application/octet-stream');
        res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(doc.nombre_archivo)}`);
        res.setHeader('Content-Length', buf.length);
        res.send(buf);
    } catch (err) {
        console.error('GET /api/b2b/documentos/:id/download:', err.message);
        res.status(500).json({ error: 'Error al descargar documento' });
    }
});

// DELETE /api/b2b/documentos/:id — solo quien lo subió o el admin puede eliminarlo
app.delete('/api/b2b/documentos/:id', authB2BMiddleware, async (req, res) => {
    try {
        const result = await pool.query(
            `DELETE FROM documentos_b2b WHERE id=$1 AND institucion_id=$2
             AND (subido_por=$3 OR $4='admin_institucion') RETURNING id`,
            [req.params.id, req.b2bUser.institucion_id, req.b2bUser.id, req.b2bUser.rol]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Documento no encontrado o sin permisos' });
        res.json({ success: true });
    } catch (err) {
        console.error('DELETE /api/b2b/documentos/:id:', err.message);
        res.status(500).json({ error: 'Error al eliminar documento' });
    }
});

// ============================================================
// ========== FIN MÓDULO B2B ==========
// ============================================================

// ============================================================
// ========== SUPERADMIN — Activación manual de planes =========
// ============================================================
// GET /api/admin/institucion/:id — Consulta datos de una institución (para el panel admin)
app.get('/api/admin/institucion/:id', async (req, res) => {
    const adminKey    = req.headers['x-admin-key'];
    const expectedKey = process.env.SUPERADMIN_KEY;
    if (!expectedKey) return res.status(503).json({ error: 'SUPERADMIN_KEY no configurada en el servidor' });
    if (!adminKey || adminKey !== expectedKey) return res.status(401).json({ error: 'Clave de administrador inválida' });
    try {
        const result = await pool.query(
            'SELECT id, nombre, tipo, email, telefono, plan, activa, created_at FROM instituciones_b2b WHERE id=$1',
            [parseInt(req.params.id)]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Institución no encontrada' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('[SuperAdmin] get-institucion error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

// POST /api/admin/set-plan
// Permite a EDEN SoftWork activar un plan manualmente para clientes
// que pagan por transferencia bancaria o cualquier acuerdo directo.
// Requiere el header: X-Admin-Key: <SUPERADMIN_KEY (env var en Railway)>
//
// Uso (curl):
//   curl -X POST https://<backend>/api/admin/set-plan \
//        -H "X-Admin-Key: tu_clave_secreta" \
//        -H "Content-Type: application/json" \
//        -d '{"institucion_id": 5, "plan": "pro", "note": "Transferencia 15/03"}'
// Planes válidos: free | basico | pro
app.post('/api/admin/set-plan', async (req, res) => {
    const adminKey   = req.headers['x-admin-key'];
    const expectedKey = process.env.SUPERADMIN_KEY;
    if (!expectedKey) return res.status(503).json({ error: 'SUPERADMIN_KEY no configurada en el servidor' });
    if (!adminKey || adminKey !== expectedKey) return res.status(401).json({ error: 'Clave de administrador inválida' });
    try {
        const { institucion_id, plan, note } = req.body;
        if (!institucion_id || !plan) return res.status(400).json({ error: 'institucion_id y plan son requeridos' });
        const validPlans = ['free', 'basico', 'pro'];
        if (!validPlans.includes(plan)) return res.status(400).json({ error: `Plan inválido. Debe ser uno de: ${validPlans.join(', ')}` });
        const result = await pool.query(
            'UPDATE instituciones_b2b SET plan=$1 WHERE id=$2 RETURNING id, nombre, plan',
            [plan, parseInt(institucion_id)]
        );
        if (result.rowCount === 0) return res.status(404).json({ error: 'Institución no encontrada' });
        const inst = result.rows[0];
        console.log(`[SuperAdmin] ✅ Plan actualizado manualmente — institución ${inst.id} (${inst.nombre}) → ${plan}${note ? ` | Nota: ${note}` : ''}`);
        res.json({ success: true, institucion_id: inst.id, nombre: inst.nombre, plan: inst.plan });
    } catch (err) {
        console.error('[SuperAdmin] set-plan error:', err.message);
        res.status(500).json({ error: err.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`✅ Servidor escuchando en puerto ${PORT}`);
    console.log(`📍 http://localhost:${PORT}`);
    await runMigrations();
    startPushReminders(); // ← Arranca el chequeo periódico de push

    // Sincronización periódica con MercadoPago: detecta cancelaciones aunque el webhook falle
    if (MP_ACCESS_TOKEN) {
        setTimeout(syncMPSubscriptions, 30000); // primer sync 30s después del boot
        setInterval(syncMPSubscriptions, 4 * 60 * 60 * 1000); // luego cada 4 horas
        console.log('✅ Sync periódico de suscripciones MP activado (cada 4 horas)');
    }

    // Recordatorios de vencimiento de trial: chequea diariamente
    setTimeout(checkTrialReminders, 2 * 60 * 1000); // primer chequeo 2min después del boot
    setInterval(checkTrialReminders, 24 * 60 * 60 * 1000); // luego cada 24 horas
    console.log('✅ Recordatorios de vencimiento de trial activados (cada 24 horas)');

    // Keep-alive: evita que Railway duerma el servidor en planes gratuitos.
    // Se hace un GET a /health propio cada 4 minutos.
    const BACKEND_URL = process.env.RAILWAY_STATIC_URL
        ? `https://${process.env.RAILWAY_STATIC_URL}`
        : (process.env.BACKEND_URL || null);
    if (BACKEND_URL) {
        setInterval(() => {
            https.get(`${BACKEND_URL}/health`, (res) => {
                // Solo para mantener vivo el proceso, no necesitamos la respuesta
                res.resume();
            }).on('error', () => { /* silencioso — el servidor sigue corriendo */ });
        }, 4 * 60 * 1000); // cada 4 minutos
        console.log(`🏓 Keep-alive activado → ${BACKEND_URL}/health`);
    }
});
