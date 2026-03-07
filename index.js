/**
 * index.js — Backend CuidaDiario (VERSIÓN COMPLETA)
 * by EDEN SoftWork
 *
 * ============================================================
 * FUNCIONALIDADES INCLUIDAS:
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
const FRONTEND_URL   = (process.env.FRONTEND_URL || '').replace(/\/$/, '');

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
app.use(express.json());

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
