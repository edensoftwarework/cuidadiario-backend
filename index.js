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
const cors = require('cors');
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
app.use(cors({ origin: '*', credentials: true }));
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
                id           SERIAL PRIMARY KEY,
                usuario_id   INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
                endpoint     TEXT    NOT NULL,
                p256dh       TEXT,
                auth         TEXT,
                created_at   TIMESTAMP DEFAULT NOW(),
                UNIQUE(usuario_id, endpoint)
            )
        `);

        // NUEVO: columnas para recuperación de contraseña
        await pool.query(`
            ALTER TABLE usuarios
            ADD COLUMN IF NOT EXISTS reset_token          VARCHAR(128),
            ADD COLUMN IF NOT EXISTS reset_token_expires  TIMESTAMP
        `);

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
app.get('/dbtest', async (req, res) => {
    try {
        const result = await pool.query('SELECT NOW()');
        res.json({ time: result.rows[0].now, status: 'Database connected' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ========== AUTENTICACIÓN ==========
app.post('/api/register', async (req, res) => {
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

app.post('/api/login', async (req, res) => {
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
app.post('/api/forgot-password', async (req, res) => {
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
        const result = await pool.query(
            'SELECT * FROM pacientes WHERE usuario_id=$1 AND activo=true ORDER BY id ASC',
            [req.user.id]
        );
        res.json(result.rows);
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
    const { nombre, dosis, frecuencia, horaInicio, hora_inicio, recordatorio, notas, horariosCustom, horarios_custom, paciente_id, pacienteId } = req.body;
    try {
        const pid = await resolvePatientId(paciente_id || pacienteId || null, req.user.id);
        if (pid && !(await validatePaciente(pid, req.user.id)))
            return res.status(403).json({ error: 'El paciente no pertenece a este usuario' });
        const result = await pool.query(
            'INSERT INTO medicamentos (usuario_id, paciente_id, nombre, dosis, frecuencia, hora_inicio, recordatorio, notas, horarios_custom) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
            [req.user.id, pid, nombre, dosis, frecuencia, horaInicio || hora_inicio || null, recordatorio || false, notas || null, horariosCustom || horarios_custom || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/medicamentos', authMiddleware, async (req, res) => {
    const paciente_id = req.query.paciente_id ? parseInt(req.query.paciente_id) : null;
    try {
        const result = paciente_id
            ? await pool.query('SELECT * FROM medicamentos WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY id DESC', [req.user.id, paciente_id])
            : await pool.query('SELECT * FROM medicamentos WHERE usuario_id=$1 ORDER BY id DESC', [req.user.id]);
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
    const { nombre, dosis, frecuencia, horaInicio, hora_inicio, recordatorio, notas, horariosCustom, horarios_custom } = req.body;
    try {
        const result = await pool.query(
            'UPDATE medicamentos SET nombre=$1, dosis=$2, frecuencia=$3, hora_inicio=$4, recordatorio=$5, notas=$6, horarios_custom=$7 WHERE id=$8 AND usuario_id=$9 RETURNING *',
            [nombre, dosis, frecuencia, horaInicio || hora_inicio || null, recordatorio, notas || null, horariosCustom || horarios_custom || null, req.params.id, req.user.id]
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
        const result = paciente_id
            ? await pool.query('SELECT * FROM citas WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha DESC, hora DESC', [req.user.id, paciente_id])
            : await pool.query('SELECT * FROM citas WHERE usuario_id=$1 ORDER BY fecha DESC, hora DESC', [req.user.id]);
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
        const result = paciente_id
            ? await pool.query('SELECT * FROM tareas WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha ASC, hora ASC', [req.user.id, paciente_id])
            : await pool.query('SELECT * FROM tareas WHERE usuario_id=$1 ORDER BY fecha ASC, hora ASC', [req.user.id]);
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
        const result = paciente_id
            ? await pool.query('SELECT * FROM sintomas WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha DESC', [req.user.id, paciente_id])
            : await pool.query('SELECT * FROM sintomas WHERE usuario_id=$1 ORDER BY fecha DESC', [req.user.id]);
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
        const result = paciente_id
            ? await pool.query('SELECT * FROM contactos WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY nombre ASC', [req.user.id, paciente_id])
            : await pool.query('SELECT * FROM contactos WHERE usuario_id=$1 ORDER BY nombre ASC', [req.user.id]);
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
        const result = paciente_id
            ? await pool.query('SELECT * FROM signos_vitales WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha DESC', [req.user.id, paciente_id])
            : await pool.query('SELECT * FROM signos_vitales WHERE usuario_id=$1 ORDER BY fecha DESC', [req.user.id]);
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
        const result = paciente_id
            ? await pool.query('SELECT * FROM historial_medicamentos WHERE usuario_id=$1 AND paciente_id=$2 ORDER BY fecha DESC LIMIT 100', [req.user.id, paciente_id])
            : await pool.query('SELECT * FROM historial_medicamentos WHERE usuario_id=$1 ORDER BY fecha DESC LIMIT 100', [req.user.id]);
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

// ========== PUSH NOTIFICATIONS (NUEVO) ==========

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

// Helper: envía una notificación push a todos los dispositivos de un usuario
async function sendPushToUser(userId, payload) {
    if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) return;
    try {
        const subs = await pool.query(
            'SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE usuario_id=$1',
            [userId]
        );
        const promises = subs.rows.map(sub => {
            const subscription = { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } };
            return webPush.sendNotification(subscription, JSON.stringify(payload))
                .catch(async err => {
                    // Endpoint caducado → eliminar automáticamente
                    if (err.statusCode === 410 || err.statusCode === 404) {
                        await pool.query('DELETE FROM push_subscriptions WHERE endpoint=$1', [sub.endpoint]);
                    }
                    console.warn(`[Push] Error enviando a ${sub.endpoint.substring(0, 40)}:`, err.message);
                });
        });
        await Promise.all(promises);
    } catch (err) {
        console.error('[Push] Error en sendPushToUser:', err.message);
    }
}

// Chequeo periódico de recordatorios — corre cada hora en el servidor
function startPushReminders() {
    if (!VAPID_PUBLIC_KEY || !VAPID_PRIVATE_KEY) {
        console.log('ℹ️  Push reminders desactivados (VAPID keys no configuradas)');
        return;
    }

    async function checkAndSendReminders() {
        try {
            const now = new Date();
            const nowHHMM = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`;
            const todayStr = now.toISOString().split('T')[0];

            // ── 1. Medicamentos con recordatorio=true y hora próxima (±35 min) ──
            const meds = await pool.query(`
                SELECT m.usuario_id, m.nombre, m.dosis, m.hora_inicio
                FROM medicamentos m
                INNER JOIN push_subscriptions ps ON ps.usuario_id = m.usuario_id
                WHERE m.recordatorio = true
                  AND m.hora_inicio IS NOT NULL
                  AND m.hora_inicio BETWEEN
                      (NOW() AT TIME ZONE 'America/Argentina/Buenos_Aires')::TIME
                      AND ((NOW() AT TIME ZONE 'America/Argentina/Buenos_Aires') + INTERVAL '35 minutes')::TIME
            `);
            for (const med of meds.rows) {
                await sendPushToUser(med.usuario_id, {
                    title: '💊 Recordatorio de medicamento',
                    body: `${med.nombre} — ${med.dosis} a las ${med.hora_inicio}`,
                    tag: `med-${med.usuario_id}-${med.nombre}`,
                    url: '/'
                });
            }

            // ── 2. Citas cuyo recordatorio vence en los próximos 20 minutos ──
            // c.recordatorio = minutos antes de la cita (ej: '30', '60', '1440')
            const citas = await pool.query(`
                SELECT c.usuario_id, c.titulo, c.fecha, c.hora, c.recordatorio, c.lugar
                FROM citas c
                INNER JOIN push_subscriptions ps ON ps.usuario_id = c.usuario_id
                WHERE c.recordatorio IS NOT NULL
                  AND c.recordatorio <> '0'
                  AND c.hora IS NOT NULL
                  AND (c.fecha || ' ' || c.hora)::timestamp AT TIME ZONE 'America/Argentina/Buenos_Aires'
                      - (CAST(c.recordatorio AS integer) * INTERVAL '1 minute')
                      BETWEEN NOW() AND NOW() + INTERVAL '20 minutes'
            `);
            for (const cita of citas.rows) {
                const mins = parseInt(cita.recordatorio);
                const tiempoTexto = mins < 60 ? `en ${mins} min`
                    : mins === 60 ? 'en 1 hora'
                    : mins === 1440 ? 'mañana'
                    : `en ${Math.round(mins / 60)}h`;
                await sendPushToUser(cita.usuario_id, {
                    title: '📅 Recordatorio de cita',
                    body: `${cita.titulo} — ${tiempoTexto}${cita.lugar ? ' en ' + cita.lugar : ''}`,
                    tag: `cita-${cita.usuario_id}-${cita.fecha}-${cita.hora}`,
                    url: '/'
                });
            }

            // ── 3. Tareas pendientes de hoy (aviso a las 8 AM) ──
            if (now.getHours() === 8 && now.getMinutes() < 30) {
                const tareas = await pool.query(`
                    SELECT t.usuario_id, COUNT(*) as pendientes
                    FROM tareas t
                    INNER JOIN push_subscriptions ps ON ps.usuario_id = t.usuario_id
                    WHERE t.completada = false
                      AND t.fecha = $1
                    GROUP BY t.usuario_id
                `, [todayStr]);
                for (const row of tareas.rows) {
                    await sendPushToUser(row.usuario_id, {
                        title: '✓ Tareas pendientes hoy',
                        body: `Tenés ${row.pendientes} tarea${row.pendientes > 1 ? 's' : ''} pendiente${row.pendientes > 1 ? 's' : ''} para hoy`,
                        tag: `tareas-${row.usuario_id}-${todayStr}`,
                        url: '/'
                    });
                }
            }

            console.log(`[Push Reminders] Chequeo completado a las ${nowHHMM}`);
        } catch (err) {
            console.error('[Push Reminders] Error:', err.message);
        }
    }

    checkAndSendReminders(); // correr al arrancar
    setInterval(checkAndSendReminders, 15 * 60 * 1000); // cada 15 minutos
    console.log('✅ Push reminders iniciados (chequeo cada 15 minutos)');
}

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
            auto_recurring: { frequency: 1, frequency_type: 'months', transaction_amount: 4000, currency_id: 'ARS' },
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

app.post('/api/webhook/mercadopago', async (req, res) => {
    try {
        const { type, data } = req.body;
        if (type === 'subscription_preapproval' && data?.id) {
            const mp = await mpRequest(`/preapproval/${data.id}`);
            if (mp.status === 200) {
                const preapproval = mp.body;
                const userId = parseInt(preapproval.external_reference);
                if (userId && !isNaN(userId)) {
                    const isPremium = preapproval.status === 'authorized';
                    await pool.query('UPDATE usuarios SET premium=$1 WHERE id=$2', [isPremium, userId]);
                    console.log(`[MP Webhook] Usuario ${userId} → premium: ${isPremium} (estado: ${preapproval.status})`);
                }
            }
        }
        res.sendStatus(200);
    } catch (err) {
        console.error('[MP Webhook] Error:', err.message);
        res.sendStatus(200);
    }
});

// ========== PERFIL Y USUARIO ==========
app.get('/api/me', authMiddleware, async (req, res) => {
    try {
        const result = await pool.query('SELECT id, nombre, email, premium FROM usuarios WHERE id=$1', [req.user.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json({ usuario: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/api/profile', authMiddleware, async (req, res) => {
    try {
        const { nombre, email, password } = req.body;
        if (!nombre || !email) return res.status(400).json({ error: 'Nombre y email son requeridos' });
        const existing = await pool.query('SELECT id FROM usuarios WHERE email=$1 AND id!=$2', [email, req.user.id]);
        if (existing.rows.length > 0) return res.status(400).json({ error: 'El email ya está en uso por otra cuenta' });
        let result;
        if (password) {
            const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
            result = await pool.query(
                'UPDATE usuarios SET nombre=$1, email=$2, password_hash=$3 WHERE id=$4 RETURNING id, nombre, email, premium',
                [nombre, email, password_hash, req.user.id]
            );
        } else {
            result = await pool.query(
                'UPDATE usuarios SET nombre=$1, email=$2 WHERE id=$3 RETURNING id, nombre, email, premium',
                [nombre, email, req.user.id]
            );
        }
        res.json({ mensaje: 'Perfil actualizado', usuario: result.rows[0] });
    } catch (err) {
        console.error('Error actualizando perfil:', err);
        res.status(500).json({ error: err.message });
    }
});

// ========== PAYPAL ==========
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

// ========== INICIAR SERVIDOR ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
    console.log(`✅ Servidor escuchando en puerto ${PORT}`);
    console.log(`📍 http://localhost:${PORT}`);
    console.log(`💳 PayPal mode: ${PAYPAL_MODE}`);
    await runMigrations();
    startPushReminders(); // ← NUEVO: arranca el chequeo periódico de push
});
