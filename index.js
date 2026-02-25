/**
 * index.js — Backend completo de CuidaDiario
 * by EDEN SoftWork
 *
 * PEGAR ESTO EN Railway → tu proyecto → index.js
 *
 * Variables de entorno necesarias en Railway:
 *   DATABASE_URL       → PostgreSQL connection string (ya existente)
 *   JWT_SECRET         → secreto para JWT (ya existente)
 *   PAYPAL_CLIENT_ID   → tu Client ID de PayPal (live o sandbox)
 *   PAYPAL_CLIENT_SECRET → tu Client Secret de PayPal
 *   PAYPAL_MODE        → "sandbox" o "live" (por defecto "sandbox")
 *
 * Cambios respecto a la versión anterior:
 *   1. Migración automática: agrega columna paypal_subscription_id si no existe
 *   2. POST /api/paypal/activate-subscription  → guarda subscriptionID en DB
 *   3. POST /api/paypal/webhook                → escucha cancelaciones de PayPal y baja premium
 *   4. GET  /api/me                            → devuelve el usuario actualizado (incluye premium)
 */

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== CONFIGURACIÓN ====================

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

const PAYPAL_MODE = process.env.PAYPAL_MODE || 'sandbox';
const PAYPAL_HOST = PAYPAL_MODE === 'live'
    ? 'api-m.paypal.com'
    : 'api-m.sandbox.paypal.com';

app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// IMPORTANTE: para el webhook de PayPal, necesitamos el raw body
// Registrar primero el endpoint del webhook con rawBody, luego usar express.json()
app.use('/api/paypal/webhook', express.raw({ type: 'application/json' }));
app.use(express.json());

// ==================== MIGRACIÓN AUTOMÁTICA ====================

async function runMigrations() {
    const client = await pool.connect();
    try {
        // Tabla usuarios
        await client.query(`
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                nombre VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                premium BOOLEAN DEFAULT FALSE,
                paypal_subscription_id VARCHAR(64),
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Agregar columna si no existe (idempotente)
        await client.query(`
            ALTER TABLE usuarios
            ADD COLUMN IF NOT EXISTS paypal_subscription_id VARCHAR(64)
        `);

        // Tabla pacientes
        await client.query(`
            CREATE TABLE IF NOT EXISTS pacientes (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                nombre VARCHAR(150) NOT NULL,
                relacion VARCHAR(100),
                fecha_nacimiento DATE,
                notas TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Tabla medicamentos
        await client.query(`
            CREATE TABLE IF NOT EXISTS medicamentos (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                paciente_id INTEGER REFERENCES pacientes(id) ON DELETE SET NULL,
                nombre VARCHAR(150) NOT NULL,
                dosis VARCHAR(100),
                frecuencia VARCHAR(50),
                hora_inicio VARCHAR(10),
                horarios_custom TEXT,
                notas TEXT,
                recordatorio BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Tabla citas
        await client.query(`
            CREATE TABLE IF NOT EXISTS citas (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                paciente_id INTEGER REFERENCES pacientes(id) ON DELETE SET NULL,
                tipo VARCHAR(50),
                titulo VARCHAR(200) NOT NULL,
                fecha DATE NOT NULL,
                hora VARCHAR(10),
                lugar VARCHAR(200),
                profesional VARCHAR(150),
                notas TEXT,
                recordatorio INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Tabla tareas
        await client.query(`
            CREATE TABLE IF NOT EXISTS tareas (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                paciente_id INTEGER REFERENCES pacientes(id) ON DELETE SET NULL,
                titulo VARCHAR(200) NOT NULL,
                categoria VARCHAR(50),
                frecuencia VARCHAR(50),
                fecha DATE,
                hora VARCHAR(10),
                hasta_fecha DATE,
                descripcion TEXT,
                recordatorio BOOLEAN DEFAULT FALSE,
                completada BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Tabla síntomas
        await client.query(`
            CREATE TABLE IF NOT EXISTS sintomas (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                paciente_id INTEGER REFERENCES pacientes(id) ON DELETE SET NULL,
                tipo VARCHAR(100),
                intensidad INTEGER,
                estado_animo VARCHAR(50),
                descripcion TEXT,
                fecha TIMESTAMP DEFAULT NOW()
            )
        `);

        // Tabla contactos
        await client.query(`
            CREATE TABLE IF NOT EXISTS contactos (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                nombre VARCHAR(150) NOT NULL,
                categoria VARCHAR(50),
                especialidad VARCHAR(100),
                telefono VARCHAR(30) NOT NULL,
                email VARCHAR(150),
                direccion TEXT,
                notas TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        `);

        // Tabla signos vitales
        await client.query(`
            CREATE TABLE IF NOT EXISTS signos_vitales (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                paciente_id INTEGER REFERENCES pacientes(id) ON DELETE SET NULL,
                tipo VARCHAR(50),
                valor NUMERIC,
                sistolica INTEGER,
                diastolica INTEGER,
                notas TEXT,
                fecha TIMESTAMP DEFAULT NOW()
            )
        `);

        // Tabla historial medicamentos
        await client.query(`
            CREATE TABLE IF NOT EXISTS historial_medicamentos (
                id SERIAL PRIMARY KEY,
                usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
                medicamento_id INTEGER REFERENCES medicamentos(id) ON DELETE SET NULL,
                medicamento_nombre VARCHAR(150),
                dosis VARCHAR(100),
                notas TEXT,
                fecha TIMESTAMP DEFAULT NOW()
            )
        `);

        console.log('✅ Migraciones completadas');
    } catch (err) {
        console.error('❌ Error en migraciones:', err.message);
    } finally {
        client.release();
    }
}

// ==================== MIDDLEWARE AUTH ====================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Token requerido' });

    jwt.verify(token, process.env.JWT_SECRET || 'secreto_default', (err, user) => {
        if (err) return res.status(401).json({ error: 'Token inválido' });
        req.user = user;
        next();
    });
}

// ==================== HELPERS PAYPAL ====================

async function getPayPalAccessToken() {
    return new Promise((resolve, reject) => {
        const credentials = Buffer.from(
            `${process.env.PAYPAL_CLIENT_ID}:${process.env.PAYPAL_CLIENT_SECRET}`
        ).toString('base64');

        const body = 'grant_type=client_credentials';
        const options = {
            hostname: PAYPAL_HOST,
            path: '/v1/oauth2/token',
            method: 'POST',
            headers: {
                'Authorization': `Basic ${credentials}`,
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(body)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const parsed = JSON.parse(data);
                    resolve(parsed.access_token);
                } catch (e) {
                    reject(e);
                }
            });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
    });
}

async function getSubscriptionDetails(subscriptionId, accessToken) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: PAYPAL_HOST,
            path: `/v1/billing/subscriptions/${subscriptionId}`,
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    reject(e);
                }
            });
        });
        req.on('error', reject);
        req.end();
    });
}

// ==================== RUTAS DE AUTENTICACIÓN ====================

app.post('/api/register', async (req, res) => {
    const { nombre, email, password } = req.body;
    if (!nombre || !email || !password) {
        return res.status(400).json({ error: 'Todos los campos son requeridos' });
    }

    try {
        const existing = await pool.query('SELECT id FROM usuarios WHERE email = $1', [email]);
        if (existing.rows.length > 0) {
            return res.status(400).json({ error: 'El email ya está registrado' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO usuarios (nombre, email, password) VALUES ($1, $2, $3) RETURNING id, nombre, email, premium',
            [nombre, email, hashedPassword]
        );

        const usuario = result.rows[0];
        const token = jwt.sign(
            { id: usuario.id, email: usuario.email },
            process.env.JWT_SECRET || 'secreto_default',
            { expiresIn: '30d' }
        );

        res.status(201).json({ token, usuario });
    } catch (err) {
        console.error('Error en registro:', err);
        res.status(500).json({ error: 'Error al registrar usuario' });
    }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email y contraseña requeridos' });
    }

    try {
        const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }

        const usuario = result.rows[0];
        const validPassword = await bcrypt.compare(password, usuario.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Credenciales incorrectas' });
        }

        const token = jwt.sign(
            { id: usuario.id, email: usuario.email },
            process.env.JWT_SECRET || 'secreto_default',
            { expiresIn: '30d' }
        );

        res.json({
            token,
            usuario: {
                id: usuario.id,
                nombre: usuario.nombre,
                email: usuario.email,
                premium: usuario.premium
            }
        });
    } catch (err) {
        console.error('Error en login:', err);
        res.status(500).json({ error: 'Error al iniciar sesión' });
    }
});

// GET /api/me — devuelve el usuario autenticado actualizado
app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, nombre, email, premium FROM usuarios WHERE id = $1',
            [req.user.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }
        res.json({ usuario: result.rows[0] });
    } catch (err) {
        console.error('Error en /api/me:', err);
        res.status(500).json({ error: 'Error al obtener usuario' });
    }
});

// ==================== PAYPAL ====================

// Activar suscripción y guardar subscriptionID
app.post('/api/paypal/activate-subscription', authenticateToken, async (req, res) => {
    const { subscriptionID } = req.body;
    if (!subscriptionID) {
        return res.status(400).json({ error: 'subscriptionID requerido' });
    }

    try {
        // Verificar con PayPal que la suscripción es válida
        const accessToken = await getPayPalAccessToken();
        const subscription = await getSubscriptionDetails(subscriptionID, accessToken);

        if (!['ACTIVE', 'APPROVED'].includes(subscription.status)) {
            return res.status(400).json({
                error: `Suscripción no activa. Estado: ${subscription.status}`
            });
        }

        // Guardar subscriptionID y activar premium
        await pool.query(
            'UPDATE usuarios SET premium = TRUE, paypal_subscription_id = $1 WHERE id = $2',
            [subscriptionID, req.user.id]
        );

        console.log(`✅ Premium activado para usuario ${req.user.id} (sub: ${subscriptionID})`);
        res.json({ success: true, message: 'Premium activado correctamente' });
    } catch (err) {
        console.error('Error al activar suscripción:', err);
        res.status(500).json({ error: 'Error al activar suscripción' });
    }
});

// Webhook de PayPal — maneja cancelaciones automáticas
app.post('/api/paypal/webhook', async (req, res) => {
    try {
        // PayPal envía raw body, parsear manualmente
        const rawBody = req.body;
        const event = JSON.parse(
            Buffer.isBuffer(rawBody) ? rawBody.toString() : rawBody
        );

        console.log('🔔 PayPal webhook recibido:', event.event_type, event.id);

        const CANCEL_EVENTS = [
            'BILLING.SUBSCRIPTION.CANCELLED',
            'BILLING.SUBSCRIPTION.SUSPENDED',
            'BILLING.SUBSCRIPTION.EXPIRED'
        ];

        if (CANCEL_EVENTS.includes(event.event_type)) {
            const subscriptionId = event.resource?.id;
            if (!subscriptionId) {
                console.warn('⚠️ Webhook sin subscription ID');
                return res.status(200).json({ received: true });
            }

            // Buscar usuario por subscriptionID y bajar premium
            const result = await pool.query(
                'UPDATE usuarios SET premium = FALSE WHERE paypal_subscription_id = $1 RETURNING id, email',
                [subscriptionId]
            );

            if (result.rows.length > 0) {
                console.log(`🔻 Premium desactivado para usuario ${result.rows[0].id} (${result.rows[0].email}) — ${event.event_type}`);
            } else {
                console.warn(`⚠️ Ningún usuario encontrado para subscription ${subscriptionId}`);
            }
        }

        // Siempre responder 200 a PayPal para confirmar recepción
        res.status(200).json({ received: true });
    } catch (err) {
        console.error('Error procesando webhook:', err);
        // Aún así responder 200 para evitar que PayPal reintente indefinidamente
        res.status(200).json({ received: true });
    }
});

// ==================== PACIENTES ====================

app.get('/api/pacientes', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM pacientes WHERE usuario_id = $1 ORDER BY created_at ASC',
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener pacientes:', err);
        res.status(500).json({ error: 'Error al obtener pacientes' });
    }
});

app.post('/api/pacientes', authenticateToken, async (req, res) => {
    const { nombre, relacion, fecha_nacimiento, notas } = req.body;
    if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });

    try {
        // Verificar límite para usuarios free (máx 1 paciente)
        const userResult = await pool.query('SELECT premium FROM usuarios WHERE id = $1', [req.user.id]);
        const isPremium = userResult.rows[0]?.premium;

        if (!isPremium) {
            const countResult = await pool.query(
                'SELECT COUNT(*) FROM pacientes WHERE usuario_id = $1',
                [req.user.id]
            );
            if (parseInt(countResult.rows[0].count) >= 1) {
                return res.status(403).json({ error: 'Plan gratuito: solo 1 paciente. Actualiza a Premium.' });
            }
        }

        const result = await pool.query(
            'INSERT INTO pacientes (usuario_id, nombre, relacion, fecha_nacimiento, notas) VALUES ($1, $2, $3, $4, $5) RETURNING *',
            [req.user.id, nombre, relacion || null, fecha_nacimiento || null, notas || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear paciente:', err);
        res.status(500).json({ error: 'Error al crear paciente' });
    }
});

app.put('/api/pacientes/:id', authenticateToken, async (req, res) => {
    const { nombre, relacion, fecha_nacimiento, notas } = req.body;
    try {
        const result = await pool.query(
            'UPDATE pacientes SET nombre=$1, relacion=$2, fecha_nacimiento=$3, notas=$4 WHERE id=$5 AND usuario_id=$6 RETURNING *',
            [nombre, relacion || null, fecha_nacimiento || null, notas || null, req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Paciente no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error al actualizar paciente:', err);
        res.status(500).json({ error: 'Error al actualizar paciente' });
    }
});

app.delete('/api/pacientes/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM pacientes WHERE id=$1 AND usuario_id=$2 RETURNING id',
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Paciente no encontrado' });
        res.json({ success: true });
    } catch (err) {
        console.error('Error al eliminar paciente:', err);
        res.status(500).json({ error: 'Error al eliminar paciente' });
    }
});

// ==================== MEDICAMENTOS ====================

app.get('/api/medicamentos', authenticateToken, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = 'SELECT * FROM medicamentos WHERE usuario_id = $1';
        const params = [req.user.id];
        if (paciente_id) {
            query += ' AND paciente_id = $2';
            params.push(paciente_id);
        }
        query += ' ORDER BY created_at ASC';
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener medicamentos:', err);
        res.status(500).json({ error: 'Error al obtener medicamentos' });
    }
});

app.post('/api/medicamentos', authenticateToken, async (req, res) => {
    const { nombre, dosis, frecuencia, horaInicio, hora_inicio, horariosCustom, horarios_custom, notas, recordatorio, paciente_id } = req.body;
    if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });

    try {
        const result = await pool.query(
            `INSERT INTO medicamentos (usuario_id, paciente_id, nombre, dosis, frecuencia, hora_inicio, horarios_custom, notas, recordatorio)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
            [req.user.id, paciente_id || null, nombre, dosis || null, frecuencia || null,
             horaInicio || hora_inicio || null, horariosCustom || horarios_custom || null,
             notas || null, recordatorio || false]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear medicamento:', err);
        res.status(500).json({ error: 'Error al crear medicamento' });
    }
});

app.put('/api/medicamentos/:id', authenticateToken, async (req, res) => {
    const { nombre, dosis, frecuencia, horaInicio, hora_inicio, horariosCustom, horarios_custom, notas, recordatorio } = req.body;
    try {
        const result = await pool.query(
            `UPDATE medicamentos SET nombre=$1, dosis=$2, frecuencia=$3, hora_inicio=$4, horarios_custom=$5, notas=$6, recordatorio=$7
             WHERE id=$8 AND usuario_id=$9 RETURNING *`,
            [nombre, dosis || null, frecuencia || null, horaInicio || hora_inicio || null,
             horariosCustom || horarios_custom || null, notas || null, recordatorio || false,
             req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Medicamento no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error al actualizar medicamento:', err);
        res.status(500).json({ error: 'Error al actualizar medicamento' });
    }
});

app.delete('/api/medicamentos/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM medicamentos WHERE id=$1 AND usuario_id=$2 RETURNING id',
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Medicamento no encontrado' });
        res.json({ success: true });
    } catch (err) {
        console.error('Error al eliminar medicamento:', err);
        res.status(500).json({ error: 'Error al eliminar medicamento' });
    }
});

// ==================== CITAS ====================

app.get('/api/citas', authenticateToken, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = 'SELECT * FROM citas WHERE usuario_id = $1';
        const params = [req.user.id];
        if (paciente_id) {
            query += ' AND paciente_id = $2';
            params.push(paciente_id);
        }
        query += ' ORDER BY fecha ASC, hora ASC';
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener citas:', err);
        res.status(500).json({ error: 'Error al obtener citas' });
    }
});

app.post('/api/citas', authenticateToken, async (req, res) => {
    const { tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio, paciente_id } = req.body;
    if (!titulo || !fecha) return res.status(400).json({ error: 'Título y fecha requeridos' });

    try {
        const result = await pool.query(
            `INSERT INTO citas (usuario_id, paciente_id, tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
            [req.user.id, paciente_id || null, tipo || null, titulo, fecha, hora || null,
             lugar || null, profesional || null, notas || null, recordatorio || 0]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear cita:', err);
        res.status(500).json({ error: 'Error al crear cita' });
    }
});

app.put('/api/citas/:id', authenticateToken, async (req, res) => {
    const { tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio } = req.body;
    try {
        const result = await pool.query(
            `UPDATE citas SET tipo=$1, titulo=$2, fecha=$3, hora=$4, lugar=$5, profesional=$6, notas=$7, recordatorio=$8
             WHERE id=$9 AND usuario_id=$10 RETURNING *`,
            [tipo || null, titulo, fecha, hora || null, lugar || null, profesional || null,
             notas || null, recordatorio || 0, req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error al actualizar cita:', err);
        res.status(500).json({ error: 'Error al actualizar cita' });
    }
});

app.delete('/api/citas/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM citas WHERE id=$1 AND usuario_id=$2 RETURNING id',
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada' });
        res.json({ success: true });
    } catch (err) {
        console.error('Error al eliminar cita:', err);
        res.status(500).json({ error: 'Error al eliminar cita' });
    }
});

// ==================== TAREAS ====================

app.get('/api/tareas', authenticateToken, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = 'SELECT * FROM tareas WHERE usuario_id = $1';
        const params = [req.user.id];
        if (paciente_id) {
            query += ' AND paciente_id = $2';
            params.push(paciente_id);
        }
        query += ' ORDER BY fecha ASC NULLS LAST, hora ASC NULLS LAST';
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener tareas:', err);
        res.status(500).json({ error: 'Error al obtener tareas' });
    }
});

app.post('/api/tareas', authenticateToken, async (req, res) => {
    const { titulo, categoria, frecuencia, fecha, hora, hastaFecha, hasta_fecha, descripcion, recordatorio, paciente_id } = req.body;
    if (!titulo) return res.status(400).json({ error: 'Título requerido' });

    try {
        const result = await pool.query(
            `INSERT INTO tareas (usuario_id, paciente_id, titulo, categoria, frecuencia, fecha, hora, hasta_fecha, descripcion, recordatorio)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *`,
            [req.user.id, paciente_id || null, titulo, categoria || null, frecuencia || null,
             fecha || null, hora || null, hastaFecha || hasta_fecha || null,
             descripcion || null, recordatorio || false]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear tarea:', err);
        res.status(500).json({ error: 'Error al crear tarea' });
    }
});

app.put('/api/tareas/:id', authenticateToken, async (req, res) => {
    const { titulo, categoria, frecuencia, fecha, hora, hastaFecha, hasta_fecha, descripcion, recordatorio, completada } = req.body;
    try {
        const result = await pool.query(
            `UPDATE tareas SET titulo=$1, categoria=$2, frecuencia=$3, fecha=$4, hora=$5,
             hasta_fecha=$6, descripcion=$7, recordatorio=$8, completada=$9
             WHERE id=$10 AND usuario_id=$11 RETURNING *`,
            [titulo, categoria || null, frecuencia || null, fecha || null, hora || null,
             hastaFecha || hasta_fecha || null, descripcion || null,
             recordatorio || false, completada || false, req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error al actualizar tarea:', err);
        res.status(500).json({ error: 'Error al actualizar tarea' });
    }
});

app.delete('/api/tareas/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM tareas WHERE id=$1 AND usuario_id=$2 RETURNING id',
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
        res.json({ success: true });
    } catch (err) {
        console.error('Error al eliminar tarea:', err);
        res.status(500).json({ error: 'Error al eliminar tarea' });
    }
});

// ==================== SÍNTOMAS ====================

app.get('/api/sintomas', authenticateToken, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = 'SELECT * FROM sintomas WHERE usuario_id = $1';
        const params = [req.user.id];
        if (paciente_id) {
            query += ' AND paciente_id = $2';
            params.push(paciente_id);
        }
        query += ' ORDER BY fecha DESC';
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener síntomas:', err);
        res.status(500).json({ error: 'Error al obtener síntomas' });
    }
});

app.post('/api/sintomas', authenticateToken, async (req, res) => {
    const { tipo, intensidad, estadoAnimo, estado_animo, descripcion, fecha, paciente_id } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO sintomas (usuario_id, paciente_id, tipo, intensidad, estado_animo, descripcion, fecha)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
            [req.user.id, paciente_id || null, tipo || null, intensidad || null,
             estadoAnimo || estado_animo || null, descripcion || null,
             fecha || new Date().toISOString()]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear síntoma:', err);
        res.status(500).json({ error: 'Error al crear síntoma' });
    }
});

app.delete('/api/sintomas/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM sintomas WHERE id=$1 AND usuario_id=$2 RETURNING id',
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Síntoma no encontrado' });
        res.json({ success: true });
    } catch (err) {
        console.error('Error al eliminar síntoma:', err);
        res.status(500).json({ error: 'Error al eliminar síntoma' });
    }
});

// ==================== CONTACTOS ====================

app.get('/api/contactos', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM contactos WHERE usuario_id = $1 ORDER BY nombre ASC',
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener contactos:', err);
        res.status(500).json({ error: 'Error al obtener contactos' });
    }
});

app.post('/api/contactos', authenticateToken, async (req, res) => {
    const { nombre, categoria, especialidad, telefono, email, direccion, notas } = req.body;
    if (!nombre || !telefono) return res.status(400).json({ error: 'Nombre y teléfono requeridos' });

    try {
        const result = await pool.query(
            `INSERT INTO contactos (usuario_id, nombre, categoria, especialidad, telefono, email, direccion, notas)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [req.user.id, nombre, categoria || null, especialidad || null,
             telefono, email || null, direccion || null, notas || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear contacto:', err);
        res.status(500).json({ error: 'Error al crear contacto' });
    }
});

app.put('/api/contactos/:id', authenticateToken, async (req, res) => {
    const { nombre, categoria, especialidad, telefono, email, direccion, notas } = req.body;
    try {
        const result = await pool.query(
            `UPDATE contactos SET nombre=$1, categoria=$2, especialidad=$3, telefono=$4, email=$5, direccion=$6, notas=$7
             WHERE id=$8 AND usuario_id=$9 RETURNING *`,
            [nombre, categoria || null, especialidad || null, telefono,
             email || null, direccion || null, notas || null, req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Contacto no encontrado' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error al actualizar contacto:', err);
        res.status(500).json({ error: 'Error al actualizar contacto' });
    }
});

app.delete('/api/contactos/:id', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'DELETE FROM contactos WHERE id=$1 AND usuario_id=$2 RETURNING id',
            [req.params.id, req.user.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Contacto no encontrado' });
        res.json({ success: true });
    } catch (err) {
        console.error('Error al eliminar contacto:', err);
        res.status(500).json({ error: 'Error al eliminar contacto' });
    }
});

// ==================== SIGNOS VITALES ====================

app.get('/api/signos-vitales', authenticateToken, async (req, res) => {
    try {
        const { paciente_id } = req.query;
        let query = 'SELECT * FROM signos_vitales WHERE usuario_id = $1';
        const params = [req.user.id];
        if (paciente_id) {
            query += ' AND paciente_id = $2';
            params.push(paciente_id);
        }
        query += ' ORDER BY fecha DESC';
        const result = await pool.query(query, params);
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener signos vitales:', err);
        res.status(500).json({ error: 'Error al obtener signos vitales' });
    }
});

app.post('/api/signos-vitales', authenticateToken, async (req, res) => {
    const { tipo, valor, sistolica, diastolica, notas, fecha, paciente_id } = req.body;
    if (!tipo) return res.status(400).json({ error: 'Tipo requerido' });

    try {
        const result = await pool.query(
            `INSERT INTO signos_vitales (usuario_id, paciente_id, tipo, valor, sistolica, diastolica, notas, fecha)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
            [req.user.id, paciente_id || null, tipo, valor || null, sistolica || null,
             diastolica || null, notas || null, fecha || new Date().toISOString()]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear signo vital:', err);
        res.status(500).json({ error: 'Error al crear signo vital' });
    }
});

// ==================== HISTORIAL MEDICAMENTOS ====================

app.get('/api/historial-medicamentos', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT hm.*, m.nombre as medicamento_nombre_actual
             FROM historial_medicamentos hm
             LEFT JOIN medicamentos m ON hm.medicamento_id = m.id
             WHERE hm.usuario_id = $1
             ORDER BY hm.fecha DESC
             LIMIT 100`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error('Error al obtener historial:', err);
        res.status(500).json({ error: 'Error al obtener historial' });
    }
});

app.post('/api/historial-medicamentos', authenticateToken, async (req, res) => {
    const { medicamentoId, medicamento_id, medicamentoNombre, medicamento_nombre, dosis, notas } = req.body;
    try {
        const result = await pool.query(
            `INSERT INTO historial_medicamentos (usuario_id, medicamento_id, medicamento_nombre, dosis, notas)
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [req.user.id, medicamentoId || medicamento_id || null,
             medicamentoNombre || medicamento_nombre || null,
             dosis || null, notas || null]
        );
        res.status(201).json(result.rows[0]);
    } catch (err) {
        console.error('Error al crear historial:', err);
        res.status(500).json({ error: 'Error al crear historial' });
    }
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        environment: PAYPAL_MODE
    });
});

app.get('/', (req, res) => {
    res.json({ message: 'CuidaDiario API funcionando ✅', version: '2.0' });
});

// ==================== INICIO ====================

runMigrations().then(() => {
    app.listen(PORT, () => {
        console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
        console.log(`💳 PayPal mode: ${PAYPAL_MODE}`);
    });
});
