const express = require('express');
const app = express();
const pool = require('./db');
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'tu_clave_secreta';
const cors = require('cors');

// ========== CONFIGURACIÓN ==========
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

// ========== MIGRACIÓN AUTOMÁTICA ==========
async function runMigrations() {
  try {
    console.log('🔄 Ejecutando migraciones...');

    // Renombrar columna nombre → tipo en sintomas (si todavía se llama nombre)
    await pool.query(`
      DO $$ BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_name='sintomas' AND column_name='nombre'
        ) THEN
          ALTER TABLE sintomas RENAME COLUMN nombre TO tipo;
        END IF;
      END $$;
    `);

    // Agregar columnas faltantes en tareas
    await pool.query(`ALTER TABLE tareas ADD COLUMN IF NOT EXISTS descripcion TEXT`);
    await pool.query(`ALTER TABLE tareas ADD COLUMN IF NOT EXISTS recordatorio BOOLEAN DEFAULT FALSE`);
    await pool.query(`ALTER TABLE tareas ADD COLUMN IF NOT EXISTS hasta_fecha DATE`);

    // Agregar columna faltante en medicamentos
    await pool.query(`ALTER TABLE medicamentos ADD COLUMN IF NOT EXISTS horarios_custom TEXT`);

    // Crear tabla signos_vitales (reemplaza localStorage)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS signos_vitales (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
        tipo VARCHAR(50) NOT NULL,
        valor DECIMAL(10,2),
        sistolica INTEGER,
        diastolica INTEGER,
        notas TEXT,
        fecha TIMESTAMP NOT NULL DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    // Crear tabla historial_medicamentos (reemplaza localStorage)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS historial_medicamentos (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id) ON DELETE CASCADE,
        medicamento_id INTEGER,
        medicamento_nombre VARCHAR(255) NOT NULL,
        dosis VARCHAR(255),
        notas TEXT,
        fecha TIMESTAMP NOT NULL DEFAULT NOW(),
        created_at TIMESTAMP DEFAULT NOW()
      )
    `);

    console.log('✅ Migraciones completadas');
  } catch (err) {
    console.error('❌ Error en migraciones:', err.message);
  }
}

runMigrations();

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

// ========== MEDICAMENTOS ==========
app.post('/api/medicamentos', authMiddleware, async (req, res) => {
  // Acepta tanto camelCase (frontend) como snake_case
  const { nombre, dosis, frecuencia, horaInicio, hora_inicio, recordatorio, notas, horariosCustom, horarios_custom } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO medicamentos (usuario_id, nombre, dosis, frecuencia, hora_inicio, recordatorio, notas, horarios_custom) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [usuario_id, nombre, dosis, frecuencia,
        horaInicio || hora_inicio || null,
        recordatorio || false,
        notas || null,
        horariosCustom || horarios_custom || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/medicamentos', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM medicamentos WHERE usuario_id = $1 ORDER BY id DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/medicamentos/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM medicamentos WHERE id = $1 AND usuario_id = $2',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Medicamento no encontrado' });
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
      [nombre, dosis, frecuencia,
        horaInicio || hora_inicio || null,
        recordatorio,
        notas || null,
        horariosCustom || horarios_custom || null,
        req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Medicamento no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/medicamentos/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM medicamentos WHERE id=$1 AND usuario_id=$2 RETURNING *',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Medicamento no encontrado' });
    res.json({ message: 'Medicamento eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== CITAS ==========
app.post('/api/citas', authMiddleware, async (req, res) => {
  const { tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO citas (usuario_id, tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [usuario_id, tipo, titulo, fecha, hora, lugar || null, profesional || null, notas || null, recordatorio || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/citas', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM citas WHERE usuario_id=$1 ORDER BY fecha DESC, hora DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/citas/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM citas WHERE id=$1 AND usuario_id=$2',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Cita no encontrada' });
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
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Cita no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/citas/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM citas WHERE id=$1 AND usuario_id=$2 RETURNING *',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Cita no encontrada' });
    res.json({ message: 'Cita eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== TAREAS ==========
app.post('/api/tareas', authMiddleware, async (req, res) => {
  const { titulo, categoria, fecha, hora, frecuencia, completada, descripcion, recordatorio, hastaFecha, hasta_fecha } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO tareas (usuario_id, titulo, categoria, fecha, hora, frecuencia, completada, descripcion, recordatorio, hasta_fecha) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
      [usuario_id, titulo, categoria, fecha, hora || null, frecuencia, completada || false,
        descripcion || null, recordatorio || false, hastaFecha || hasta_fecha || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tareas', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tareas WHERE usuario_id=$1 ORDER BY fecha ASC, hora ASC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tareas/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tareas WHERE id=$1 AND usuario_id=$2',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Tarea no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT con actualización parcial: solo se sobreescriben los campos que vienen en el body
app.put('/api/tareas/:id', authMiddleware, async (req, res) => {
  try {
    // Obtener datos actuales para no pisar campos con null
    const current = await pool.query(
      'SELECT * FROM tareas WHERE id=$1 AND usuario_id=$2',
      [req.params.id, req.user.id]
    );
    if (current.rows.length === 0)
      return res.status(404).json({ error: 'Tarea no encontrada' });

    const t = current.rows[0];
    const b = req.body;

    const result = await pool.query(
      'UPDATE tareas SET titulo=$1, categoria=$2, fecha=$3, hora=$4, frecuencia=$5, completada=$6, descripcion=$7, recordatorio=$8, hasta_fecha=$9 WHERE id=$10 AND usuario_id=$11 RETURNING *',
      [
        b.titulo     !== undefined ? b.titulo     : t.titulo,
        b.categoria  !== undefined ? b.categoria  : t.categoria,
        b.fecha      !== undefined ? b.fecha      : t.fecha,
        b.hora       !== undefined ? (b.hora || null) : t.hora,
        b.frecuencia !== undefined ? b.frecuencia : t.frecuencia,
        b.completada !== undefined ? b.completada : t.completada,
        b.descripcion !== undefined ? (b.descripcion || null) : t.descripcion,
        b.recordatorio !== undefined ? b.recordatorio : t.recordatorio,
        b.hastaFecha !== undefined ? (b.hastaFecha || null)
          : b.hasta_fecha !== undefined ? (b.hasta_fecha || null)
          : t.hasta_fecha,
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
    const result = await pool.query(
      'DELETE FROM tareas WHERE id=$1 AND usuario_id=$2 RETURNING *',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Tarea no encontrada' });
    res.json({ message: 'Tarea eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== SÍNTOMAS ==========
app.post('/api/sintomas', authMiddleware, async (req, res) => {
  // Acepta tipo (frontend) y estadoAnimo (camelCase del frontend)
  const { tipo, nombre, intensidad, estadoAnimo, estado_animo, descripcion, fecha } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO sintomas (usuario_id, tipo, intensidad, estado_animo, descripcion, fecha) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [usuario_id, tipo || nombre, intensidad,
        estadoAnimo || estado_animo || null,
        descripcion || null,
        fecha ? new Date(fecha) : new Date()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sintomas', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM sintomas WHERE usuario_id=$1 ORDER BY fecha DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sintomas/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM sintomas WHERE id=$1 AND usuario_id=$2',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Síntoma no encontrado' });
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
      [tipo || nombre, intensidad,
        estadoAnimo || estado_animo || null,
        descripcion || null,
        fecha ? new Date(fecha) : new Date(),
        req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Síntoma no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/sintomas/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM sintomas WHERE id=$1 AND usuario_id=$2 RETURNING *',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Síntoma no encontrado' });
    res.json({ message: 'Síntoma eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== CONTACTOS ==========
app.post('/api/contactos', authMiddleware, async (req, res) => {
  const { nombre, categoria, especialidad, telefono, email, direccion, notas } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO contactos (usuario_id, nombre, categoria, especialidad, telefono, email, direccion, notas) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [usuario_id, nombre, categoria, especialidad || null, telefono, email || null, direccion || null, notas || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/contactos', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM contactos WHERE usuario_id=$1 ORDER BY nombre ASC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/contactos/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM contactos WHERE id=$1 AND usuario_id=$2',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Contacto no encontrado' });
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
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Contacto no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/contactos/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM contactos WHERE id=$1 AND usuario_id=$2 RETURNING *',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Contacto no encontrado' });
    res.json({ message: 'Contacto eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== SIGNOS VITALES ==========
app.post('/api/signos-vitales', authMiddleware, async (req, res) => {
  const { tipo, valor, sistolica, diastolica, notas, fecha } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO signos_vitales (usuario_id, tipo, valor, sistolica, diastolica, notas, fecha) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [usuario_id, tipo, valor || null, sistolica || null, diastolica || null, notas || null, fecha ? new Date(fecha) : new Date()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/signos-vitales', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM signos_vitales WHERE usuario_id=$1 ORDER BY fecha DESC',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/signos-vitales/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM signos_vitales WHERE id=$1 AND usuario_id=$2 RETURNING *',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Signo vital no encontrado' });
    res.json({ message: 'Signo vital eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== HISTORIAL MEDICAMENTOS ==========
app.post('/api/historial-medicamentos', authMiddleware, async (req, res) => {
  const { medicamento_id, medicamentoId, medicamento_nombre, medicamentoNombre, dosis, notas, fecha } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO historial_medicamentos (usuario_id, medicamento_id, medicamento_nombre, dosis, notas, fecha) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
      [usuario_id,
        medicamento_id || medicamentoId || null,
        medicamento_nombre || medicamentoNombre,
        dosis || null,
        notas || null,
        fecha ? new Date(fecha) : new Date()]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/historial-medicamentos', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM historial_medicamentos WHERE usuario_id=$1 ORDER BY fecha DESC LIMIT 100',
      [req.user.id]
    );
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/historial-medicamentos/:id', authMiddleware, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM historial_medicamentos WHERE id=$1 AND usuario_id=$2 RETURNING *',
      [req.params.id, req.user.id]
    );
    if (result.rows.length === 0)
      return res.status(404).json({ error: 'Registro no encontrado' });
    res.json({ message: 'Registro eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ========== INICIAR SERVIDOR ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Servidor escuchando en puerto ${PORT}`);
  console.log(`📍 http://localhost:${PORT}`);
});
