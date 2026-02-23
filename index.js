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

// Helper: parsea paciente_id de query o body, devuelve número o null
function parsePacienteId(req) {
  const v = req.query.paciente_id || req.body?.paciente_id || req.body?.pacienteId;
  return v ? parseInt(v) : null;
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

// ========== PACIENTES (NUEVO) ==========

// GET /api/pacientes — listar todos los pacientes del usuario
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

// POST /api/pacientes — crear paciente (máx 1 en free, ilimitado en premium)
app.post('/api/pacientes', authMiddleware, async (req, res) => {
  const { nombre, relacion, fecha_nacimiento, fechaNacimiento, notas } = req.body;
  if (!nombre) return res.status(400).json({ error: 'El nombre es requerido' });
  try {
    // Verificar límite para usuarios free
    const userResult = await pool.query('SELECT premium FROM usuarios WHERE id=$1', [req.user.id]);
    const isPremium = userResult.rows[0]?.premium || false;

    if (!isPremium) {
      const count = await pool.query(
        'SELECT COUNT(*) FROM pacientes WHERE usuario_id=$1 AND activo=true',
        [req.user.id]
      );
      if (parseInt(count.rows[0].count) >= 1) {
        return res.status(403).json({
          error: 'La versión gratuita permite solo 1 paciente. Actualiza a Premium para agregar más.'
        });
      }
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

// PUT /api/pacientes/:id — actualizar paciente
app.put('/api/pacientes/:id', authMiddleware, async (req, res) => {
  const { nombre, relacion, fecha_nacimiento, fechaNacimiento, notas } = req.body;
  try {
    const current = await pool.query(
      'SELECT * FROM pacientes WHERE id=$1 AND usuario_id=$2',
      [req.params.id, req.user.id]
    );
    if (current.rows.length === 0)
      return res.status(404).json({ error: 'Paciente no encontrado' });
    const p = current.rows[0];
    const result = await pool.query(
      'UPDATE pacientes SET nombre=$1, relacion=$2, fecha_nacimiento=$3, notas=$4 WHERE id=$5 AND usuario_id=$6 RETURNING *',
      [
        nombre           !== undefined ? nombre                                   : p.nombre,
        relacion         !== undefined ? (relacion || null)                       : p.relacion,
        fecha_nacimiento !== undefined ? (fecha_nacimiento || null)
          : fechaNacimiento !== undefined ? (fechaNacimiento || null)             : p.fecha_nacimiento,
        notas            !== undefined ? (notas || null)                          : p.notas,
        req.params.id, req.user.id
      ]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/pacientes/:id — baja lógica (activo=false)
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
  const {
    nombre, dosis, frecuencia,
    horaInicio, hora_inicio,
    recordatorio, notas,
    horariosCustom, horarios_custom,
    paciente_id, pacienteId
  } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO medicamentos (usuario_id, paciente_id, nombre, dosis, frecuencia, hora_inicio, recordatorio, notas, horarios_custom) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [
        usuario_id,
        paciente_id || pacienteId || null,
        nombre, dosis, frecuencia,
        horaInicio || hora_inicio || null,
        recordatorio || false,
        notas || null,
        horariosCustom || horarios_custom || null
      ]
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
    const result = await pool.query(
      'SELECT * FROM medicamentos WHERE id=$1 AND usuario_id=$2',
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
      [
        nombre, dosis, frecuencia,
        horaInicio || hora_inicio || null,
        recordatorio,
        notas || null,
        horariosCustom || horarios_custom || null,
        req.params.id, req.user.id
      ]
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
  const { tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio, paciente_id, pacienteId } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO citas (usuario_id, paciente_id, tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
      [usuario_id, paciente_id || pacienteId || null, tipo, titulo, fecha, hora, lugar || null, profesional || null, notas || null, recordatorio || null]
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
  const {
    titulo, categoria, fecha, hora, frecuencia, completada,
    descripcion, recordatorio, hastaFecha, hasta_fecha,
    paciente_id, pacienteId
  } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO tareas (usuario_id, paciente_id, titulo, categoria, fecha, hora, frecuencia, completada, descripcion, recordatorio, hasta_fecha) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *',
      [
        usuario_id, paciente_id || pacienteId || null,
        titulo, categoria, fecha,
        hora || null, frecuencia, completada || false,
        descripcion || null, recordatorio || false,
        hastaFecha || hasta_fecha || null
      ]
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

// PUT con actualización parcial: solo sobreescribe los campos que vienen en el body
app.put('/api/tareas/:id', authMiddleware, async (req, res) => {
  try {
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
        b.titulo      !== undefined ? b.titulo                 : t.titulo,
        b.categoria   !== undefined ? b.categoria              : t.categoria,
        b.fecha       !== undefined ? b.fecha                  : t.fecha,
        b.hora        !== undefined ? (b.hora || null)         : t.hora,
        b.frecuencia  !== undefined ? b.frecuencia             : t.frecuencia,
        b.completada  !== undefined ? b.completada             : t.completada,
        b.descripcion !== undefined ? (b.descripcion || null)  : t.descripcion,
        b.recordatorio !== undefined ? b.recordatorio          : t.recordatorio,
        b.hastaFecha  !== undefined ? (b.hastaFecha || null)
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
  const { tipo, nombre, intensidad, estadoAnimo, estado_animo, descripcion, fecha, paciente_id, pacienteId } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO sintomas (usuario_id, paciente_id, tipo, intensidad, estado_animo, descripcion, fecha) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [
        usuario_id, paciente_id || pacienteId || null,
        tipo || nombre, intensidad,
        estadoAnimo || estado_animo || null,
        descripcion || null,
        fecha ? new Date(fecha) : new Date()
      ]
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
      [
        tipo || nombre, intensidad,
        estadoAnimo || estado_animo || null,
        descripcion || null,
        fecha ? new Date(fecha) : new Date(),
        req.params.id, req.user.id
      ]
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
  const { nombre, categoria, especialidad, telefono, email, direccion, notas, paciente_id, pacienteId } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO contactos (usuario_id, paciente_id, nombre, categoria, especialidad, telefono, email, direccion, notas) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *',
      [usuario_id, paciente_id || pacienteId || null, nombre, categoria, especialidad || null, telefono, email || null, direccion || null, notas || null]
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
  const { tipo, valor, sistolica, diastolica, notas, fecha, paciente_id, pacienteId } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO signos_vitales (usuario_id, paciente_id, tipo, valor, sistolica, diastolica, notas, fecha) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
      [usuario_id, paciente_id || pacienteId || null, tipo, valor || null, sistolica || null, diastolica || null, notas || null, fecha ? new Date(fecha) : new Date()]
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
  const {
    medicamento_id, medicamentoId,
    medicamento_nombre, medicamentoNombre,
    dosis, notas, fecha,
    paciente_id, pacienteId
  } = req.body;
  const usuario_id = req.user.id;
  try {
    const result = await pool.query(
      'INSERT INTO historial_medicamentos (usuario_id, paciente_id, medicamento_id, medicamento_nombre, dosis, notas, fecha) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
      [
        usuario_id,
        paciente_id || pacienteId || null,
        medicamento_id || medicamentoId || null,
        medicamento_nombre || medicamentoNombre,
        dosis || null,
        notas || null,
        fecha ? new Date(fecha) : new Date()
      ]
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
app.listen(PORT, async () => {
  console.log(`✅ Servidor escuchando en puerto ${PORT}`);
  console.log(`📍 http://localhost:${PORT}`);
  await runMigrations();
});
