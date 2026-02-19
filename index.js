const express = require('express');
const app = express();
const pool = require('./db');

app.use(express.json());

///////////////////// ENDPOINTS DE USUARIOS /////////////////////

// Crear usuario
app.post('/usuarios', async (req, res) => {
  const { nombre, email, password_hash, premium } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO usuarios (nombre, email, password_hash, premium) VALUES ($1, $2, $3, $4) RETURNING *',
      [nombre, email, password_hash, premium || false]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener todos los usuarios
app.get('/usuarios', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM usuarios');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener usuario por id
app.get('/usuarios/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Actualizar usuario
app.put('/usuarios/:id', async (req, res) => {
  const { nombre, email, password_hash, premium } = req.body;
  try {
    const result = await pool.query(
      'UPDATE usuarios SET nombre = $1, email = $2, password_hash = $3, premium = $4 WHERE id = $5 RETURNING *',
      [nombre, email, password_hash, premium, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Eliminar usuario
app.delete('/usuarios/:id', async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM usuarios WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
    res.json({ message: 'Usuario eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

////////////////////////// ENDPOINTS DE MEDICAMENTOS /////////////////////

// Crear medicamento
app.post('/medicamentos', async (req, res) => {
  const { usuario_id, nombre, dosis, frecuencia, hora_inicio, recordatorio, notas } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO medicamentos (usuario_id, nombre, dosis, frecuencia, hora_inicio, recordatorio, notas) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [usuario_id, nombre, dosis, frecuencia, hora_inicio, recordatorio || false, notas || null]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener todos los medicamentos
app.get('/medicamentos', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM medicamentos');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener medicamento por id
app.get('/medicamentos/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM medicamentos WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Medicamento no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Actualizar medicamento
app.put('/medicamentos/:id', async (req, res) => {
  const { usuario_id, nombre, dosis, frecuencia, hora_inicio, recordatorio, notas } = req.body;
  try {
    const result = await pool.query(
      'UPDATE medicamentos SET usuario_id = $1, nombre = $2, dosis = $3, frecuencia = $4, hora_inicio = $5, recordatorio = $6, notas = $7 WHERE id = $8 RETURNING *',
      [usuario_id, nombre, dosis, frecuencia, hora_inicio, recordatorio, notas, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Medicamento no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Eliminar medicamento
app.delete('/medicamentos/:id', async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM medicamentos WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Medicamento no encontrado' });
    res.json({ message: 'Medicamento eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

///////////////////////////// ENDPOINTS DE CITAS /////////////////////

// Crear cita
app.post('/citas', async (req, res) => {
  const { usuario_id, tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO citas (usuario_id, tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *',
      [usuario_id, tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener todas las citas
app.get('/citas', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM citas');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener cita por id
app.get('/citas/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM citas WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Actualizar cita
app.put('/citas/:id', async (req, res) => {
  const { usuario_id, tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio } = req.body;
  try {
    const result = await pool.query(
      'UPDATE citas SET usuario_id = $1, tipo = $2, titulo = $3, fecha = $4, hora = $5, lugar = $6, profesional = $7, notas = $8, recordatorio = $9 WHERE id = $10 RETURNING *',
      [usuario_id, tipo, titulo, fecha, hora, lugar, profesional, notas, recordatorio, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Eliminar cita
app.delete('/citas/:id', async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM citas WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Cita no encontrada' });
    res.json({ message: 'Cita eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

////////////////////////////// ENDPOINTS DE TAREAS /////////////////////

// Crear tarea
app.post('/tareas', async (req, res) => {
  const { usuario_id, titulo, categoria, fecha, hora, frecuencia, completada } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO tareas (usuario_id, titulo, categoria, fecha, hora, frecuencia, completada) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
      [usuario_id, titulo, categoria, fecha, hora, frecuencia, completada || false]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener todas las tareas
app.get('/tareas', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tareas');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener tarea por id
app.get('/tareas/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tareas WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Actualizar tarea
app.put('/tareas/:id', async (req, res) => {
  const { usuario_id, titulo, categoria, fecha, hora, frecuencia, completada } = req.body;
  try {
    const result = await pool.query(
      'UPDATE tareas SET usuario_id = $1, titulo = $2, categoria = $3, fecha = $4, hora = $5, frecuencia = $6, completada = $7 WHERE id = $8 RETURNING *',
      [usuario_id, titulo, categoria, fecha, hora, frecuencia, completada, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Eliminar tarea
app.delete('/tareas/:id', async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM tareas WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
    res.json({ message: 'Tarea eliminada' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//////////////////////////////// ENDPOINTS DE SÍNTOMAS /////////////////////

// Crear síntoma
app.post('/sintomas', async (req, res) => {
  const { usuario_id, fecha, tipo, intensidad, estado_animo, descripcion } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO sintomas (usuario_id, fecha, tipo, intensidad, estado_animo, descripcion) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [usuario_id, fecha, tipo, intensidad, estado_animo, descripcion]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener todos los síntomas
app.get('/sintomas', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM sintomas');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener síntoma por id
app.get('/sintomas/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM sintomas WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Síntoma no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Actualizar síntoma
app.put('/sintomas/:id', async (req, res) => {
  const { usuario_id, fecha, tipo, intensidad, estado_animo, descripcion } = req.body;
  try {
    const result = await pool.query(
      'UPDATE sintomas SET usuario_id = $1, fecha = $2, tipo = $3, intensidad = $4, estado_animo = $5, descripcion = $6 WHERE id = $7 RETURNING *',
      [usuario_id, fecha, tipo, intensidad, estado_animo, descripcion, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Síntoma no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Eliminar síntoma
app.delete('/sintomas/:id', async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM sintomas WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Síntoma no encontrado' });
    res.json({ message: 'Síntoma eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/////////////////////////////// ENDPOINTS DE CONTACTOS /////////////////////

// Crear contacto
app.post('/contactos', async (req, res) => {
  const { usuario_id, nombre, categoria, especialidad, telefono, email, direccion, notas } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO contactos (usuario_id, nombre, categoria, especialidad, telefono, email, direccion, notas) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [usuario_id, nombre, categoria, especialidad, telefono, email, direccion, notas]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener todos los contactos
app.get('/contactos', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM contactos');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener contacto por id
app.get('/contactos/:id', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM contactos WHERE id = $1', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Contacto no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Actualizar contacto
app.put('/contactos/:id', async (req, res) => {
  const { usuario_id, nombre, categoria, especialidad, telefono, email, direccion, notas } = req.body;
  try {
    const result = await pool.query(
      'UPDATE contactos SET usuario_id = $1, nombre = $2, categoria = $3, especialidad = $4, telefono = $5, email = $6, direccion = $7, notas = $8 WHERE id = $9 RETURNING *',
      [usuario_id, nombre, categoria, especialidad, telefono, email, direccion, notas, req.params.id]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'Contacto no encontrado' });
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Eliminar contacto
app.delete('/contactos/:id', async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM contactos WHERE id = $1 RETURNING *', [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Contacto no encontrado' });
    res.json({ message: 'Contacto eliminado' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/////////////////////////////////////////////////////////////////////////////

app.get('/', (req, res) => {
  res.send('Backend funcionando para CuidaDiario!');
});

// Endpoint para probar la conexión a PostgreSQL
app.get('/dbtest', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({ time: result.rows[0].now });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

//////////////////////// ESPACIO PARA MIGRACIONES////////////////////



/////////////////////////////////////////////////////////////////////

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});