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