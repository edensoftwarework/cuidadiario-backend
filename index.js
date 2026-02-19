const express = require('express');
const app = express();
const pool = require('./db');

app.use(express.json());

// Crear usuario
app.post('/usuarios', async (req, res) => {
  const { email, password_hash, premium } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO usuarios (email, password_hash, premium) VALUES ($1, $2, $3) RETURNING *',
      [email, password_hash, premium || false]
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
  const { email, password_hash, premium } = req.body;
  try {
    const result = await pool.query(
      'UPDATE usuarios SET email = $1, password_hash = $2, premium = $3 WHERE id = $4 RETURNING *',
      [email, password_hash, premium, req.params.id]
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


