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

app.get('/migrate', async (req, res) => {
  try {
    // Tabla citas
    await pool.query(`
      CREATE TABLE IF NOT EXISTS citas (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id),
        tipo VARCHAR(50),
        titulo VARCHAR(255),
        fecha DATE,
        hora TIME,
        lugar VARCHAR(255),
        profesional VARCHAR(255),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Tabla tareas
    await pool.query(`
      CREATE TABLE IF NOT EXISTS tareas (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id),
        titulo VARCHAR(255) NOT NULL,
        categoria VARCHAR(50),
        frecuencia VARCHAR(50),
        fecha DATE,
        completada BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Tabla síntomas
    await pool.query(`
      CREATE TABLE IF NOT EXISTS sintomas (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id),
        nombre VARCHAR(100),
        intensidad INTEGER,
        estado_animo VARCHAR(20),
        descripcion TEXT,
        fecha DATE,
        hora TIME,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Tabla contactos
    await pool.query(`
      CREATE TABLE IF NOT EXISTS contactos (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id),
        nombre VARCHAR(255) NOT NULL,
        telefono VARCHAR(30),
        email VARCHAR(255),
        direccion VARCHAR(255),
        categoria VARCHAR(50),
        especialidad VARCHAR(100),
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    res.send('Migración completada.');
  } catch (err) {
    res.status(500).send('Error en migración: ' + err.message);
  }
});

/////////////////////////////////////////////////////////////////////


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});


