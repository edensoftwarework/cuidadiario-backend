const express = require('express');
const app = express();
const pool = require('./db');

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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});


