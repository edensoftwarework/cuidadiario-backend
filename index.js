const express = require('express');
const app = express();

app.get('/', (req, res) => {
  res.send('Backend funcionando para CuidaDiario!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en puerto ${PORT}`);
});