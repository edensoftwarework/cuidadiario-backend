const { Pool } = require('pg');

const isP0CTest = process.env.P0C_TEST_MODE === '1';

if (isP0CTest) {
  const localHosts = new Set(['127.0.0.1', 'localhost', '::1']);
  const externalTestVariables = [
    'DATABASE_URL', 'DATABASE_PUBLIC_URL', 'RESEND_API_KEY', 'MP_ACCESS_TOKEN',
    'MP_WEBHOOK_SECRET', 'PAYPAL_CLIENT_ID', 'PAYPAL_CLIENT_SECRET',
    'VAPID_PUBLIC_KEY', 'VAPID_PRIVATE_KEY', 'BACKEND_URL', 'RAILWAY_STATIC_URL'
  ];
  if (!localHosts.has(process.env.PGHOST)) {
    throw new Error('P0-C test guard: PGHOST debe ser loopback');
  }
  if (!/^cuidadiario_p0c_test(?:_|$)/.test(process.env.PGDATABASE || '')) {
    throw new Error('P0-C test guard: PGDATABASE debe ser una base dedicada cuidadiario_p0c_test*');
  }
  if (!String(process.env.JWT_SECRET || '').startsWith('p0c-local-')) {
    throw new Error('P0-C test guard: JWT_SECRET debe ser sintético y local');
  }
  if (externalTestVariables.some(name => process.env[name])) {
    throw new Error('P0-C test guard: integraciones externas deben permanecer deshabilitadas');
  }
}

const pool = new Pool({
  host: process.env.PGHOST,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  port: process.env.PGPORT,
  ssl: isP0CTest ? false : { rejectUnauthorized: false }
});

module.exports = pool;
