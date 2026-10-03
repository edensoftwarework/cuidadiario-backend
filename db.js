const { Pool } = require('pg');

const isP0CTest = process.env.P0C_TEST_MODE === '1';
const isP1Test = process.env.P1_TEST_MODE === '1';
const isIsolatedTest = isP0CTest || isP1Test;

if (isIsolatedTest) {
  const localHosts = new Set(['127.0.0.1', 'localhost', '::1']);
  const externalTestVariables = [
    'DATABASE_URL', 'DATABASE_PUBLIC_URL', 'RESEND_API_KEY', 'MP_ACCESS_TOKEN',
    'MP_WEBHOOK_SECRET', 'PAYPAL_CLIENT_ID', 'PAYPAL_CLIENT_SECRET',
    'VAPID_PUBLIC_KEY', 'VAPID_PRIVATE_KEY', 'BACKEND_URL', 'RAILWAY_STATIC_URL'
  ];
  const expectedDbPrefix = isP1Test ? /^cuidadiario_p1_test(?:_|$)/ : /^cuidadiario_p0c_test(?:_|$)/;
  const expectedSecretPrefix = isP1Test ? 'p1-local-' : 'p0c-local-';
  const guardLabel = isP1Test ? 'P1' : 'P0-C';
  if (!localHosts.has(process.env.PGHOST)) {
    throw new Error(`${guardLabel} test guard: PGHOST debe ser loopback`);
  }
  if (!expectedDbPrefix.test(process.env.PGDATABASE || '')) {
    throw new Error(`${guardLabel} test guard: PGDATABASE debe ser una base dedicada de pruebas`);
  }
  if (!String(process.env.JWT_SECRET || '').startsWith(expectedSecretPrefix)) {
    throw new Error(`${guardLabel} test guard: JWT_SECRET debe ser sintético y local`);
  }
  if (externalTestVariables.some(name => process.env[name])) {
    throw new Error(`${guardLabel} test guard: integraciones externas deben permanecer deshabilitadas`);
  }
}

const pool = new Pool({
  host: process.env.PGHOST,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  port: process.env.PGPORT,
  ssl: isIsolatedTest ? false : { rejectUnauthorized: false }
});

module.exports = pool;
