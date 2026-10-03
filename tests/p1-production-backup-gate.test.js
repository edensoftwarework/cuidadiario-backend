'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const https = require('node:https');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { Client, Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const {
    MIGRATIONS,
    VERSIONED_TABLES,
    SOFT_DELETE_TABLES,
    runB2BP1Migrations,
} = require('../b2b-p1');

const PG_BIN = process.env.P1_PG_BIN || 'C:\\Program Files\\PostgreSQL\\18\\bin';
const INITDB = path.join(PG_BIN, 'initdb.exe');
const PG_CTL = path.join(PG_BIN, 'pg_ctl.exe');
const CREATEDB = path.join(PG_BIN, 'createdb.exe');
const PG_RESTORE = path.join(PG_BIN, 'pg_restore.exe');
const DUMP = process.env.P1_BACKUP_DUMP_PATH;
const EXPECTED_SIZE = Number(process.env.P1_BACKUP_EXPECTED_SIZE_BYTES);
const EXPECTED_HASH = String(process.env.P1_BACKUP_EXPECTED_SHA256 || '').toUpperCase();
const EXPECTED_LIST_LINES = Number(process.env.P1_BACKUP_EXPECTED_LIST_LINES);
const TEST_SECRET = 'p1-local-production-restore-gate-secret';

let assertions = 0;
const check = (value, message) => { assertions += 1; assert.ok(value, message); };
const equal = (actual, expected, message) => { assertions += 1; assert.deepEqual(actual, expected, message); };
const quoteIdent = value => `"${String(value).replace(/"/g, '""')}"`;
const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');

function validateGateInputs() {
    const missing = [];
    if (!DUMP) missing.push('P1_BACKUP_DUMP_PATH');
    if (!Number.isSafeInteger(EXPECTED_SIZE) || EXPECTED_SIZE <= 0) missing.push('P1_BACKUP_EXPECTED_SIZE_BYTES');
    if (!/^[A-F0-9]{64}$/.test(EXPECTED_HASH)) missing.push('P1_BACKUP_EXPECTED_SHA256');
    if (!Number.isSafeInteger(EXPECTED_LIST_LINES) || EXPECTED_LIST_LINES <= 0) missing.push('P1_BACKUP_EXPECTED_LIST_LINES');
    if (missing.length > 0) {
        throw new Error(
            `Gate sin metadatos explícitos del dump fresco: ${missing.join(', ')}. ` +
            'No se admite un backup preconfigurado o implícito.'
        );
    }
    if (!path.isAbsolute(DUMP)) {
        throw new Error('P1_BACKUP_DUMP_PATH debe ser una ruta absoluta al dump fresco');
    }
}

function run(command, args, options = {}) {
    const result = spawnSync(command, args, {
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
        ...options,
    });
    if (result.status !== 0) {
        throw new Error(`${path.basename(command)} falló (${result.status}): ${result.stderr || result.stdout}`);
    }
    return result;
}

async function hashFile(filename) {
    const hash = crypto.createHash('sha256');
    await new Promise((resolve, reject) => {
        const stream = fs.createReadStream(filename);
        stream.on('data', chunk => hash.update(chunk));
        stream.on('end', resolve);
        stream.on('error', reject);
    });
    return hash.digest('hex').toUpperCase();
}

async function freePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address();
            server.close(error => error ? reject(error) : resolve(port));
        });
    });
}

function dbConfig(port, database) {
    return { host: '127.0.0.1', port, user: 'p1_admin', password: '', database, ssl: false };
}

async function withClient(port, database, work) {
    const client = new Client(dbConfig(port, database));
    await client.connect();
    try { return await work(client); }
    finally { await client.end(); }
}

async function listTables(client) {
    return (await client.query(`
        SELECT tablename FROM pg_tables
        WHERE schemaname='public'
        ORDER BY tablename
    `)).rows.map(row => row.tablename);
}

async function collectDataSnapshot(client) {
    const tables = await listTables(client);
    const snapshot = {};
    const ignored = ['version', 'deleted_at', 'deleted_by', 'deletion_reason'];
    for (const table of tables) {
        const target = quoteIdent(table);
        const count = Number((await client.query(`SELECT COUNT(*)::bigint AS n FROM ${target}`)).rows[0].n);
        const fingerprint = (await client.query(`
            SELECT md5(COALESCE(string_agg(row_hash, '' ORDER BY row_hash), '')) AS fingerprint
            FROM (
                SELECT md5((to_jsonb(t) - $1::text[])::text) AS row_hash
                FROM ${target} t
            ) rows
        `, [ignored])).rows[0].fingerprint;
        snapshot[table] = { count, fingerprint, scope: table.endsWith('_b2b') ? 'b2b' : 'non_b2b' };
    }
    return snapshot;
}

async function schemaFingerprint(client, tables) {
    const columns = (await client.query(`
        SELECT table_name,column_name,ordinal_position,data_type,udt_name,is_nullable,column_default,
               character_maximum_length,numeric_precision,numeric_scale
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name = ANY($1::text[])
        ORDER BY table_name,ordinal_position
    `, [tables])).rows;
    const constraints = (await client.query(`
        SELECT c.conrelid::regclass::text AS table_name,c.conname,c.contype,pg_get_constraintdef(c.oid,true) AS definition
        FROM pg_constraint c
        WHERE c.connamespace='public'::regnamespace AND c.conrelid::regclass::text = ANY($1::text[])
        ORDER BY table_name,c.conname
    `, [tables])).rows;
    const indexes = (await client.query(`
        SELECT tablename,indexname,indexdef
        FROM pg_indexes
        WHERE schemaname='public' AND tablename = ANY($1::text[])
        ORDER BY tablename,indexname
    `, [tables])).rows;
    const triggers = (await client.query(`
        SELECT c.relname AS table_name,t.tgname,pg_get_triggerdef(t.oid,true) AS definition
        FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
        JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND NOT t.tgisinternal AND c.relname = ANY($1::text[])
        ORDER BY c.relname,t.tgname
    `, [tables])).rows;
    return sha256(JSON.stringify({ columns, constraints, indexes, triggers }));
}

async function collectBaseline(client) {
    const data = await collectDataSnapshot(client);
    const tables = Object.keys(data);
    const b2b = tables.filter(name => name.endsWith('_b2b'));
    const nonB2B = tables.filter(name => !name.endsWith('_b2b'));
    return {
        data,
        tables,
        b2b,
        nonB2B,
        b2bSchema: await schemaFingerprint(client, b2b),
        nonB2BSchema: await schemaFingerprint(client, nonB2B),
        rowTotals: {
            b2b: b2b.reduce((sum, name) => sum + data[name].count, 0),
            nonB2B: nonB2B.reduce((sum, name) => sum + data[name].count, 0),
        },
    };
}

async function collectPreP1Matrix(client) {
    const objectNames = [
        'schema_migrations_b2b', 'auditoria_eventos_b2b', 'operaciones_idempotentes_b2b',
        'prevent_auditoria_eventos_b2b_mutation', 'auditoria_eventos_b2b_append_only',
        'auditoria_b2b_tenant_fecha_idx', 'auditoria_b2b_recurso_idx', 'auditoria_b2b_paciente_idx',
        'idempotencia_b2b_expiry_idx',
    ];
    const objects = {};
    for (const name of objectNames) {
        const result = await client.query(`
            SELECT
                to_regclass('public.' || $1) IS NOT NULL AS relation,
                to_regprocedure('public.' || $1 || '()') IS NOT NULL AS function,
                EXISTS (SELECT 1 FROM pg_trigger WHERE tgname=$1 AND NOT tgisinternal) AS trigger
        `, [name]);
        objects[name] = result.rows[0];
    }
    const columns = (await client.query(`
        SELECT table_name,column_name,data_type,udt_name,is_nullable,column_default
        FROM information_schema.columns
        WHERE table_schema='public'
          AND (column_name='version' OR column_name IN ('deleted_at','deleted_by','deletion_reason'))
        ORDER BY table_name,column_name
    `)).rows;
    return { objects, columns };
}

function timedPool(pool, timings) {
    return {
        async connect() {
            const client = await pool.connect();
            return {
                async query(...args) {
                    const text = typeof args[0] === 'string' ? args[0] : args[0]?.text;
                    const migration = MIGRATIONS.find(item => item.sql.trim() === String(text || '').trim());
                    const started = process.hrtime.bigint();
                    try { return await client.query(...args); }
                    finally {
                        if (migration) timings[migration.version] = Number(process.hrtime.bigint() - started) / 1e6;
                    }
                },
                release() { client.release(); },
            };
        },
    };
}

async function validatePostMigration(client, baseline) {
    const after = await collectBaseline(client);
    for (const table of baseline.tables) {
        check(after.data[table], `tabla heredada ${table} preservada`);
        equal(after.data[table].count, baseline.data[table].count, `conteo ${table} preservado`);
        equal(after.data[table].fingerprint, baseline.data[table].fingerprint, `contenido heredado ${table} preservado`);
    }
    equal(after.nonB2BSchema, baseline.nonB2BSchema, 'esquema no-B2B/B2C preservado');
    equal(Number((await client.query('SELECT COUNT(*) FROM auditoria_eventos_b2b')).rows[0].count), 0,
        'migración no fabrica auditoría histórica');
    equal(Number((await client.query('SELECT COUNT(*) FROM operaciones_idempotentes_b2b')).rows[0].count), 0,
        'migración no fabrica operaciones idempotentes');
    for (const table of VERSIONED_TABLES) {
        const invalid = Number((await client.query(`SELECT COUNT(*) FROM ${quoteIdent(table)} WHERE version IS DISTINCT FROM 1`)).rows[0].count);
        equal(invalid, 0, `${table}.version inicia prospectivamente en 1`);
    }
    for (const table of SOFT_DELETE_TABLES) {
        const hidden = Number((await client.query(`
            SELECT COUNT(*) FROM ${quoteIdent(table)}
            WHERE deleted_at IS NOT NULL OR deleted_by IS NOT NULL OR deletion_reason IS NOT NULL
        `)).rows[0].count);
        equal(hidden, 0, `${table} no oculta filas históricas`);
    }
    const journal = (await client.query('SELECT version,checksum FROM schema_migrations_b2b ORDER BY version')).rows;
    equal(journal.length, 3, 'journal contiene tres migraciones');
    for (const migration of MIGRATIONS) {
        const row = journal.find(item => item.version === migration.version);
        equal(row?.checksum, sha256(migration.sql), `${migration.version} conserva checksum esperado`);
    }
    const trigger = await client.query(`
        SELECT pg_get_triggerdef(t.oid,true) AS definition
        FROM pg_trigger t
        WHERE t.tgname='auditoria_eventos_b2b_append_only' AND NOT t.tgisinternal
    `);
    equal(trigger.rowCount, 1, 'trigger append-only presente');
    check(/BEFORE (?:UPDATE OR DELETE|DELETE OR UPDATE)/.test(trigger.rows[0].definition), 'trigger bloquea UPDATE y DELETE');
    return after;
}

async function validatePostStructure(client) {
    const versionMatrix = [];
    for (const table of VERSIONED_TABLES) {
        const column = (await client.query(`
            SELECT data_type,is_nullable,column_default
            FROM information_schema.columns
            WHERE table_schema='public' AND table_name=$1 AND column_name='version'
        `, [table])).rows[0];
        equal(column?.data_type, 'bigint', `${table}.version es BIGINT`);
        equal(column?.is_nullable, 'NO', `${table}.version es NOT NULL`);
        check(/1/.test(column?.column_default || ''), `${table}.version tiene DEFAULT 1`);
        const versionCheck = (await client.query(`
            SELECT pg_get_constraintdef(c.oid,true) AS definition
            FROM pg_constraint c
            WHERE c.conrelid=$1::regclass AND c.contype='c'
              AND pg_get_constraintdef(c.oid,true) LIKE '%version%> 0%'
        `, [table])).rows;
        equal(versionCheck.length, 1, `${table}.version tiene CHECK > 0`);
        versionMatrix.push({ table, type:column.data_type, notNull:true, defaultOne:true, checkPositive:true });
    }
    const softDeleteMatrix = [];
    const expectedTypes = {
        deleted_at:'timestamp with time zone', deleted_by:'integer', deletion_reason:'text',
    };
    for (const table of SOFT_DELETE_TABLES) {
        for (const [columnName, expectedType] of Object.entries(expectedTypes)) {
            const column = (await client.query(`
                SELECT data_type,is_nullable,column_default
                FROM information_schema.columns
                WHERE table_schema='public' AND table_name=$1 AND column_name=$2
            `, [table, columnName])).rows[0];
            equal(column?.data_type, expectedType, `${table}.${columnName} tiene tipo esperado`);
            equal(column?.is_nullable, 'YES', `${table}.${columnName} es nullable`);
            equal(column?.column_default, null, `${table}.${columnName} no inventa default`);
        }
        softDeleteMatrix.push({ table, deletedAt:'timestamptz nullable', deletedBy:'integer nullable', reason:'text nullable' });
    }
    const requiredIndexes = [
        'auditoria_b2b_tenant_fecha_idx','auditoria_b2b_recurso_idx','auditoria_b2b_paciente_idx','idempotencia_b2b_expiry_idx',
    ];
    const indexes = (await client.query(`
        SELECT indexname FROM pg_indexes
        WHERE schemaname='public' AND indexname = ANY($1::text[])
        ORDER BY indexname
    `, [requiredIndexes])).rows.map(row => row.indexname);
    equal(indexes, [...requiredIndexes].sort(), 'índices P1 esperados presentes');
    const constraints = (await client.query(`
        SELECT c.conrelid::regclass::text AS table_name,c.contype,pg_get_constraintdef(c.oid,true) AS definition
        FROM pg_constraint c
        WHERE c.conrelid IN ('auditoria_eventos_b2b'::regclass,'operaciones_idempotentes_b2b'::regclass)
        ORDER BY table_name,c.contype,definition
    `)).rows;
    check(constraints.some(row => row.table_name === 'auditoria_eventos_b2b' && row.contype === 'p'), 'ledger tiene PK');
    check(constraints.filter(row => row.table_name === 'auditoria_eventos_b2b' && row.contype === 'c').length >= 3, 'ledger tiene checks de dominio');
    check(constraints.some(row => row.table_name === 'operaciones_idempotentes_b2b' && row.contype === 'p'), 'idempotencia tiene PK');
    check(constraints.some(row => row.table_name === 'operaciones_idempotentes_b2b' && row.contype === 'u' && /institucion_id.*actor_usuario_id.*operacion.*clave/.test(row.definition)),
        'idempotencia tiene unique de alcance');
    check(constraints.some(row => row.table_name === 'operaciones_idempotentes_b2b' && row.contype === 'c' && /estado/.test(row.definition)),
        'idempotencia restringe estado');
    equal((await client.query("SELECT to_regprocedure('prevent_auditoria_eventos_b2b_mutation()') IS NOT NULL AS present")).rows[0].present,
        true, 'función append-only presente');
    return { versionMatrix, softDeleteMatrix, indexes, constraintCount:constraints.length };
}

async function runFailureScenarios(port, databases, baselineNonB2B) {
    const result = {};

    result.p1_001 = await withClient(port, databases.fail001, async client => {
        await client.query('CREATE TABLE auditoria_eventos_b2b (dummy integer)');
        const pool = new Pool(dbConfig(port, databases.fail001));
        let error = '';
        try { await runB2BP1Migrations(pool); } catch (caught) { error = caught.message; }
        await pool.end();
        check(/p1_001_foundations/.test(error), 'fallo p1_001 bloquea runner');
        equal(Number((await client.query('SELECT COUNT(*) FROM schema_migrations_b2b')).rows[0].count), 0,
            'p1_001 fallida no se registra');
        equal((await client.query("SELECT to_regclass('public.operaciones_idempotentes_b2b') IS NULL AS absent")).rows[0].absent,
            true, 'p1_001 revierte objetos parciales');
        return { blocked: true, journalRows: 0 };
    });

    result.p1_002 = await withClient(port, databases.fail002, async client => {
        await client.query('ALTER TABLE tareas_b2b RENAME TO tareas_b2b_gate_original');
        await client.query('CREATE VIEW tareas_b2b AS SELECT * FROM tareas_b2b_gate_original');
        const pool = new Pool(dbConfig(port, databases.fail002));
        let error = '';
        try { await runB2BP1Migrations(pool); } catch (caught) { error = caught.message; }
        await pool.end();
        check(/p1_002_versions/.test(error), 'fallo p1_002 bloquea runner');
        const versions = (await client.query('SELECT version FROM schema_migrations_b2b ORDER BY version')).rows.map(row => row.version);
        equal(versions, ['p1_001_foundations'], 'p1_002 fallida conserva sólo p1_001');
        equal((await client.query(`SELECT COUNT(*)::int AS n FROM information_schema.columns WHERE table_schema='public' AND table_name='instituciones_b2b' AND column_name='version'`)).rows[0].n,
            0, 'p1_002 revierte columnas agregadas antes del fallo');
        return { blocked: true, journal: versions };
    });

    result.p1_003 = await withClient(port, databases.fail003, async client => {
        const pool = new Pool(dbConfig(port, databases.fail003));
        await runB2BP1Migrations(pool);
        await client.query("DELETE FROM schema_migrations_b2b WHERE version='p1_003_soft_delete'");
        for (const table of SOFT_DELETE_TABLES) {
            await client.query(`ALTER TABLE ${quoteIdent(table)} DROP COLUMN deleted_at, DROP COLUMN deleted_by, DROP COLUMN deletion_reason`);
        }
        await client.query('ALTER TABLE sintomas_b2b RENAME TO sintomas_b2b_gate_original');
        await client.query('CREATE VIEW sintomas_b2b AS SELECT * FROM sintomas_b2b_gate_original');
        let error = '';
        try { await runB2BP1Migrations(pool); } catch (caught) { error = caught.message; }
        await pool.end();
        check(/p1_003_soft_delete/.test(error), 'fallo p1_003 bloquea runner');
        equal(Number((await client.query("SELECT COUNT(*) FROM schema_migrations_b2b WHERE version='p1_003_soft_delete'")).rows[0].count), 0,
            'p1_003 fallida no se registra');
        equal((await client.query(`SELECT COUNT(*)::int AS n FROM information_schema.columns WHERE table_schema='public' AND table_name='citas_b2b' AND column_name='deleted_at'`)).rows[0].n,
            0, 'p1_003 revierte columnas parciales');
        return { blocked: true, journalRows: 2 };
    });

    result.concurrent = await (async () => {
        await withClient(port, databases.concurrent, client => client.query(`
            CREATE TABLE schema_migrations_b2b (
                version TEXT PRIMARY KEY,
                checksum CHAR(64) NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
        `));
        const poolA = new Pool(dbConfig(port, databases.concurrent));
        const poolB = new Pool(dbConfig(port, databases.concurrent));
        const started = process.hrtime.bigint();
        await Promise.all([runB2BP1Migrations(poolA), runB2BP1Migrations(poolB)]);
        const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
        await poolA.end();
        await poolB.end();
        const rows = await withClient(port, databases.concurrent, async client =>
            Number((await client.query('SELECT COUNT(*) FROM schema_migrations_b2b')).rows[0].count));
        equal(rows, 3, 'dos runners concurrentes registran cada migración una sola vez');
        return { journalRows: rows, elapsedMs };
    })();

    result.checksum = await withClient(port, databases.concurrent, async client => {
        const original = (await client.query("SELECT checksum FROM schema_migrations_b2b WHERE version='p1_001_foundations'")).rows[0].checksum;
        await client.query("UPDATE schema_migrations_b2b SET checksum=$1 WHERE version='p1_001_foundations'", ['0'.repeat(64)]);
        const pool = new Pool(dbConfig(port, databases.concurrent));
        let error = '';
        try { await runB2BP1Migrations(pool); } catch (caught) { error = caught.message; }
        await pool.end();
        check(/Checksum inválido/.test(error), 'checksum divergente bloquea runner');
        await client.query("UPDATE schema_migrations_b2b SET checksum=$1 WHERE version='p1_001_foundations'", [original]);
        return { blocked: true };
    });

    result.incompatible = await withClient(port, databases.incompatible, async client => {
        await client.query('ALTER TABLE pacientes_b2b ADD COLUMN version TEXT');
        const pool = new Pool(dbConfig(port, databases.incompatible));
        await runB2BP1Migrations(pool);
        await pool.end();
        const column = (await client.query(`
            SELECT data_type FROM information_schema.columns
            WHERE table_schema='public' AND table_name='pacientes_b2b' AND column_name='version'
        `)).rows[0];
        equal(column.data_type, 'text', 'IF NOT EXISTS no corrige una columna incompatible');
        equal(Number((await client.query("SELECT COUNT(*) FROM schema_migrations_b2b WHERE version='p1_002_versions'")).rows[0].count), 1,
            'runner solo no detecta definición incompatible preexistente');
        return { preflightRequired: true, observedType: column.data_type };
    });

    for (const database of [databases.fail001, databases.fail002, databases.fail003]) {
        const nonB2BHash = await withClient(port, database, async client => {
            return schemaFingerprint(client, baselineNonB2B.tables);
        });
        equal(nonB2BHash, baselineNonB2B.hash, `${database}: fallo no altera esquema B2C/no-B2B`);
    }
    return result;
}

async function seedSyntheticFixture(db) {
    const password = 'Gate-local-password-2026';
    const passwordHash = await bcrypt.hash(password, 4);
    const institution = (await db.query(`
        INSERT INTO instituciones_b2b (nombre,plan,activa)
        VALUES ('P1 Gate Synthetic','total',TRUE) RETURNING id
    `)).rows[0].id;
    const user = (await db.query(`
        INSERT INTO usuarios_b2b (institucion_id,nombre,email,password_hash,rol,activo,email_verified)
        VALUES ($1,'Gate Admin','p1-gate-local@example.invalid',$2,'admin_institucion',TRUE,TRUE) RETURNING id
    `, [institution, passwordHash])).rows[0].id;
    const patient = (await db.query(`
        INSERT INTO pacientes_b2b (institucion_id,nombre,activo)
        VALUES ($1,'Gate Synthetic Patient',TRUE) RETURNING id
    `, [institution])).rows[0].id;
    const discharged = (await db.query(`
        INSERT INTO pacientes_b2b (institucion_id,nombre,activo,fecha_egreso,motivo_egreso)
        VALUES ($1,'Gate Discharged',TRUE,NOW(),'gate') RETURNING id
    `, [institution])).rows[0].id;
    const insertMedication = async stock => (await db.query(`
        INSERT INTO medicamentos_b2b (institucion_id,paciente_id,nombre,stock,activo)
        VALUES ($1,$2,'Gate Medication',$3,TRUE) RETURNING id
    `, [institution, patient, stock])).rows[0].id;
    const medication = await insertMedication(5);
    const stockRace = await insertMedication(1);
    const failureMedication = await insertMedication(5);
    const citation = (await db.query(`
        INSERT INTO citas_b2b (institucion_id,paciente_id,titulo,fecha,created_by)
        VALUES ($1,$2,'Gate Citation',NOW()+INTERVAL '1 day',$3) RETURNING id
    `, [institution, patient, user])).rows[0].id;
    const archivedCitation = (await db.query(`
        INSERT INTO citas_b2b (institucion_id,paciente_id,titulo,fecha,created_by)
        VALUES ($1,$2,'Gate Archive',NOW()+INTERVAL '2 days',$3) RETURNING id
    `, [institution, patient, user])).rows[0].id;
    const task = (await db.query(`
        INSERT INTO tareas_b2b (institucion_id,paciente_id,titulo,activa,created_by)
        VALUES ($1,$2,'Gate Task',TRUE,$3) RETURNING id
    `, [institution, patient, user])).rows[0].id;
    const catalog = (await db.query(`
        INSERT INTO catalogo_medicamentos_b2b (institucion_id,nombre,stock_actual)
        VALUES ($1,'Gate Catalog',2) RETURNING id
    `, [institution])).rows[0].id;
    return { institution, user, patient, discharged, medication, stockRace, failureMedication, citation, archivedCitation, task, catalog, password };
}

async function runRuntimeChecks(port, database, baseline) {
    Object.assign(process.env, {
        P1_TEST_MODE: '1', PGHOST: '127.0.0.1', PGPORT: String(port), PGUSER: 'p1_admin', PGPASSWORD: '',
        PGDATABASE: database, JWT_SECRET: TEST_SECRET, NODE_ENV: 'test', PORT: '0',
    });
    delete process.env.P0C_TEST_MODE;
    for (const name of ['DATABASE_URL','DATABASE_PUBLIC_URL','RESEND_API_KEY','MP_ACCESS_TOKEN','MP_WEBHOOK_SECRET',
        'PAYPAL_CLIENT_ID','PAYPAL_CLIENT_SECRET','VAPID_PUBLIC_KEY','VAPID_PRIVATE_KEY','BACKEND_URL','RAILWAY_STATIC_URL']) {
        delete process.env[name];
    }
    const originalHttpsRequest = https.request;
    const originalHttpsGet = https.get;
    const originalFetch = global.fetch;
    let externalAttempts = 0;
    let server;
    let backend;
    let db;
    try {
        https.request = function blockedHttpsRequest() { externalAttempts += 1; throw new Error('external HTTPS blocked'); };
        https.get = function blockedHttpsGet() { externalAttempts += 1; throw new Error('external HTTPS blocked'); };
        global.fetch = async function guardedFetch(input, init) {
            const url = new URL(typeof input === 'string' ? input : input.url);
            if (url.protocol !== 'http:' || !['127.0.0.1','localhost','::1'].includes(url.hostname)) {
                externalAttempts += 1;
                throw new Error(`external fetch blocked: ${url.hostname}`);
            }
            return originalFetch(input, init);
        };
        backend = require('../index');
        const startupStarted = process.hrtime.bigint();
        server = await backend.startServer(0);
        const startupMs = Number(process.hrtime.bigint() - startupStarted) / 1e6;
        const base = `http://127.0.0.1:${server.address().port}`;
        db = new Client(dbConfig(port, database));
        await db.connect();
        const fixture = await seedSyntheticFixture(db);
        const token = jwt.sign({
            id: fixture.user, institucion_id: fixture.institution, rol: 'admin_institucion',
            email: 'p1-gate-local@example.invalid', nombre: 'Gate Admin', b2b: true, email_verified: true,
        }, TEST_SECRET, { expiresIn: '1h' });
        async function request(method, route, body, extraHeaders = {}, suppliedToken = token) {
            const headers = { ...extraHeaders };
            if (suppliedToken) headers.Authorization = `Bearer ${suppliedToken}`;
            if (body !== undefined) headers['Content-Type'] = 'application/json';
            const response = await fetch(`${base}${route}`, {
                method, headers, body: body === undefined ? undefined : JSON.stringify(body),
            });
            const text = await response.text();
            let parsed = text;
            try { parsed = text ? JSON.parse(text) : null; } catch {}
            return { status: response.status, body: parsed, headers: response.headers };
        }

        let response = await request('GET', '/health', undefined, {}, null);
        equal(response.status, 200, 'backend P1 inicia y health responde');
        const afterStartup = await collectBaseline(db);
        for (const table of baseline.nonB2B) {
            equal(afterStartup.data[table].count, baseline.data[table].count, `startup preserva filas no-B2B ${table}`);
            equal(afterStartup.data[table].fingerprint, baseline.data[table].fingerprint, `startup preserva datos no-B2B ${table}`);
        }
        equal(afterStartup.nonB2BSchema, baseline.nonB2BSchema, 'startup preserva esquema B2C/no-B2B');

        const historyBefore = Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=$1', [fixture.medication])).rows[0].count);
        const sameKey = { 'Idempotency-Key':'gate-same-attempt' };
        const replay = await Promise.all([
            request('POST', `/api/b2b/medicamentos/${fixture.medication}/toma`, { cantidad:1, notas:'gate synthetic', _quien:'UNTRUSTED' }, sameKey),
            request('POST', `/api/b2b/medicamentos/${fixture.medication}/toma`, { cantidad:1, notas:'gate synthetic', _quien:'UNTRUSTED' }, sameKey),
        ]);
        equal(replay.map(item => item.status), [201, 201], 'misma key concurrente obtiene resultado estable');
        equal(Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=$1', [fixture.medication])).rows[0].stock), 4,
            'misma key descuenta stock una vez');
        equal(Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=$1', [fixture.medication])).rows[0].count), historyBefore + 1,
            'misma key crea una administración');
        response = await request('POST', `/api/b2b/medicamentos/${fixture.medication}/toma`, { cantidad:2, notas:'different' }, sameKey);
        equal(response.status, 409, 'misma key con payload distinto devuelve 409');

        const stockRace = await Promise.all([
            request('POST', `/api/b2b/medicamentos/${fixture.stockRace}/toma`, { cantidad:1 }, { 'Idempotency-Key':'gate-stock-a' }),
            request('POST', `/api/b2b/medicamentos/${fixture.stockRace}/toma`, { cantidad:1 }, { 'Idempotency-Key':'gate-stock-b' }),
        ]);
        equal(stockRace.filter(item => item.status === 201).length, 1, 'stock 1 permite una administración concurrente');
        equal(stockRace.filter(item => item.status === 400).length, 1, 'stock 1 rechaza la segunda administración');
        equal(Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=$1', [fixture.stockRace])).rows[0].stock), 0,
            'stock nunca queda negativo');

        for (const stage of ['toma_after_stock','toma_after_history','toma_after_audit']) {
            await db.query('UPDATE medicamentos_b2b SET stock=5 WHERE id=$1', [fixture.failureMedication]);
            const beforeHistory = Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=$1', [fixture.failureMedication])).rows[0].count);
            response = await request('POST', `/api/b2b/medicamentos/${fixture.failureMedication}/toma`, { cantidad:1 },
                { 'Idempotency-Key':`gate-${stage}`, 'x-p1-fail-stage':stage });
            equal(response.status, 500, `${stage} responde fallo controlado`);
            equal(Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=$1', [fixture.failureMedication])).rows[0].stock), 5,
                `${stage} revierte stock`);
            equal(Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=$1', [fixture.failureMedication])).rows[0].count), beforeHistory,
                `${stage} revierte historial`);
            equal(Number((await db.query('SELECT COUNT(*) FROM operaciones_idempotentes_b2b WHERE clave=$1', [`gate-${stage}`])).rows[0].count), 0,
                `${stage} revierte reserva idempotente`);
        }

        const patchRace = await Promise.all([
            request('PATCH', `/api/b2b/citas/${fixture.citation}`, { titulo:'Gate A', expected_version:1 }),
            request('PATCH', `/api/b2b/citas/${fixture.citation}`, { titulo:'Gate B', expected_version:1 }),
        ]);
        equal(patchRace.filter(item => item.status === 200).length, 1, 'dos PATCH misma versión: uno gana');
        equal(patchRace.filter(item => item.status === 409).length, 1, 'dos PATCH misma versión: uno recibe 409');
        response = await request('DELETE', `/api/b2b/citas/${fixture.archivedCitation}`, { deletion_reason:'gate synthetic' });
        equal(response.status, 200, 'soft-delete funciona sobre esquema restaurado');
        const archived = (await db.query('SELECT deleted_at FROM citas_b2b WHERE id=$1', [fixture.archivedCitation])).rows[0];
        check(archived?.deleted_at, 'soft-delete preserva fila física');
        response = await request('GET', `/api/b2b/citas?paciente_id=${fixture.patient}`);
        check(!response.body.some(item => item.id === fixture.archivedCitation), 'GET normal oculta archivado');
        await request('DELETE', `/api/b2b/citas/${fixture.archivedCitation}`, { deletion_reason:'repeat' });
        equal(Number((await db.query(`
            SELECT COUNT(*) FROM auditoria_eventos_b2b
            WHERE recurso_tipo='cita' AND recurso_id=$1 AND accion='SOFT_DELETE'
        `, [fixture.archivedCitation])).rows[0].count), 1, 'soft-delete repetido no duplica evento');

        response = await request('GET', `/api/b2b/pacientes/${fixture.discharged}`);
        equal(response.status, 200, 'egresado conserva lectura histórica');
        response = await request('POST', '/api/b2b/sintomas', { paciente_id:fixture.discharged, descripcion:'blocked' });
        equal(response.status, 409, 'egresado bloquea mutación nueva');
        response = await request('PATCH', `/api/b2b/pacientes/${fixture.discharged}`, { habitacion:'gate' });
        equal(response.status, 400, 'corrección post-egreso exige motivo');
        response = await request('PATCH', `/api/b2b/pacientes/${fixture.discharged}`, { habitacion:'gate', correction_reason:'gate reason' });
        equal(response.status, 200, 'admin puede corrección motivada');
        response = await request('PATCH', `/api/b2b/pacientes/${fixture.discharged}`, { fecha_egreso:null, correction_reason:'gate' });
        equal(response.status, 409, 'egreso no se revierte incidentalmente');

        for (const stage of ['catalog_after_update','catalog_after_history']) {
            await db.query('UPDATE catalogo_medicamentos_b2b SET stock_actual=2 WHERE id=$1', [fixture.catalog]);
            response = await request('PATCH', `/api/b2b/catalogo/${fixture.catalog}`, { stock_actual:9 }, { 'x-p1-fail-stage':stage });
            equal(response.status, 500, `${stage} falla controladamente`);
            equal(Number((await db.query('SELECT stock_actual FROM catalogo_medicamentos_b2b WHERE id=$1', [fixture.catalog])).rows[0].stock_actual), 2,
                `${stage} revierte catálogo`);
        }
        response = await request('POST', `/api/b2b/tareas/${fixture.task}/completar`, { notas:'gate' },
            { 'Idempotency-Key':'gate-task-fail', 'x-p1-fail-stage':'task_after_history' });
        equal(response.status, 500, 'tarea revierte ante fallo intermedio');

        response = await request('POST', '/api/b2b/documentos', {
            paciente_id:fixture.patient,nombre_archivo:'gate-fail.txt',tipo_mime:'text/plain',datos:'QUJDRA=='
        }, { 'Idempotency-Key':'gate-doc-fail', 'x-p1-fail-stage':'document_after_quota' });
        equal(response.status, 500, 'documento revierte ante fallo intermedio');
        process.env.P1_TEST_DOC_LIMIT_BYTES = '8';
        const docRace = await Promise.all([
            request('POST','/api/b2b/documentos',{paciente_id:fixture.patient,nombre_archivo:'gate-a.txt',tipo_mime:'text/plain',datos:'QUJDRA=='},{'Idempotency-Key':'gate-doc-a'}),
            request('POST','/api/b2b/documentos',{paciente_id:fixture.patient,nombre_archivo:'gate-b.txt',tipo_mime:'text/plain',datos:'RUZHSA=='},{'Idempotency-Key':'gate-doc-b'}),
        ]);
        equal(docRace.filter(item => item.status === 201).length, 1, 'cuota concurrente permite un documento');
        equal(docRace.filter(item => item.status === 413).length, 1, 'cuota concurrente rechaza segundo documento');
        const documentId = docRace.find(item => item.status === 201).body.id;
        response = await request('DELETE', `/api/b2b/documentos/${documentId}`, { deletion_reason:'gate archive' });
        equal(response.status, 200, 'documento se archiva lógicamente');
        const docRow = (await db.query('SELECT deleted_at,datos FROM documentos_b2b WHERE id=$1', [documentId])).rows[0];
        check(docRow.deleted_at && docRow.datos, 'documento archivado conserva bytes');
        response = await request('GET', `/api/b2b/documentos/${documentId}/download`);
        equal(response.status, 404, 'documento archivado no descarga por ruta normal');

        const auditText = JSON.stringify((await db.query(`
            SELECT before_data,after_data,metadata FROM auditoria_eventos_b2b WHERE institucion_id=$1
        `, [fixture.institution])).rows);
        check(!/password|password_hash|jwt|authorization|api[_-]?key|secret|token/i.test(auditText), 'ledger no contiene claves prohibidas');
        check(!auditText.includes('QUJDRA==') && !auditText.includes('RUZHSA=='), 'ledger no contiene documentos/base64');
        check(!auditText.includes('UNTRUSTED'), 'ledger no usa _quien como identidad');
        const auditRow = (await db.query(`
            SELECT actor_usuario_id,institucion_id,paciente_id,recurso_tipo,accion,recurso_version,ocurrido_at,request_id
            FROM auditoria_eventos_b2b WHERE institucion_id=$1 ORDER BY id DESC LIMIT 1
        `, [fixture.institution])).rows[0];
        equal(auditRow.institucion_id, fixture.institution, 'ledger conserva institución');
        check(auditRow.recurso_tipo && auditRow.accion && auditRow.ocurrido_at, 'ledger conserva recurso, acción y timestamp servidor');
        let updateRejected = false;
        try { await db.query('UPDATE auditoria_eventos_b2b SET motivo=$1 WHERE institucion_id=$2', ['forbidden', fixture.institution]); } catch { updateRejected = true; }
        check(updateRejected, 'trigger rechaza UPDATE de ledger');
        let deleteRejected = false;
        try { await db.query('DELETE FROM auditoria_eventos_b2b WHERE institucion_id=$1', [fixture.institution]); } catch { deleteRejected = true; }
        check(deleteRejected, 'trigger rechaza DELETE de ledger');

        process.env.B2B_P1_BRIDGE_MODE = '1';
        response = await request('POST', '/api/b2b/auth/login', { email:'p1-gate-local@example.invalid', password:fixture.password }, {}, null);
        equal(response.status, 200, 'bridge permite login B2B');
        response = await request('GET', `/api/b2b/citas?paciente_id=${fixture.patient}`);
        equal(response.status, 200, 'bridge permite GET genuino');
        check(!response.body.some(item => item.id === fixture.archivedCitation), 'bridge no reexpone archivados');
        response = await request('POST', '/api/b2b/sintomas', { paciente_id:fixture.patient, descripcion:'blocked' });
        equal(response.status, 503, 'bridge bloquea mutación B2B');
        response = await request('GET', '/api/b2b/verify-subscription');
        equal(response.status, 503, 'bridge bloquea verify-subscription mutador');
        response = await request('GET', '/api/b2b/auth/verify-email?token=synthetic', undefined, {}, null);
        equal(response.status, 503, 'bridge bloquea verify-email mutador');
        response = await request('POST', '/api/admin/set-plan', { institucion_id:fixture.institution, plan:'total' }, { 'x-admin-key':'synthetic' }, null);
        equal(response.status, 503, 'bridge bloquea set-plan');

        const b2cPassword = 'gate-b2c-password';
        const b2cHash = await bcrypt.hash(b2cPassword, 4);
        const b2cUser = (await db.query(`
            INSERT INTO usuarios (nombre,email,password_hash,premium)
            VALUES ('Gate B2C','p1-gate-b2c@example.invalid',$1,FALSE) RETURNING id
        `, [b2cHash])).rows[0].id;
        response = await request('POST', '/api/login', { email:'p1-gate-b2c@example.invalid', password:b2cPassword }, {}, null);
        equal(response.status, 200, 'bridge no intercepta login B2C sintético');
        check(!jwt.decode(response.body.token).b2b, 'token B2C conserva contrato');
        await db.query('DELETE FROM usuarios WHERE id=$1', [b2cUser]);
        delete process.env.B2B_P1_BRIDGE_MODE;
        delete process.env.P1_TEST_DOC_LIMIT_BYTES;

        equal(externalAttempts, 0, 'backend no intenta servicios externos');
        return { startupMs, health: 200, externalAttempts, syntheticInstitution: fixture.institution };
    } finally {
        https.request = originalHttpsRequest;
        https.get = originalHttpsGet;
        global.fetch = originalFetch;
        delete process.env.B2B_P1_BRIDGE_MODE;
        delete process.env.P1_TEST_DOC_LIMIT_BYTES;
        if (server) await new Promise(resolve => server.close(resolve));
        if (backend?.pool) await backend.pool.end().catch(() => {});
        if (db) await db.end().catch(() => {});
    }
}

async function main() {
    const progress = message => console.error(`[P1 REAL BACKUP GATE] ${message}`);
    validateGateInputs();
    check(fs.existsSync(DUMP), 'dump fresco existe');
    equal(fs.statSync(DUMP).size, EXPECTED_SIZE, 'tamaño del dump coincide');
    equal(await hashFile(DUMP), EXPECTED_HASH, 'SHA-256 del dump coincide');
    const archiveList = run(PG_RESTORE, ['--list', DUMP]).stdout.split(/\r?\n/).filter((_, index, all) => index < all.length - 1 || all[index] !== '');
    equal(archiveList.length, EXPECTED_LIST_LINES, 'pg_restore --list tiene 325 líneas');
    check(archiveList.some(line => /_b2b/.test(line)), 'archive contiene objetos B2B');
    check(archiveList.some(line => !line.startsWith(';') && !/_b2b/.test(line)), 'archive contiene objetos no-B2B');

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cuidadiario-p1-real-gate-'));
    const dataDir = path.join(tempRoot, 'pgdata');
    const logFile = path.join(tempRoot, 'postgres.log');
    const port = await freePort();
    const rootName = `cuidadiario_p1_test_restore_${process.pid}`;
    const databases = {
        main: rootName,
        fail001: `${rootName}_fail001`, fail002: `${rootName}_fail002`, fail003: `${rootName}_fail003`,
        concurrent: `${rootName}_concurrent`, incompatible: `${rootName}_incompatible`,
    };
    let started = false;
    let mainPool;
    try {
        progress('inicializando PostgreSQL 18 efímero');
        run(INITDB, ['-D', dataDir, '--auth=trust', '--username=p1_admin', '--no-locale', '--encoding=UTF8']);
        run(PG_CTL, ['-D', dataDir, '-l', logFile, '-o', `-h 127.0.0.1 -p ${port}`, '-w', 'start'], { stdio: 'ignore' });
        started = true;
        run(CREATEDB, ['-h','127.0.0.1','-p',String(port),'-U','p1_admin',databases.main]);
        const restoreStarted = process.hrtime.bigint();
        const restore = run(PG_RESTORE, [
            '-h','127.0.0.1','-p',String(port),'-U','p1_admin','-d',databases.main,
            '--no-owner','--no-privileges','--exit-on-error',DUMP,
        ]);
        const restoreMs = Number(process.hrtime.bigint() - restoreStarted) / 1e6;
        const restoreWarnings = (restore.stderr || '').split(/\r?\n/).filter(Boolean);
        equal(restoreWarnings.length, 0, 'restauración no emite warnings');
        progress(`restauración completada en ${restoreMs.toFixed(1)} ms`);

        const baseline = await withClient(port, databases.main, async client => {
            const serverVersion = (await client.query("SELECT current_setting('server_version') AS version")).rows[0].version;
            check(serverVersion.startsWith('18.'), 'restauración usa PostgreSQL 18');
            const preP1 = await collectPreP1Matrix(client);
            equal(preP1.columns.length, 0, 'no hay columnas P1 preexistentes');
            for (const [name, state] of Object.entries(preP1.objects)) {
                equal(state.relation || state.function || state.trigger, false, `${name} no preexiste`);
            }
            return { ...(await collectBaseline(client)), serverVersion, preP1 };
        });
        check(baseline.b2b.length > 0 && baseline.nonB2B.length > 0, 'restauración contiene B2B y B2C/no-B2B');

        for (const target of Object.values(databases).filter(name => name !== databases.main)) {
            run(CREATEDB, ['-h','127.0.0.1','-p',String(port),'-U','p1_admin','-T',databases.main,target]);
        }

        mainPool = new Pool(dbConfig(port, databases.main));
        const timings = {};
        const migrationStarted = process.hrtime.bigint();
        await runB2BP1Migrations(timedPool(mainPool, timings));
        const migrationTotalMs = Number(process.hrtime.bigint() - migrationStarted) / 1e6;
        const secondStarted = process.hrtime.bigint();
        await runB2BP1Migrations(mainPool);
        const secondRunMs = Number(process.hrtime.bigint() - secondStarted) / 1e6;
        const postMigration = await withClient(port, databases.main, client => validatePostMigration(client, baseline));
        const postStructure = await withClient(port, databases.main, validatePostStructure);
        const failures = await runFailureScenarios(port, databases, { hash:baseline.nonB2BSchema, tables:baseline.nonB2B });

        const failureStartupEnv = {
            ...process.env,
            P1_TEST_MODE:'1', PGHOST:'127.0.0.1', PGPORT:String(port), PGUSER:'p1_admin', PGPASSWORD:'',
            PGDATABASE:databases.fail001, JWT_SECRET:TEST_SECRET, NODE_ENV:'test', PORT:'0',
            DATABASE_URL:'', DATABASE_PUBLIC_URL:'', RESEND_API_KEY:'', MP_ACCESS_TOKEN:'', MP_WEBHOOK_SECRET:'',
            PAYPAL_CLIENT_ID:'', PAYPAL_CLIENT_SECRET:'', VAPID_PUBLIC_KEY:'', VAPID_PRIVATE_KEY:'', BACKEND_URL:'', RAILWAY_STATIC_URL:'',
        };
        const startupFailure = spawnSync(process.execPath, ['-e', `
            const backend=require('./index');
            backend.startServer(0).then(() => process.exit(2)).catch(error => {
                if (/Migración B2B p1_001_foundations falló/.test(error.message)) process.exit(0);
                console.error(error.message); process.exit(3);
            });
        `], { cwd:path.join(__dirname,'..'), env:failureStartupEnv, encoding:'utf8', timeout:20000 });
        equal(startupFailure.status, 0, 'fallo de migración impide que backend acepte tráfico');

        await mainPool.end();
        mainPool = null;
        const runtime = await runRuntimeChecks(port, databases.main, baseline);

        const result = {
            result: 'PASS', assertions,
            dump: {
                path: DUMP, size: EXPECTED_SIZE, sha256: EXPECTED_HASH,
                listLines: archiveList.length,
                archiveEntries: archiveList.filter(line => line && !line.startsWith(';')).length,
            },
            restore: {
                postgres: baseline.serverVersion, pgRestore: run(PG_RESTORE, ['--version']).stdout.trim(),
                restoreMs, warnings: restoreWarnings.length, errors: 0,
                tables: baseline.tables.length, b2bTables: baseline.b2b.length, nonB2BTables: baseline.nonB2B.length,
                baselineRows: baseline.rowTotals,
            },
            preP1: { collisions: 0, p1Columns: baseline.preP1.columns.length },
            migrations: { individualMs: timings, totalMs: migrationTotalMs, secondRunMs, journalRows: 3 },
            preservation: {
                inheritedTables: baseline.tables.length,
                b2bRows: baseline.rowTotals.b2b,
                nonB2BRows: baseline.rowTotals.nonB2B,
                allCountsAndFingerprintsMatch: true,
                nonB2BSchemaMatch: postMigration.nonB2BSchema === baseline.nonB2BSchema,
                historicalAuditRowsCreated: 0,
            },
            postStructure: {
                versionedTables: postStructure.versionMatrix.length,
                softDeleteTables: postStructure.softDeleteMatrix.length,
                indexes: postStructure.indexes,
                constraintCount: postStructure.constraintCount,
            },
            failures,
            runtime,
            environment: { node:process.version, host:'127.0.0.1', profile:'ephemeral-isolated-removed', externalAttempts:runtime.externalAttempts },
        };
        console.log(JSON.stringify(result, null, 2));
    } finally {
        if (mainPool) await mainPool.end().catch(() => {});
        if (started) spawnSync(PG_CTL, ['-D', dataDir, '-m', 'fast', '-w', 'stop'], { encoding:'utf8', timeout:15000 });
        const resolved = path.resolve(tempRoot);
        const tempResolved = path.resolve(os.tmpdir());
        if (!resolved.startsWith(`${tempResolved}${path.sep}`) || !path.basename(resolved).startsWith('cuidadiario-p1-real-gate-')) {
            throw new Error(`Ruta temporal fuera del alcance esperado: ${resolved}`);
        }
        fs.rmSync(resolved, { recursive:true, force:true });
    }
}

main().then(() => {
    // startServer instala timers de producción; el gate ya cerró server, pool y clúster.
    process.exit(0);
}).catch(error => {
    console.error('P1 REAL BACKUP GATE: FAIL');
    console.error(error.stack || error);
    process.exit(1);
});
