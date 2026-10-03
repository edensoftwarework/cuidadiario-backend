'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const net = require('net');
const https = require('https');
const { spawnSync } = require('child_process');
const { Client } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { schemaSql, fixtureSql } = require('./p0-c-authorization.test');

const PG_BIN = 'C:\\Program Files\\PostgreSQL\\18\\bin';
const INITDB = path.join(PG_BIN, 'initdb.exe');
const PG_CTL = path.join(PG_BIN, 'pg_ctl.exe');
const TEST_SECRET = 'p1-local-synthetic-secret-never-production';
const TEST_DB = `cuidadiario_p1_test_${process.pid}`;
let assertions = 0;

function check(value, message) { assertions += 1; assert.ok(value, message); }
function equal(actual, expected, message) { assertions += 1; assert.strictEqual(actual, expected, message); }
function run(command, args, options = {}) {
    const result = spawnSync(command, args, { encoding: 'utf8', ...options });
    if (result.status !== 0) throw new Error(`${path.basename(command)} falló (${result.status}): ${result.stderr || result.stdout}`);
    return result;
}
async function freePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address();
            server.close(() => resolve(port));
        });
    });
}

const sequenceSql = `
CREATE SEQUENCE instituciones_b2b_id_seq START 10001;
ALTER TABLE instituciones_b2b ALTER COLUMN id SET DEFAULT nextval('instituciones_b2b_id_seq');
CREATE SEQUENCE usuarios_b2b_id_seq START 10001;
ALTER TABLE usuarios_b2b ALTER COLUMN id SET DEFAULT nextval('usuarios_b2b_id_seq');
CREATE SEQUENCE pacientes_b2b_id_seq START 10001;
ALTER TABLE pacientes_b2b ALTER COLUMN id SET DEFAULT nextval('pacientes_b2b_id_seq');
CREATE SEQUENCE documentos_b2b_id_seq START 10001;
ALTER TABLE documentos_b2b ALTER COLUMN id SET DEFAULT nextval('documentos_b2b_id_seq');
`;

async function main() {
    const progress = message => console.log(`[P1-A/B] ${message}`);
    check(fs.existsSync(INITDB), 'PostgreSQL initdb 18 disponible');
    check(fs.existsSync(PG_CTL), 'PostgreSQL pg_ctl 18 disponible');

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cuidadiario-p1-'));
    const dataDir = path.join(tempRoot, 'pgdata');
    const logFile = path.join(tempRoot, 'postgres.log');
    const port = await freePort();
    let pgStarted = false;
    let server;
    let appPool;
    let db;
    let adminClient;
    let externalAttempts = 0;
    const originalHttpsRequest = https.request;
    const originalHttpsGet = https.get;
    const originalFetch = global.fetch;

    try {
        progress('Inicializando PostgreSQL efímero aislado');
        run(INITDB, ['-D', dataDir, '--auth=trust', '--username=p1_admin', '--no-locale', '--encoding=UTF8']);
        run(PG_CTL, ['-D', dataDir, '-l', logFile, '-o', `-h 127.0.0.1 -p ${port}`, '-w', 'start'], { stdio: 'ignore' });
        pgStarted = true;
        adminClient = new Client({ host: '127.0.0.1', port, user: 'p1_admin', database: 'postgres', ssl: false });
        await adminClient.connect();
        await adminClient.query(`CREATE DATABASE ${TEST_DB}`);
        await adminClient.end();
        adminClient = null;

        db = new Client({ host: '127.0.0.1', port, user: 'p1_admin', database: TEST_DB, ssl: false });
        await db.connect();
        await db.query(schemaSql);
        await db.query(sequenceSql);
        await db.query(fixtureSql);
        const b2cHash = await bcrypt.hash('synthetic-b2c-password', 4);
        await db.query("INSERT INTO usuarios (id,nombre,email,password_hash,premium) VALUES (501,'B2C Sintético','b2c@example.invalid',$1,FALSE)", [b2cHash]);

        const inheritedCounts = (await db.query(`SELECT
            (SELECT COUNT(*)::int FROM pacientes_b2b) pacientes,
            (SELECT COUNT(*)::int FROM documentos_b2b) documentos,
            (SELECT COUNT(*)::int FROM usuarios) b2c`)).rows[0];
        Object.assign(process.env, {
            P1_TEST_MODE: '1', PGHOST: '127.0.0.1', PGPORT: String(port), PGUSER: 'p1_admin',
            PGPASSWORD: '', PGDATABASE: TEST_DB, JWT_SECRET: TEST_SECRET, NODE_ENV: 'test'
        });
        delete process.env.P0C_TEST_MODE;
        for (const name of ['DATABASE_URL','DATABASE_PUBLIC_URL','RESEND_API_KEY','MP_ACCESS_TOKEN','MP_WEBHOOK_SECRET',
            'PAYPAL_CLIENT_ID','PAYPAL_CLIENT_SECRET','VAPID_PUBLIC_KEY','VAPID_PRIVATE_KEY','BACKEND_URL','RAILWAY_STATIC_URL']) {
            delete process.env[name];
        }
        https.request = function blockedHttpsRequest() { externalAttempts += 1; throw new Error('P1 guard: HTTPS externo bloqueado'); };
        https.get = function blockedHttpsGet() { externalAttempts += 1; throw new Error('P1 guard: HTTPS externo bloqueado'); };
        global.fetch = async function guardedFetch(input, init) {
            const url = new URL(typeof input === 'string' ? input : input.url);
            if (url.protocol !== 'http:' || !['127.0.0.1','localhost','::1'].includes(url.hostname)) {
                externalAttempts += 1;
                throw new Error(`P1 guard: fetch externo bloqueado (${url.hostname})`);
            }
            return originalFetch(input, init);
        };

        progress('Ejecutando migraciones aditivas dos veces');
        const backend = require('../index');
        appPool = backend.pool;
        await backend.runB2BP1Migrations(appPool);
        await backend.runB2BP1Migrations(appPool);
        equal(Number((await db.query('SELECT COUNT(*) FROM schema_migrations_b2b')).rows[0].count), 3, 'tres migraciones registradas una sola vez');
        equal(Number((await db.query('SELECT COUNT(*) FROM pacientes_b2b')).rows[0].count), inheritedCounts.pacientes, 'filas heredadas de pacientes preservadas');
        equal(Number((await db.query('SELECT COUNT(*) FROM documentos_b2b')).rows[0].count), inheritedCounts.documentos, 'filas heredadas de documentos preservadas');
        equal(Number((await db.query('SELECT COUNT(*) FROM usuarios')).rows[0].count), inheritedCounts.b2c, 'tabla B2C preservada');
        equal(Number((await db.query('SELECT version FROM pacientes_b2b WHERE id=1001')).rows[0].version), 1, 'fila heredada recibe versión prospectiva 1');
        check((await db.query("SELECT bool_and(length(checksum)=64) ok FROM schema_migrations_b2b")).rows[0].ok, 'checksums SHA-256 almacenados');
        const originalChecksum = (await db.query("SELECT checksum FROM schema_migrations_b2b WHERE version='p1_001_foundations'")).rows[0].checksum;
        await db.query("UPDATE schema_migrations_b2b SET checksum=$1 WHERE version='p1_001_foundations'", ['0'.repeat(64)]);
        let checksumBlocked = false;
        try { await backend.runB2BP1Migrations(appPool); } catch (error) { checksumBlocked = /Checksum inválido/.test(error.message); }
        check(checksumBlocked, 'checksum divergente bloquea el runner');
        await db.query("UPDATE schema_migrations_b2b SET checksum=$1 WHERE version='p1_001_foundations'", [originalChecksum]);
        await backend.runB2BP1Migrations(appPool);
        equal(Number((await db.query('SELECT COUNT(*) FROM schema_migrations_b2b')).rows[0].count), 3, 'runner vuelve a operar tras restaurar checksum correcto');

        const badHost = spawnSync(process.execPath, ['-e', "require('./db')"], { cwd: path.join(__dirname, '..'), encoding: 'utf8', env: { ...process.env, PGHOST: 'railway.invalid' } });
        check(badHost.status !== 0, 'guard P1 rechaza host no loopback');
        const badDb = spawnSync(process.execPath, ['-e', "require('./db')"], { cwd: path.join(__dirname, '..'), encoding: 'utf8', env: { ...process.env, PGDATABASE: 'production' } });
        check(badDb.status !== 0, 'guard P1 rechaza nombre de base no aislada');
        const badExternal = spawnSync(process.execPath, ['-e', "require('./db')"], { cwd: path.join(__dirname, '..'), encoding: 'utf8', env: { ...process.env, DATABASE_PUBLIC_URL: 'postgres://forbidden.invalid' } });
        check(badExternal.status !== 0, 'guard P1 rechaza variables externas');

        server = await new Promise((resolve, reject) => {
            const candidate = backend.app.listen(0, '127.0.0.1', () => resolve(candidate));
            candidate.once('error', reject);
        });
        const base = `http://127.0.0.1:${server.address().port}`;
        async function request(method, route, token, body, extraHeaders = {}) {
            const headers = { ...extraHeaders };
            if (token) headers.Authorization = `Bearer ${token}`;
            if (body !== undefined) headers['Content-Type'] = 'application/json';
            const response = await fetch(`${base}${route}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
            const text = await response.text();
            let parsed = text;
            try { parsed = text ? JSON.parse(text) : null; } catch {}
            return { status: response.status, body: parsed, text, headers: response.headers };
        }
        const token = (id, institution, role) => jwt.sign({ id, institucion_id: institution, rol: role,
            email: `${id}@example.invalid`, nombre: `Usuario ${id}`, b2b: true, email_verified: true }, TEST_SECRET, { expiresIn: '1h' });
        const adminA = token(101, 1, 'admin_institucion');
        const caregiverA = token(102, 1, 'cuidador_staff');
        const adminB = token(201, 2, 'admin_institucion');

        progress('Validando registro atómico y ledger básico');
        let beforeInstitutions = Number((await db.query('SELECT COUNT(*) FROM instituciones_b2b')).rows[0].count);
        let r = await request('POST', '/api/b2b/auth/register', null,
            { nombre_institucion:'Registro fallido sintético', nombre_admin:'Admin', email:'test8@test8', password:'synthetic-pass' },
            { 'x-p1-fail-stage':'register_after_institution' });
        equal(r.status, 500, 'fallo inyectado de registro responde error');
        equal(Number((await db.query('SELECT COUNT(*) FROM instituciones_b2b')).rows[0].count), beforeInstitutions, 'registro fallido no deja institución huérfana');
        r = await request('POST', '/api/b2b/auth/register', null,
            { nombre_institucion:'Registro correcto sintético', nombre_admin:'Admin', email:'test9@test9', password:'synthetic-pass' });
        equal(r.status, 201, 'registro sintético completo funciona');
        const newInstitution = r.body.user.institucion_id;
        equal(Number((await db.query('SELECT COUNT(*) FROM usuarios_b2b WHERE institucion_id=$1', [newInstitution])).rows[0].count), 1, 'registro crea usuario junto con institución');
        equal(Number((await db.query('SELECT COUNT(*) FROM auditoria_eventos_b2b WHERE institucion_id=$1', [newInstitution])).rows[0].count), 2, 'registro crea ambos eventos de auditoría');

        progress('Validando idempotencia, stock, actor y rollback de toma');
        await db.query('UPDATE medicamentos_b2b SET stock=5 WHERE id=1101');
        const historyBefore = Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=1101')).rows[0].count);
        const idemHeaders = { 'Idempotency-Key':'toma-same-attempt-1' };
        const concurrentReplay = await Promise.all([
            request('POST','/api/b2b/medicamentos/1101/toma',caregiverA,{cantidad:1,notas:'sintética',_quien:'IMPOSTOR'},idemHeaders),
            request('POST','/api/b2b/medicamentos/1101/toma',caregiverA,{cantidad:1,notas:'sintética',_quien:'IMPOSTOR'},idemHeaders)
        ]);
        equal(concurrentReplay[0].status, 201, 'primera solicitud idempotente exitosa');
        equal(concurrentReplay[1].status, 201, 'concurrente misma key obtiene replay exitoso');
        equal(Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=1101')).rows[0].stock), 4, 'misma key descuenta stock una sola vez');
        equal(Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=1101')).rows[0].count), historyBefore + 1, 'misma key genera una sola administración');
        const latestAdministration = (await db.query('SELECT * FROM historial_medicamentos_b2b WHERE medicamento_id=1101 ORDER BY id DESC LIMIT 1')).rows[0];
        equal(latestAdministration.administrado_por, 102, 'actor persistido proviene del backend autenticado');
        equal(latestAdministration.administrador_nombre, 'Cuidador A1', '_quien falso no sustituye identidad vigente');
        r = await request('POST','/api/b2b/medicamentos/1101/toma',caregiverA,{cantidad:2,notas:'payload distinto'},idemHeaders);
        equal(r.status, 409, 'misma key con payload distinto es conflicto');
        equal(r.body.code, 'IDEMPOTENCY_KEY_REUSED', 'conflicto idempotente tiene código estable');

        await db.query("INSERT INTO medicamentos_b2b (id,institucion_id,paciente_id,nombre,dosis,frecuencia,stock) VALUES (1110,1,1001,'Stock concurrente','1','diaria',1)");
        const stockRace = await Promise.all([
            request('POST','/api/b2b/medicamentos/1110/toma',adminA,{cantidad:1},{'Idempotency-Key':'stock-race-a'}),
            request('POST','/api/b2b/medicamentos/1110/toma',adminA,{cantidad:1},{'Idempotency-Key':'stock-race-b'})
        ]);
        equal(stockRace.filter(x => x.status === 201).length, 1, 'stock insuficiente permite exactamente una toma concurrente');
        equal(stockRace.filter(x => x.status === 400).length, 1, 'segunda toma concurrente es rechazada');
        equal(Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=1110')).rows[0].stock), 0, 'stock nunca queda negativo');

        for (const stage of ['toma_after_stock','toma_after_history','toma_after_audit']) {
            await db.query('UPDATE medicamentos_b2b SET stock=5 WHERE id=1103');
            const preHistory = Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=1103')).rows[0].count);
            const preAudit = Number((await db.query('SELECT COUNT(*) FROM auditoria_eventos_b2b')).rows[0].count);
            r = await request('POST','/api/b2b/medicamentos/1103/toma',adminA,{cantidad:1},{'Idempotency-Key':`fail-${stage}`,'x-p1-fail-stage':stage});
            equal(r.status, 500, `${stage}: falla inyectada`);
            equal(Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=1103')).rows[0].stock), 5, `${stage}: stock revierte`);
            equal(Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=1103')).rows[0].count), preHistory, `${stage}: historial revierte`);
            equal(Number((await db.query('SELECT COUNT(*) FROM auditoria_eventos_b2b')).rows[0].count), preAudit, `${stage}: ledger revierte`);
            equal(Number((await db.query("SELECT COUNT(*) FROM operaciones_idempotentes_b2b WHERE clave=$1", [`fail-${stage}`])).rows[0].count), 0, `${stage}: reserva idempotente revierte`);
        }

        progress('Validando versionado, soft-delete y egreso');
        const patchRace = await Promise.all([
            request('PATCH','/api/b2b/citas/1301',adminA,{titulo:'Versión A',expected_version:1}),
            request('PATCH','/api/b2b/citas/1301',adminA,{titulo:'Versión B',expected_version:1})
        ]);
        equal(patchRace.filter(x => x.status === 200).length, 1, 'dos PATCH concurrentes: uno gana');
        equal(patchRace.filter(x => x.status === 409 && x.body.code === 'VERSION_CONFLICT').length, 1, 'dos PATCH concurrentes: uno recibe VERSION_CONFLICT');
        equal(Number((await db.query('SELECT version FROM citas_b2b WHERE id=1301')).rows[0].version), 2, 'versión incrementa una vez');
        r = await request('DELETE','/api/b2b/citas/1303',adminA,{deletion_reason:'archivo sintético'});
        equal(r.status, 200, 'soft-delete de cita exitoso');
        let archived = (await db.query('SELECT * FROM citas_b2b WHERE id=1303')).rows[0];
        check(!!archived.deleted_at, 'fila archivada permanece físicamente con deleted_at');
        equal(archived.deleted_by, 101, 'soft-delete registra actor');
        r = await request('GET','/api/b2b/citas?paciente_id=1001',adminA);
        check(!r.body.some(row => row.id === 1303), 'GET normal excluye archivado');
        r = await request('DELETE','/api/b2b/citas/1303',adminA,{deletion_reason:'repetido'});
        equal(r.status, 200, 'segundo DELETE es estable');
        check(r.body.already_deleted === true, 'segundo DELETE informa estado previo');
        equal(Number((await db.query("SELECT COUNT(*) FROM auditoria_eventos_b2b WHERE recurso_tipo='cita' AND recurso_id=1303 AND accion='SOFT_DELETE'")).rows[0].count), 1, 'segundo DELETE no duplica auditoría');
        r = await request('DELETE','/api/b2b/citas/1302',adminB,{});
        equal(r.status, 404, 'tenant B no puede archivar recurso de A');
        r = await request('PATCH','/api/b2b/citas/999999',adminA,{titulo:'no existe'});
        equal(r.status, 404, 'recurso inexistente conserva 404');

        await db.query("INSERT INTO pacientes_b2b (id,institucion_id,nombre,apellido,fecha_egreso,motivo_egreso,activo) VALUES (1004,1,'Egresado','Sintético',NOW(),'cierre',TRUE)");
        await db.query("INSERT INTO asignaciones_b2b (id,institucion_id,cuidador_id,paciente_id,activa) VALUES (8,1,102,1004,TRUE)");
        r = await request('GET','/api/b2b/pacientes/1004',adminA);
        equal(r.status, 200, 'lectura histórica del egresado permitida');
        r = await request('POST','/api/b2b/sintomas',adminA,{paciente_id:1004,descripcion:'no crear'});
        equal(r.status, 409, 'nueva mutación sobre egresado bloqueada');
        equal(r.body.code, 'PATIENT_DISCHARGED', 'bloqueo de egresado tiene código estable');
        r = await request('PATCH','/api/b2b/pacientes/1004',adminA,{habitacion:'corregida'});
        equal(r.status, 400, 'corrección post-egreso sin motivo bloqueada');
        equal(r.body.code, 'CORRECTION_REASON_REQUIRED', 'motivo post-egreso requerido');
        r = await request('PATCH','/api/b2b/pacientes/1004',adminA,{habitacion:'corregida',correction_reason:'corrección sintética'});
        equal(r.status, 200, 'admin puede corrección post-egreso motivada');
        r = await request('PATCH','/api/b2b/pacientes/1004',adminA,{fecha_egreso:null,correction_reason:'no reactivar'});
        equal(r.status, 409, 'fecha_egreso null no reactiva incidentalmente');
        equal(r.body.code, 'PATIENT_REACTIVATION_NOT_ALLOWED', 'reactivación incidental tiene código estable');
        r = await request('DELETE','/api/b2b/asignaciones/8',adminA,{});
        equal(r.status, 200, 'revocación administrativa tras egreso permitida');

        progress('Validando transacciones laterales y documentos');
        for (const stage of ['catalog_after_update','catalog_after_history']) {
            await db.query('UPDATE catalogo_medicamentos_b2b SET stock_actual=2 WHERE id=1200');
            const restocks = Number((await db.query('SELECT COUNT(*) FROM historial_restock_b2b WHERE catalogo_id=1200')).rows[0].count);
            r = await request('PATCH','/api/b2b/catalogo/1200',adminA,{stock_actual:9},{'x-p1-fail-stage':stage});
            equal(r.status, 500, `${stage}: falla inyectada`);
            equal(Number((await db.query('SELECT stock_actual FROM catalogo_medicamentos_b2b WHERE id=1200')).rows[0].stock_actual), 2, `${stage}: catálogo revierte`);
            equal(Number((await db.query('SELECT COUNT(*) FROM historial_restock_b2b WHERE catalogo_id=1200')).rows[0].count), restocks, `${stage}: historial revierte`);
        }
        r = await request('PATCH','/api/b2b/catalogo/1200',adminA,{stock_actual:9,notas_restock:'sintético'});
        equal(r.status, 200, 'restock exitoso');
        equal(Number((await db.query('SELECT COUNT(*) FROM historial_restock_b2b WHERE catalogo_id=1200')).rows[0].count), 1, 'restock e historial confirman juntos');

        const taskHistory = Number((await db.query('SELECT COUNT(*) FROM historial_tareas_b2b WHERE tarea_id=1401')).rows[0].count);
        r = await request('POST','/api/b2b/tareas/1401/completar',adminA,{notas:'fallar'},{'Idempotency-Key':'task-fail','x-p1-fail-stage':'task_after_history'});
        equal(r.status, 500, 'fallo inyectado de tarea');
        equal(Number((await db.query('SELECT COUNT(*) FROM historial_tareas_b2b WHERE tarea_id=1401')).rows[0].count), taskHistory, 'historial de tarea revierte');
        r = await request('POST','/api/b2b/tareas/1401/completar',adminA,{notas:'sin key'});
        equal(r.status, 201, 'cliente heredado sin Idempotency-Key sigue compatible');

        const docCount = Number((await db.query('SELECT COUNT(*) FROM documentos_b2b')).rows[0].count);
        r = await request('POST','/api/b2b/documentos',adminA,{paciente_id:1001,nombre_archivo:'fail.txt',tipo_mime:'text/plain',datos:'QUJDRA=='},
            {'Idempotency-Key':'doc-fail','x-p1-fail-stage':'document_after_quota'});
        equal(r.status, 500, 'fallo inyectado después de cuota');
        equal(Number((await db.query('SELECT COUNT(*) FROM documentos_b2b')).rows[0].count), docCount, 'documento fallido no deja fila parcial');
        const used = Number((await db.query('SELECT COALESCE(SUM(LENGTH(datos)),0) total FROM documentos_b2b WHERE institucion_id=1')).rows[0].total);
        process.env.P1_TEST_DOC_LIMIT_BYTES = String(used + 8);
        const docRace = await Promise.all([
            request('POST','/api/b2b/documentos',adminA,{paciente_id:1001,nombre_archivo:'race-a.txt',tipo_mime:'text/plain',datos:'QUJDRA=='},{'Idempotency-Key':'doc-race-a'}),
            request('POST','/api/b2b/documentos',adminA,{paciente_id:1001,nombre_archivo:'race-b.txt',tipo_mime:'text/plain',datos:'RUZHSA=='},{'Idempotency-Key':'doc-race-b'})
        ]);
        equal(docRace.filter(x => x.status === 201).length, 1, 'cuota concurrente permite un documento');
        equal(docRace.filter(x => x.status === 413).length, 1, 'cuota concurrente rechaza el segundo');
        const createdDocument = docRace.find(x => x.status === 201).body.id;
        r = await request('DELETE',`/api/b2b/documentos/${createdDocument}`,adminA,{deletion_reason:'archivo controlado'});
        equal(r.status, 200, 'documento se archiva lógicamente');
        archived = (await db.query('SELECT deleted_at,datos FROM documentos_b2b WHERE id=$1',[createdDocument])).rows[0];
        check(!!archived.deleted_at && !!archived.datos, 'documento archivado conserva bytes y metadatos');
        r = await request('GET',`/api/b2b/documentos/${createdDocument}/download`,adminA);
        equal(r.status, 404, 'descarga normal excluye documento archivado');
        r = await request('GET','/api/b2b/documentos?paciente_id=1001',adminA);
        check(!r.body.some(row => row.id === createdDocument), 'listado normal excluye documento archivado');

        progress('Validando ledger append-only, sanitización y bridge');
        const auditJson = JSON.stringify((await db.query('SELECT before_data,after_data,metadata FROM auditoria_eventos_b2b')).rows);
        check(!/password|password_hash|jwt|authorization|api[_-]?key|secret|token/i.test(auditJson), 'ledger no contiene claves prohibidas');
        check(!auditJson.includes('QUJDRA==') && !auditJson.includes('RUZHSA=='), 'ledger no contiene base64 de documentos');
        check(!auditJson.includes('IMPOSTOR'), 'ledger no confía en _quien');
        const actorAudit = (await db.query("SELECT actor_usuario_id FROM auditoria_eventos_b2b WHERE recurso_tipo='administracion_medicamento' AND recurso_id=$1", [latestAdministration.id])).rows[0];
        equal(actorAudit.actor_usuario_id, 102, 'ledger atribuye actor autenticado vigente');
        const referenceAudit = (await db.query("SELECT after_data FROM auditoria_eventos_b2b WHERE recurso_tipo='administracion_medicamento' AND recurso_id=$1", [latestAdministration.id])).rows[0].after_data;
        check(!Object.prototype.hasOwnProperty.call(referenceAudit, 'notas') && !Object.prototype.hasOwnProperty.call(referenceAudit, 'administrador_nombre'), 'evento REFERENCE no duplica notas ni nombre visible');
        let triggerUpdateRejected = false;
        try { await db.query('UPDATE auditoria_eventos_b2b SET motivo=$1 WHERE id=(SELECT MIN(id) FROM auditoria_eventos_b2b)', ['forbidden']); } catch { triggerUpdateRejected = true; }
        check(triggerUpdateRejected, 'trigger rechaza UPDATE del ledger');
        let triggerDeleteRejected = false;
        try { await db.query('DELETE FROM auditoria_eventos_b2b WHERE id=(SELECT MIN(id) FROM auditoria_eventos_b2b)'); } catch { triggerDeleteRejected = true; }
        check(triggerDeleteRejected, 'trigger rechaza DELETE del ledger');

        r = await request('GET','/api/b2b/maintenance-status');
        equal(r.status, 200, 'estado de mantenimiento B2B responde sin credenciales');
        equal(r.body.maintenance, false, 'estado de mantenimiento refleja señal visual desactivada');
        check(/no-store/i.test(r.headers.get('cache-control') || ''), 'estado de mantenimiento prohíbe caché HTTP');

        process.env.B2B_MAINTENANCE_MODE = '1';
        r = await request('GET','/api/b2b/maintenance-status');
        equal(r.body.maintenance, true, 'estado de mantenimiento refleja señal visual activada');
        delete process.env.B2B_MAINTENANCE_MODE;

        process.env.B2B_P1_BRIDGE_MODE = '1';
        r = await request('GET','/api/b2b/citas?paciente_id=1001',adminA);
        equal(r.status, 200, 'bridge permite lectura B2B');
        check(!r.body.some(row => row.id === 1303), 'bridge no reexpone archivados');
        r = await request('POST','/api/b2b/sintomas',adminA,{paciente_id:1001,descripcion:'bloqueada'});
        equal(r.status, 503, 'bridge bloquea mutaciones B2B');
        equal(r.body.code, 'B2B_P1_BRIDGE_READ_ONLY', 'bridge expone código estable');
        r = await request('POST','/api/admin/set-plan',null,{institucion_id:1,plan:'total'}, {'x-admin-key':'cualquier-fixture'});
        equal(r.status, 503, 'bridge también bloquea el mutador administrativo B2B fuera de /api/b2b');
        delete process.env.B2B_P1_BRIDGE_MODE;

        process.env.SUPERADMIN_KEY = 'p1-local-superadmin-key';
        r = await request('POST','/api/admin/set-plan',null,{institucion_id:1,plan:'total',note:'cambio sintético'},
            {'x-admin-key':'p1-local-superadmin-key'});
        equal(r.status, 200, 'canal lateral superadmin actualiza plan sintético');
        const planAudit = (await db.query("SELECT actor_tipo,motivo FROM auditoria_eventos_b2b WHERE recurso_tipo='plan' ORDER BY id DESC LIMIT 1")).rows[0];
        equal(planAudit.actor_tipo, 'superadmin_key', 'canal lateral identifica actor técnico');
        equal(planAudit.motivo, 'cambio sintético', 'canal lateral conserva motivo no secreto');
        delete process.env.SUPERADMIN_KEY;

        await db.query("UPDATE instituciones_b2b SET plan='total',plan_manual_expires_at=NOW()-INTERVAL '1 day' WHERE id=1");
        r = await request('POST','/api/b2b/pacientes',adminA,{nombre:'Alta tras vencimiento sintética'});
        equal(r.status, 201, 'vencimiento lazy de plan mantiene acción válida del trial sintético');
        equal((await db.query('SELECT plan FROM instituciones_b2b WHERE id=1')).rows[0].plan, 'free', 'vencimiento de plan se aplica');
        equal(Number((await db.query("SELECT COUNT(*) FROM auditoria_eventos_b2b WHERE recurso_tipo='plan' AND accion='TRANSITION' AND motivo='plan_manual_expired'")).rows[0].count), 1, 'vencimiento de plan queda auditado atómicamente');

        r = await request('POST','/api/login',null,{email:'b2c@example.invalid',password:'synthetic-b2c-password'});
        equal(r.status, 200, 'login B2C sintético no regresa');
        check(!jwt.decode(r.body.token).b2b, 'token B2C conserva contrato');
        equal(Number((await db.query('SELECT COUNT(*) FROM usuarios')).rows[0].count), inheritedCounts.b2c, 'P1 no muta tabla B2C');
        equal(externalAttempts, 0, 'cero intentos de conexión externa');

        progress('Matriz completa');
        console.log('P1-A/B INTEGRITY TEST: PASS');
        console.log(`TOTAL_ASSERTIONS=${assertions}`);
        console.log(`EXTERNAL_REQUEST_ATTEMPTS=${externalAttempts}`);
        console.log(`POSTGRES=18 local ephemeral 127.0.0.1:${port}/${TEST_DB}`);
        console.log('DATA=synthetic fixtures only');
    } finally {
        https.request = originalHttpsRequest;
        https.get = originalHttpsGet;
        global.fetch = originalFetch;
        delete process.env.B2B_P1_BRIDGE_MODE;
        delete process.env.B2B_MAINTENANCE_MODE;
        delete process.env.P1_TEST_DOC_LIMIT_BYTES;
        delete process.env.SUPERADMIN_KEY;
        if (server) await new Promise(resolve => server.close(resolve));
        if (appPool) await appPool.end().catch(() => {});
        if (db) await db.end().catch(() => {});
        if (adminClient) await adminClient.end().catch(() => {});
        if (pgStarted) spawnSync(PG_CTL, ['-D', dataDir, '-m', 'fast', '-w', 'stop'], { encoding: 'utf8' });
        const resolvedTemp = path.resolve(tempRoot);
        const resolvedOsTemp = path.resolve(os.tmpdir()) + path.sep;
        if (resolvedTemp.startsWith(resolvedOsTemp) && path.basename(resolvedTemp).startsWith('cuidadiario-p1-')) {
            fs.rmSync(resolvedTemp, { recursive: true, force: true });
        }
    }
}

main().catch(error => {
    console.error('P1-A/B INTEGRITY TEST: FAIL');
    console.error(error.stack || error.message);
    process.exitCode = 1;
});
