'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const net = require('net');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { Client } = require('pg');
const jwt = require('jsonwebtoken');
const { schemaSql, fixtureSql } = require('./p0-c-authorization.test');

const PG_BIN = 'C:\\Program Files\\PostgreSQL\\18\\bin';
const INITDB = path.join(PG_BIN, 'initdb.exe');
const PG_CTL = path.join(PG_BIN, 'pg_ctl.exe');
const TEST_SECRET = 'p1-local-d2-synthetic-secret-never-production';
const TEST_DB = `cuidadiario_p1_test_d2_${process.pid}`;
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
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }

function parseStoredZip(buffer) {
    const entries = new Map();
    let offset = 0;
    while (offset + 4 <= buffer.length && buffer.readUInt32LE(offset) === 0x04034b50) {
        const method = buffer.readUInt16LE(offset + 8);
        const compressedSize = buffer.readUInt32LE(offset + 18);
        const uncompressedSize = buffer.readUInt32LE(offset + 22);
        const nameLength = buffer.readUInt16LE(offset + 26);
        const extraLength = buffer.readUInt16LE(offset + 28);
        const nameStart = offset + 30;
        const name = buffer.subarray(nameStart, nameStart + nameLength).toString('utf8');
        const bodyStart = nameStart + nameLength + extraLength;
        const body = buffer.subarray(bodyStart, bodyStart + compressedSize);
        equal(method, 0, `${name}: método ZIP store`);
        equal(body.length, uncompressedSize, `${name}: tamaño ZIP coherente`);
        check(!entries.has(name), `${name}: sin colisión ZIP`);
        entries.set(name, Buffer.from(body));
        offset = bodyStart + compressedSize;
    }
    check(entries.size > 0, 'ZIP contiene entradas locales');
    return entries;
}

function jsonLines(entry) {
    const text = entry.toString('utf8').trim();
    return text ? text.split('\n').map(line => JSON.parse(line)) : [];
}

function assertSafeEntryNames(entries) {
    for (const name of entries.keys()) {
        check(!name.includes('\\'), `${name}: sin backslash`);
        check(!name.startsWith('/') && !/^[A-Za-z]:/.test(name), `${name}: ruta relativa`);
        check(!name.split('/').some(segment => segment === '..' || segment === '.'), `${name}: sin traversal`);
    }
}

async function waitForEmpty(directory) {
    for (let attempt = 0; attempt < 40; attempt += 1) {
        if (!fs.existsSync(directory) || fs.readdirSync(directory).length === 0) return true;
        await new Promise(resolve => setTimeout(resolve, 25));
    }
    return false;
}

async function main() {
    const progress = message => console.log(`[P1-D2] ${message}`);
    check(fs.existsSync(INITDB), 'PostgreSQL initdb 18 disponible');
    check(fs.existsSync(PG_CTL), 'PostgreSQL pg_ctl 18 disponible');

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cuidadiario-p1d2-test-'));
    const dataDir = path.join(tempRoot, 'pgdata');
    const logFile = path.join(tempRoot, 'postgres.log');
    const exportTempRoot = path.join(tempRoot, 'exports');
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
        progress('Inicializando PostgreSQL efímero y fixtures sintéticos A/B/B2C');
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
        await db.query(`CREATE TABLE historial_citas_b2b (
            id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, cita_id INTEGER, paciente_id INTEGER NOT NULL,
            titulo TEXT NOT NULL, descripcion TEXT, fecha TIMESTAMP NOT NULL, medico TEXT, especialidad TEXT,
            lugar TEXT, estado TEXT, archivado_en TIMESTAMP DEFAULT NOW(), archivado_por INTEGER
        )`);
        await db.query(fixtureSql);
        await db.query("DELETE FROM notas_b2b WHERE id=1804");
        await db.query("DELETE FROM asignaciones_b2b WHERE id IN (6,7)");
        await db.query("INSERT INTO usuarios(id,nombre,email,password_hash,premium) VALUES (501,'B2C Sintético','b2c-d2@example.invalid','B2C-SECRET-HASH',FALSE)");

        Object.assign(process.env, {
            P1_TEST_MODE: '1', PGHOST: '127.0.0.1', PGPORT: String(port), PGUSER: 'p1_admin',
            PGPASSWORD: '', PGDATABASE: TEST_DB, JWT_SECRET: TEST_SECRET, NODE_ENV: 'test',
            P1D2_TEST_TEMP_ROOT: exportTempRoot,
        });
        delete process.env.P0C_TEST_MODE;
        for (const name of ['DATABASE_URL','DATABASE_PUBLIC_URL','RESEND_API_KEY','MP_ACCESS_TOKEN','MP_WEBHOOK_SECRET',
            'PAYPAL_CLIENT_ID','PAYPAL_CLIENT_SECRET','VAPID_PUBLIC_KEY','VAPID_PRIVATE_KEY','BACKEND_URL','RAILWAY_STATIC_URL']) {
            delete process.env[name];
        }
        https.request = function blockedHttpsRequest() { externalAttempts += 1; throw new Error('P1-D2 guard: HTTPS externo bloqueado'); };
        https.get = function blockedHttpsGet() { externalAttempts += 1; throw new Error('P1-D2 guard: HTTPS externo bloqueado'); };
        global.fetch = async function guardedFetch(input, init) {
            const url = new URL(typeof input === 'string' ? input : input.url);
            if (url.protocol !== 'http:' || !['127.0.0.1','localhost','::1'].includes(url.hostname)) {
                externalAttempts += 1;
                throw new Error(`P1-D2 guard: fetch externo bloqueado (${url.hostname})`);
            }
            return originalFetch(input, init);
        };

        const backend = require('../index');
        const d2 = require('../b2b-p1d2');
        appPool = backend.pool;
        await backend.runB2BP1Migrations(appPool);

        progress('Completando historia sintética, archivados, documentos y ledger');
        await db.query(`UPDATE usuarios_b2b SET password_hash='PASSWORD-HASH-LEAK-MARKER',
            reset_token='RESET-TOKEN-LEAK-MARKER',email_verification_token='VERIFY-TOKEN-LEAK-MARKER' WHERE id=101`);
        await db.query('UPDATE instituciones_b2b SET shared_mode=TRUE WHERE id=1');
        await db.query("UPDATE pacientes_b2b SET fecha_egreso='2026-09-30',motivo_egreso='Egreso sintético' WHERE id=1002");
        await db.query("UPDATE citas_b2b SET deleted_at=NOW(),deleted_by=101,deletion_reason='Archivo sintético' WHERE id=1303");
        await db.query("UPDATE sintomas_b2b SET deleted_at=NOW(),deleted_by=101,deletion_reason='Archivo sintético' WHERE id=1503");
        await db.query("UPDATE signos_vitales_b2b SET deleted_at=NOW(),deleted_by=101,deletion_reason='Archivo sintético' WHERE id=1603");
        await db.query("UPDATE contactos_b2b SET deleted_at=NOW(),deleted_by=101,deletion_reason='Archivo sintético' WHERE id=1703");
        await db.query("UPDATE notas_b2b SET deleted_at=NOW(),deleted_by=101,deletion_reason='Archivo sintético' WHERE id=1803");
        await db.query(`UPDATE documentos_b2b SET nombre_archivo='../../mismo.txt',deleted_at=NOW(),deleted_by=101,
            deletion_reason='Archivo sintético' WHERE id=1903`);
        await db.query("UPDATE documentos_b2b SET nombre_archivo='..\\\\..\\\\mismo.txt' WHERE id=1904");
        await db.query(`INSERT INTO historial_citas_b2b
            (id,institucion_id,cita_id,paciente_id,titulo,descripcion,fecha,estado,archivado_por)
            VALUES (1,1,1301,1001,'Cita histórica A','Sintética',NOW(),'realizada',101),
                   (2,2,2301,2001,'Cita histórica B','B-SECRET',NOW(),'realizada',201)`);
        await db.query(`INSERT INTO operadores_b2b
            (id,institucion_id,nombre,rol,activo,pin_hash,created_by_usuario_id)
            VALUES (501,1,'Operador A','admin_institucion',TRUE,'PIN-HASH-LEAK-MARKER',101),
                   (502,1,'Operador cuidador A','cuidador_staff',TRUE,'PIN-HASH-OTHER',101),
                   (601,2,'Operador B','admin_institucion',TRUE,'B-PIN-HASH',201)`);
        const operatorToken = 'a'.repeat(43);
        await db.query(`INSERT INTO operador_sesiones_b2b
            (id,institucion_id,operador_b2b_id,principal_usuario_id,token_hash,credential_version,expires_at)
            VALUES ('00000000-0000-4000-8000-000000000501',1,501,102,$1,1,NOW()+INTERVAL '1 hour')`, [sha256(operatorToken)]);
        await db.query(`INSERT INTO auditoria_eventos_b2b
            (institucion_id,paciente_id,actor_usuario_id,actor_tipo,operador_b2b_id,recurso_tipo,recurso_id,
             accion,recurso_version,motivo,before_data,after_data,capture_mode,metadata)
            VALUES
            (1,1001,101,'usuario',501,'paciente',1001,'UPDATE',2,'Evento A',
             '{"nombre":"Anterior","password_hash":"AUDIT-PASSWORD-LEAK"}',
             '{"nombre":"Actual","nested":{"token":"AUDIT-TOKEN-LEAK"}}','DIFF',
             '{"url":"postgres://secret:secret@example.invalid/db","safe":"ok"}'),
            (2,2001,201,'usuario',NULL,'paciente',2001,'EVENT',1,'B-SECRET audit',
             NULL,'{"nombre":"B-SECRET"}','REFERENCE','{}')`);

        server = await new Promise((resolve, reject) => {
            const candidate = backend.app.listen(0, '127.0.0.1', () => resolve(candidate));
            candidate.once('error', reject);
        });
        const base = `http://127.0.0.1:${server.address().port}`;
        const token = (id, institution, role) => jwt.sign({
            id, institucion_id: institution, rol: role, email: `${id}@example.invalid`,
            nombre: `Usuario ${id}`, b2b: true, email_verified: true,
        }, TEST_SECRET, { expiresIn: '1h' });
        const adminA = token(101, 1, 'admin_institucion');
        const caregiverA = token(102, 1, 'cuidador_staff');
        const adminB = token(201, 2, 'admin_institucion');
        const inactiveInstitutionAdmin = token(301, 3, 'admin_institucion');
        const inactiveUser = token(106, 1, 'cuidador_staff');

        async function requestExport(authToken, headers = {}) {
            const response = await fetch(`${base}/api/b2b/institutional-export`, {
                headers: { Authorization: `Bearer ${authToken}`, ...headers }, cache: 'no-store',
            });
            const body = Buffer.from(await response.arrayBuffer());
            return { response, body };
        }

        progress('Validando autorización administrativa y P1-C');
        let response = await requestExport(caregiverA);
        equal(response.response.status, 403, 'cuidador no puede exportar institución');
        response = await requestExport(inactiveInstitutionAdmin);
        equal(response.response.status, 401, 'institución inactiva falla cerrada');
        response = await requestExport(inactiveUser);
        equal(response.response.status, 401, 'usuario inactivo falla cerrado');
        response = await requestExport(caregiverA, { 'X-B2B-Operator-Token': operatorToken });
        equal(response.response.status, 403, 'operador admin no eleva principal no administrador');

        progress('Descargando export completo del tenant A');
        response = await requestExport(adminA);
        equal(response.response.status, 200, 'admin A descarga export institucional');
        equal(response.response.headers.get('content-type'), 'application/zip', 'respuesta ZIP');
        check(/no-store/.test(response.response.headers.get('cache-control') || ''), 'respuesta no-store');
        check(/attachment/i.test(response.response.headers.get('content-disposition') || ''), 'respuesta attachment');
        check(/cuidadiario-export-institucion-a-sintetica-/.test(response.response.headers.get('content-disposition') || ''), 'nombre de archivo seguro');
        equal(Number(response.response.headers.get('content-length')), response.body.length, 'Content-Length exacto');
        const zipProbePath = path.join(tempRoot, 'p1-d2-candidate.zip');
        fs.writeFileSync(zipProbePath, response.body, { mode: 0o600 });
        const tarProbe = spawnSync('tar', ['-tf', zipProbePath], { encoding: 'utf8' });
        equal(tarProbe.status, 0, 'ZIP aceptado por libarchive');
        check(tarProbe.stdout.split(/\r?\n/).filter(Boolean).length > 20, 'ZIP lista todas sus entradas');
        fs.rmSync(zipProbePath, { force: true });
        const entriesA = parseStoredZip(response.body);
        assertSafeEntryNames(entriesA);

        for (const required of ['manifest.json','manifest.sha256','checksums.sha256','README.txt','data/institucion.json',
            'data/usuarios.jsonl','data/pacientes.jsonl','data/asignaciones.jsonl','data/tareas.jsonl',
            'data/catalogo_medicamentos.jsonl','data/historial_restock.jsonl','data/historial_citas.jsonl',
            'data/operadores.jsonl','documents/index.jsonl','audit/eventos.jsonl','audit/eventos.csv',
            'views/residentes.csv','views/staff.csv','views/documentos.csv']) {
            check(entriesA.has(required), `${required}: presente`);
        }
        const manifest = JSON.parse(entriesA.get('manifest.json').toString('utf8'));
        equal(manifest.schema, 'cuidadiario-institutional-export/v1', 'schema de manifest v1');
        equal(Number(manifest.institution.id), 1, 'manifest identifica tenant A');
        equal(manifest.consistency.transaction_isolation, 'repeatable read', 'aislamiento repeatable read');
        equal(manifest.consistency.transaction_read_only, 'on', 'transacción read-only');
        equal(manifest.schema_migrations_b2b.length, 4, 'cuatro migraciones P1/P1-C');
        check(manifest.counts.pacientes >= 3 && manifest.counts.documentos >= 4, 'conteos completos del tenant');
        equal(manifest.counts.auditoria_eventos, 1, 'conteo ledger tenant A');
        check(manifest.warnings.some(item => item.code === 'DECLARED_SIZE_MISMATCH'), 'manifest explicita tamaños documentales heredados divergentes');

        const manifestDigestLine = entriesA.get('manifest.sha256').toString('utf8').trim();
        equal(manifestDigestLine, `${sha256(entriesA.get('manifest.json'))}  manifest.json`, 'digest del manifest válido');
        const checksumLines = entriesA.get('checksums.sha256').toString('utf8').trim().split('\n');
        const checksums = new Map(checksumLines.map(line => [line.slice(66), line.slice(0, 64)]));
        for (const file of manifest.files) {
            check(entriesA.has(file.path), `${file.path}: inventariado y presente`);
            equal(sha256(entriesA.get(file.path)), file.sha256, `${file.path}: hash manifest válido`);
            if (file.path !== 'checksums.sha256') equal(checksums.get(file.path), file.sha256, `${file.path}: hash checksums válido`);
        }

        const patientsA = jsonLines(entriesA.get('data/pacientes.jsonl'));
        check(patientsA.some(row => row.fecha_egreso && row.motivo_egreso === 'Egreso sintético'), 'residentes egresados incluidos');
        const appointmentsA = jsonLines(entriesA.get('data/citas.jsonl'));
        check(appointmentsA.some(row => row.deleted_at && row.deletion_reason === 'Archivo sintético'), 'citas soft-deleted incluidas');
        const documentsA = jsonLines(entriesA.get('documents/index.jsonl'));
        equal(documentsA.length, 4, 'documentos activos y archivados incluidos');
        check(documentsA.some(row => row.deleted_at), 'documento archivado incluido');
        equal(new Set(documentsA.map(row => row.package_path)).size, documentsA.length, 'nombres documentales sin colisión');
        check(documentsA.every(row => /^documents\/\d+\/original\.[a-z0-9]+$/.test(row.package_path)), 'rutas documentales determinísticas');
        for (const document of documentsA) {
            check(entriesA.has(document.package_path), `${document.package_path}: binario presente`);
            equal(sha256(entriesA.get(document.package_path)), document.original_sha256, `${document.package_path}: hash original válido`);
            equal(entriesA.get(document.package_path).length, document.original_bytes, `${document.package_path}: tamaño original válido`);
        }

        const usersA = jsonLines(entriesA.get('data/usuarios.jsonl'));
        check(usersA.every(row => !('password_hash' in row) && !('reset_token' in row) && !('email_verification_token' in row)), 'usuarios sanitizados');
        const operatorsA = jsonLines(entriesA.get('data/operadores.jsonl'));
        check(operatorsA.every(row => !('pin_hash' in row) && !('credential_version' in row)), 'operadores sanitizados');
        check(!entriesA.has('data/operador_sesiones.jsonl') && !entriesA.has('data/operaciones_idempotentes.jsonl'), 'sesiones e idempotencia excluidas');
        const auditA = jsonLines(entriesA.get('audit/eventos.jsonl'));
        equal(auditA.length, 1, 'ledger A incluido');
        const auditText = entriesA.get('audit/eventos.jsonl').toString('utf8');
        check(!/AUDIT-PASSWORD-LEAK|AUDIT-TOKEN-LEAK|postgres:\/\//.test(auditText), 'ledger redacta secretos accidentales');
        check(manifest.audit_redactions.redactedFields >= 2 && manifest.audit_redactions.redactedValues >= 1, 'manifest informa redacciones');

        const allText = [...entriesA.entries()].filter(([name]) => /\.(json|jsonl|csv|txt|sha256)$/.test(name))
            .map(([, value]) => value.toString('utf8')).join('\n');
        check(!/B-SECRET|b2c-d2@example.invalid|B2C-SECRET-HASH/.test(allText), 'cero datos tenant B o B2C');
        check(!/PASSWORD-HASH-LEAK-MARKER|RESET-TOKEN-LEAK-MARKER|VERIFY-TOKEN-LEAK-MARKER|PIN-HASH-LEAK-MARKER/.test(allText), 'cero credenciales o hashes secretos');
        check(!/operador_sesiones_b2b.*token_hash/i.test(allText), 'cero hashes de sesión');

        progress('Validando export separado del tenant B');
        response = await requestExport(adminB);
        equal(response.response.status, 200, 'admin B descarga su propio export');
        const entriesB = parseStoredZip(response.body);
        const textB = [...entriesB.entries()].filter(([name]) => /\.(json|jsonl|csv|txt)$/.test(name))
            .map(([, value]) => value.toString('utf8')).join('\n');
        check(/B-SECRET/.test(textB), 'tenant B contiene sus fixtures');
        check(!/A1 permitido|Institución A Sintética/.test(textB), 'tenant B no contiene datos A');

        progress('Validando fail-closed de relación cross-tenant');
        await db.query("INSERT INTO asignaciones_b2b(id,institucion_id,cuidador_id,paciente_id,activa) VALUES (9991,1,101,2001,TRUE)");
        let relationFailure = null;
        try {
            await d2.createInstitutionalExport({ pool: appPool, institutionId: 1,
                principal: { id:101, institucion_id:1 }, tempRoot: exportTempRoot });
        } catch (error) { relationFailure = error; }
        equal(relationFailure?.code, 'P1D2_UNRESOLVED_TENANT_RELATION', 'relación cross-tenant aborta');
        await db.query('DELETE FROM asignaciones_b2b WHERE id=9991');
        check(await waitForEmpty(exportTempRoot), 'fallo de relación limpia temporales');

        progress('Validando snapshot consistente con mutación concurrente sintética');
        await db.query("UPDATE pacientes_b2b SET nombre='Nombre antes snapshot' WHERE id=1001");
        const snapshotResult = await d2.createInstitutionalExport({
            pool: appPool, institutionId: 1, principal: { id:101, institucion_id:1 }, tempRoot: exportTempRoot,
            hooks: { afterSnapshotEstablished: async () => {
                await db.query("UPDATE pacientes_b2b SET nombre='Nombre después snapshot' WHERE id=1001");
            } },
        });
        const snapshotEntries = parseStoredZip(fs.readFileSync(snapshotResult.zipPath));
        const snapshotPatients = jsonLines(snapshotEntries.get('data/pacientes.jsonl'));
        equal(snapshotPatients.find(row => Number(row.id) === 1001).nombre, 'Nombre antes snapshot', 'snapshot no mezcla mutación concurrente');
        await d2.cleanupExport(snapshotResult);
        check(await waitForEmpty(exportTempRoot), 'export directo limpia temporales');

        progress('Validando fallo inyectado y limpieza HTTP');
        response = await requestExport(adminA, { 'x-p1d2-fail-stage': 'after-structured-data' });
        equal(response.response.status, 500, 'fallo sintético responde 500');
        const failureBody = JSON.parse(response.body.toString('utf8'));
        equal(failureBody.code, 'P1D2_TEST_FAILURE', 'fallo sintético conserva código seguro');
        check(await waitForEmpty(exportTempRoot), 'fallo HTTP limpia temporales');

        progress('Validando UI controlada y regresión B2C sintética');
        const apiSource = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'js', 'api-b2b.js'), 'utf8');
        const configSource = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'js', 'configuracion.js'), 'utf8');
        const configHtml = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'pages', 'configuracion.html'), 'utf8');
        check(/async download\(path\)/.test(apiSource) && /cache:\s*'no-store'/.test(apiSource), 'cliente descarga sin caché');
        check(/descargarExportInstitucional/.test(configSource) && /institutional-export/.test(configSource), 'acción UI D2 conectada');
        check(/Exportación institucional completa/.test(configHtml) && /Reporte imprimible/.test(configHtml), 'UI distingue ZIP de reporte parcial');
        equal(Number((await db.query('SELECT COUNT(*) FROM usuarios')).rows[0].count), 1, 'tabla B2C sintética preservada');
        equal(externalAttempts, 0, 'cero tráfico externo');
        check(await waitForEmpty(exportTempRoot), 'cero temporales D2 al finalizar');

        console.log(`TOTAL_ASSERTIONS=${assertions}`);
        console.log('EXTERNAL_ATTEMPTS=0');
        console.log('P1_D2_TEST_RESULT=PASS');
    } finally {
        https.request = originalHttpsRequest;
        https.get = originalHttpsGet;
        global.fetch = originalFetch;
        if (server) await new Promise(resolve => server.close(resolve));
        if (appPool) await appPool.end().catch(() => {});
        if (db) await db.end().catch(() => {});
        if (adminClient) await adminClient.end().catch(() => {});
        if (pgStarted) spawnSync(PG_CTL, ['-D', dataDir, '-m', 'fast', '-w', 'stop'], { encoding: 'utf8' });
        fs.rmSync(tempRoot, { recursive: true, force: true });
    }
}

main().catch(error => {
    console.error(error.stack || error.message);
    process.exitCode = 1;
});
