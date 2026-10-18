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
const { schemaSql, fixtureSql } = require('./p0-c-authorization.test');
const { LA2_MIGRATION } = require('../b2b-la2');
const { LA3_MIGRATION } = require('../b2b-la3');
const crypto = require('crypto');

const PG_BIN = 'C:\\Program Files\\PostgreSQL\\18\\bin';
const INITDB = path.join(PG_BIN, 'initdb.exe');
const PG_CTL = path.join(PG_BIN, 'pg_ctl.exe');
const TEST_SECRET = 'p1-local-la2-synthetic-secret-never-production';
const TEST_DB = `cuidadiario_p1_test_la2_${process.pid}`;
let assertions = 0;

function check(value, message) { assertions += 1; assert.ok(value, message); }
function equal(actual, expected, message) { assertions += 1; assert.strictEqual(actual, expected, message); }
function run(command, args, options = {}) {
    const result = spawnSync(command, args, { encoding:'utf8', ...options });
    if (result.status !== 0) throw new Error(`${path.basename(command)} falló (${result.status}): ${result.stderr || result.stdout}`);
}
async function freePort() {
    return new Promise((resolve, reject) => {
        const server = net.createServer();
        server.once('error', reject);
        server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); });
    });
}

async function main() {
    check(fs.existsSync(INITDB), 'PostgreSQL initdb 18 disponible');
    check(fs.existsSync(PG_CTL), 'PostgreSQL pg_ctl 18 disponible');
    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cuidadiario-la2-'));
    const dataDir = path.join(tempRoot, 'pgdata');
    const logFile = path.join(tempRoot, 'postgres.log');
    const port = await freePort();
    let pgStarted = false;
    let adminClient;
    let db;
    let appPool;
    let server;
    let externalAttempts = 0;
    const originalHttpsRequest = https.request;
    const originalHttpsGet = https.get;
    const originalFetch = global.fetch;
    try {
        console.log('[LA2] Inicializando PostgreSQL efímero aislado');
        run(INITDB, ['-D',dataDir,'--auth=trust','--username=la2_admin','--no-locale','--encoding=UTF8']);
        run(PG_CTL, ['-D',dataDir,'-l',logFile,'-o',`-h 127.0.0.1 -p ${port}`,'-w','start'], { stdio:'ignore' });
        pgStarted = true;
        adminClient = new Client({ host:'127.0.0.1',port,user:'la2_admin',database:'postgres',ssl:false });
        await adminClient.connect();
        await adminClient.query(`CREATE DATABASE ${TEST_DB}`);
        await adminClient.end(); adminClient = null;
        db = new Client({ host:'127.0.0.1',port,user:'la2_admin',database:TEST_DB,ssl:false });
        await db.connect();
        await db.query(schemaSql);
        await db.query(fixtureSql);
        const b2cBefore = Number((await db.query('SELECT COUNT(*) FROM usuarios')).rows[0].count);
        const legacyAdministrations = Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b')).rows[0].count);

        Object.assign(process.env, { P1_TEST_MODE:'1',PGHOST:'127.0.0.1',PGPORT:String(port),PGUSER:'la2_admin',PGPASSWORD:'',PGDATABASE:TEST_DB,JWT_SECRET:TEST_SECRET,NODE_ENV:'test' });
        for (const name of ['DATABASE_URL','DATABASE_PUBLIC_URL','RESEND_API_KEY','MP_ACCESS_TOKEN','MP_WEBHOOK_SECRET','PAYPAL_CLIENT_ID','PAYPAL_CLIENT_SECRET','VAPID_PUBLIC_KEY','VAPID_PRIVATE_KEY','BACKEND_URL','RAILWAY_STATIC_URL']) delete process.env[name];
        https.request = function blockedHttpsRequest() { externalAttempts += 1; throw new Error('LA2: HTTPS externo bloqueado'); };
        https.get = function blockedHttpsGet() { externalAttempts += 1; throw new Error('LA2: HTTPS externo bloqueado'); };
        global.fetch = async function guardedFetch(input, init) {
            const url = new URL(typeof input === 'string' ? input : input.url);
            if (url.protocol !== 'http:' || !['127.0.0.1','localhost','::1'].includes(url.hostname)) {
                externalAttempts += 1;
                throw new Error(`LA2: tráfico externo bloqueado (${url.hostname})`);
            }
            return originalFetch(input, init);
        };

        const backend = require('../index');
        appPool = backend.pool;
        console.log('[LA2] Aplicando migración candidata dos veces');
        await backend.runB2BP1Migrations(appPool);
        await backend.runB2BP1Migrations(appPool);
        const checksum = crypto.createHash('sha256').update(LA2_MIGRATION.sql).digest('hex');
        const journal = await db.query("SELECT checksum FROM schema_migrations_b2b WHERE version='la_002_longitudinal_medication'");
        equal(journal.rowCount, 1, 'LA2 journal único');
        equal(journal.rows[0].checksum, checksum, 'checksum LA2 coincide');
        const la3Checksum = crypto.createHash('sha256').update(LA3_MIGRATION.sql).digest('hex');
        const la3Journal = await db.query("SELECT checksum FROM schema_migrations_b2b WHERE version='la_003_operational_reporting'");
        equal(la3Journal.rowCount,1,'LA3 journal único');
        equal(la3Journal.rows[0].checksum,la3Checksum,'checksum LA3 coincide');
        equal(Number((await db.query("SELECT COUNT(*) FROM information_schema.columns WHERE table_name='instituciones_b2b' AND column_name='timezone'")).rows[0].count),1,'timezone aditiva presente');
        equal(Number((await db.query("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('evoluciones_b2b','historial_esquemas_medicacion_b2b')")).rows[0].count), 2, 'tablas LA2 presentes');
        equal(Number((await db.query("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='medicamentos_b2b' AND column_name IN ('via','indicacion','prescriptor','vigente_desde','vigente_hasta','horarios_programados','esquema_version')")).rows[0].count), 7, 'columnas de esquema presentes');
        equal(Number((await db.query("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema='public' AND table_name='historial_medicamentos_b2b' AND column_name IN ('resultado','motivo_omision','programada_para','via','esquema_version','operador_b2b_id')")).rows[0].count), 6, 'columnas de administración presentes');
        equal(Number((await db.query("SELECT COUNT(*) FROM historial_esquemas_medicacion_b2b")).rows[0].count), 0, 'migración no fabrica historial de esquemas');
        equal(Number((await db.query("SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE resultado='administrada'")).rows[0].count), legacyAdministrations, 'tomas históricas preservadas como administraciones');
        equal(Number((await db.query('SELECT COUNT(*) FROM usuarios')).rows[0].count), b2cBefore, 'B2C preservado por migración');
        await db.query('UPDATE instituciones_b2b SET shared_mode=TRUE WHERE id=1');

        server = await new Promise((resolve, reject) => {
            const candidate = backend.app.listen(0,'127.0.0.1',() => resolve(candidate));
            candidate.once('error', reject);
        });
        const base = `http://127.0.0.1:${server.address().port}`;
        async function request(method, route, token, body, operatorToken, extraHeaders = {}) {
            const headers = { ...extraHeaders };
            if (token) headers.Authorization = `Bearer ${token}`;
            if (operatorToken) headers['X-B2B-Operator-Token'] = operatorToken;
            if (body !== undefined) headers['Content-Type'] = 'application/json';
            const response = await fetch(base + route, { method,headers,body:body === undefined ? undefined : JSON.stringify(body) });
            const text = await response.text();
            let parsed = text;
            try { parsed = text ? JSON.parse(text) : null; } catch {}
            return { status:response.status,body:parsed,headers:response.headers };
        }
        const token = (id, institution) => jwt.sign({ id,institucion_id:institution,b2b:true,email_verified:true }, TEST_SECRET, { expiresIn:'1h' });
        const adminA = token(101,1);
        const caregiverA = token(102,1);
        const adminB = token(201,2);

        let r = await request('POST','/api/b2b/operators',adminA,{ nombre:'Médico Sintético LA2',rol:'medico',pin:'246810' });
        equal(r.status, 201, 'operador sintético creado');
        const operatorId = Number(r.body.id);
        r = await request('POST','/api/b2b/operators/activate',adminA,{ operator_id:operatorId,pin:'246810' });
        equal(r.status, 200, 'operador activado con PIN');
        const operatorToken = r.body.operator_token;
        r = await request('POST','/api/b2b/operators',adminA,{ nombre:'Cuidador Operador Sintético',rol:'cuidador_staff',pin:'246811' });
        equal(r.status,201,'operador cuidador sintético creado');
        r = await request('POST','/api/b2b/operators/activate',adminA,{ operator_id:Number(r.body.id),pin:'246811' });
        equal(r.status,200,'operador cuidador activado');
        const caregiverOperatorToken=r.body.operator_token;

        console.log('[LA2] Validando evoluciones, aislamiento y actor');
        const evolutionKey = { 'Idempotency-Key':'la2-evolution-1' };
        r = await request('POST','/api/b2b/pacientes/1001/evoluciones',adminA,{ tipo:'evaluacion',titulo:'Evaluación sintética',contenido:'Seguimiento clínico sintético sin datos reales',ocurrido_at:'2026-10-07T12:00:00Z' },operatorToken,evolutionKey);
        equal(r.status, 201, 'evolución creada');
        const evolutionId = Number(r.body.id);
        r = await request('POST','/api/b2b/pacientes/1001/evoluciones',adminA,{ tipo:'evaluacion',titulo:'Evaluación sintética',contenido:'Seguimiento clínico sintético sin datos reales',ocurrido_at:'2026-10-07T12:00:00Z' },operatorToken,evolutionKey);
        equal(r.status, 201, 'replay de evolución responde igual');
        equal(r.headers.get('idempotent-replayed'), 'true', 'replay identificado');
        equal(Number((await db.query('SELECT COUNT(*) FROM evoluciones_b2b WHERE id=$1',[evolutionId])).rows[0].count), 1, 'idempotencia no duplica evolución');
        const evolutionActor = (await db.query('SELECT creado_por,operador_b2b_id FROM evoluciones_b2b WHERE id=$1',[evolutionId])).rows[0];
        equal(Number(evolutionActor.creado_por),101,'evolución conserva principal');
        equal(Number(evolutionActor.operador_b2b_id),operatorId,'evolución atribuye operador');
        r = await request('PATCH',`/api/b2b/evoluciones/${evolutionId}`,adminA,{ expected_version:1,contenido:'Seguimiento clínico sintético corregido' },operatorToken);
        equal(r.status,200,'evolución existente se corrige');
        equal(Number(r.body.version),2,'corrección de evolución incrementa versión');
        equal(r.body.contenido,'Seguimiento clínico sintético corregido','corrección de evolución persiste');
        r = await request('PATCH',`/api/b2b/evoluciones/${evolutionId}`,adminA,{ expected_version:1,contenido:'No debe pisar la corrección' },operatorToken);
        equal(r.status,409,'versión obsoleta de evolución no pisa cambios');
        equal(r.body.code,'VERSION_CONFLICT','conflicto de evolución conserva código explícito');
        equal(Number((await db.query("SELECT COUNT(*) FROM auditoria_eventos_b2b WHERE recurso_tipo='evolucion' AND recurso_id=$1 AND accion='CORRECTION'",[evolutionId])).rows[0].count),1,'corrección de evolución queda auditada');
        r = await request('GET','/api/b2b/pacientes/2001/evoluciones',adminA);
        equal(r.status,404,'tenant ajeno no accede a evoluciones');
        r = await request('GET','/api/b2b/pacientes/1002/timeline',caregiverA);
        equal(r.status,404,'personal no accede a paciente no asignado');
        await db.query("UPDATE pacientes_b2b SET fecha_egreso=clock_timestamp() WHERE id=1001");
        r = await request('POST','/api/b2b/pacientes/1001/evoluciones',adminA,{ tipo:'seguimiento',contenido:'No debe persistir' });
        check(r.status >= 400,'egreso bloquea nueva evolución');
        await db.query('UPDATE pacientes_b2b SET fecha_egreso=NULL WHERE id=1001');

        console.log('[LA2] Validando historia de esquemas y concurrencia');
        const medBefore = (await db.query('SELECT * FROM medicamentos_b2b WHERE id=1101')).rows[0];
        r = await request('PATCH','/api/b2b/medicamentos/1101',adminA,{ expected_version:Number(medBefore.version),dosis:'No debe persistir',motivo_cambio:'Operador incompetente' },caregiverOperatorToken);
        equal(r.status,403,'admin con operador cuidador no atribuye una prescripción profesional');
        r = await request('PATCH','/api/b2b/medicamentos/1101',adminA,{ expected_version:Number(medBefore.version),via:'Oral',indicacion:'Uso sintético controlado',prescriptor:'Profesional Sintético',vigente_desde:'2026-10-07T09:00:00Z',horarios_custom:['09:00','21:00'],horarios_programados:['08:00','20:00'],motivo_cambio:'Ajuste sintético del esquema' },operatorToken);
        equal(r.status,200,'prescripción ampliada actualizada');
        const medChanged = (await db.query('SELECT * FROM medicamentos_b2b WHERE id=1101')).rows[0];
        equal(Number(medChanged.esquema_version),2,'versión de esquema incrementada');
        equal(JSON.stringify(medChanged.horarios_custom),JSON.stringify(['09:00','21:00']),'horarios custom heredados se conservan como JSON válido');
        equal(Number((await db.query('SELECT COUNT(*) FROM historial_esquemas_medicacion_b2b WHERE medicamento_id=1101 AND esquema_version=1')).rows[0].count),1,'snapshot anterior conservado');
        r = await request('GET','/api/b2b/dashboard/direccion?desde=2026-01-01&hasta=2027-01-01&granularidad=mes',adminA);
        equal(r.status,200,'administrador consulta dashboard Dirección');
        equal(r.body.historicos.tareas_vencidas.estado,'no_disponible','no fabrica historia de tareas vencidas');
        r = await request('GET','/api/b2b/dashboard/direccion?desde=2026-01-01&hasta=2027-01-01&granularidad=mes',caregiverA);
        equal(r.status,403,'cuidador no accede por URL directa a Dirección');
        r = await request('GET','/api/b2b/dashboard',caregiverA);
        equal(r.status,200,'dashboard operativo conserva compatibilidad');
        check(Array.isArray(r.body.requiere_atencion),'dashboard operativo agrega requiere_atencion');
        r = await request('PATCH','/api/b2b/medicamentos/1101',adminA,{ expected_version:Number(medBefore.version),via:'Intravenosa',motivo_cambio:'Conflicto' });
        equal(r.status,409,'versión obsoleta no pisa prescripción');
        r = await request('PATCH','/api/b2b/medicamentos/1101',caregiverA,{ expected_version:Number(medChanged.version),via:'Otra',motivo_cambio:'No autorizado' });
        equal(r.status,403,'operativo no gestiona prescripción');
        r = await request('GET','/api/b2b/medicamentos/1101/esquemas',adminA);
        equal(r.status,200,'historial de esquema consultable');
        equal(r.body.historial.length,1,'historial expone snapshot exacto');

        console.log('[LA2] Validando administración, omisión e idempotencia');
        const stockBefore = Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=1101')).rows[0].stock);
        const adminKey = { 'Idempotency-Key':'la2-administration-1' };
        const adminBody = { resultado:'administrada',cantidad:1,programada_para:'2026-10-07T20:00:00Z',notas:'Administración sintética',_offline_ts:'2026-10-18T02:45:00.000Z' };
        r = await request('POST','/api/b2b/medicamentos/1101/administraciones',adminA,adminBody,operatorToken,adminKey);
        equal(r.status,201,'administración registrada');
        equal(r.body.resultado,'administrada','resultado explícito persistido');
        const offlineAdministrationId = Number(r.body.id);
        equal((await db.query("SELECT to_char(fecha,'YYYY-MM-DD HH24:MI:SS') AS fecha FROM historial_medicamentos_b2b WHERE id=$1",[offlineAdministrationId])).rows[0].fecha,
            '2026-10-17 23:45:00','administración offline UTC persiste como hora civil argentina sin doble conversión');
        r = await request('POST','/api/b2b/medicamentos/1101/administraciones',adminA,adminBody,operatorToken,adminKey);
        equal(r.status,201,'administración idempotente reproducida');
        equal(Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=1101')).rows[0].stock),stockBefore-1,'stock descontado una sola vez');
        r = await request('POST','/api/b2b/medicamentos/1101/administraciones',caregiverA,{ resultado:'omitida' },null,{ 'Idempotency-Key':'la2-omission-invalid' });
        equal(r.status,400,'omisión sin motivo rechazada');
        const stockBeforeOmission = Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=1101')).rows[0].stock);
        r = await request('POST','/api/b2b/medicamentos/1101/administraciones',caregiverA,{ resultado:'omitida',motivo_omision:'Paciente no disponible',notas:'Omisión sintética' },null,{ 'Idempotency-Key':'la2-omission-1' });
        equal(r.status,201,'omisión con motivo registrada');
        equal(Number((await db.query('SELECT stock FROM medicamentos_b2b WHERE id=1101')).rows[0].stock),stockBeforeOmission,'omisión no descuenta stock');
        r = await request('POST','/api/b2b/medicamentos/1101/toma',adminA,{ cantidad:1 },operatorToken,{ 'Idempotency-Key':'la2-legacy-toma' });
        equal(r.status,201,'ruta toma heredada conserva compatibilidad');
        equal(r.body.resultado,'administrada','ruta heredada produce administración');

        console.log('[LA2] Validando timeline compuesto y append-only');
        r = await request('POST','/api/b2b/pacientes/1001/evoluciones',adminA,{
            tipo:'seguimiento',ocurrido_at:'2026-10-18T03:00:00.000Z',
            titulo:'Seguimiento horario sintético',contenido:'Evento posterior a medianoche argentina',
        },operatorToken,{ 'Idempotency-Key':'la2-instant-time-1' });
        equal(r.status,201,'instante sintético posterior creado');
        const instantEvolutionId = Number(r.body.id);
        await db.query(`INSERT INTO estados_residente_b2b
            (institucion_id,paciente_id,tipo,iniciado_at,finalizado_at,motivo,iniciado_por,finalizado_por)
            VALUES (1,1001,'salida_familiar','2026-10-07T10:00:00-03:00','2026-10-07T18:00:00-03:00','Visita sintética',101,102)`);
        r = await request('GET','/api/b2b/pacientes/1001/timeline?limit=50',adminA);
        equal(r.status,200,'timeline consultable');
        const types = new Set(r.body.items.map(item => item.tipo));
        check(types.has('evaluacion'),'timeline incluye evolución');
        check(types.has('cambio_esquema'),'timeline incluye cambio de esquema');
        check(types.has('medicacion_administrada'),'timeline incluye administración');
        check(types.has('medicacion_omitida'),'timeline incluye omisión');
        const returnEvent = r.body.items.find(item => item.tipo === 'regreso');
        check(!!returnEvent, 'timeline incluye regreso como evento independiente');
        equal(returnEvent.source, 'estado_regreso', 'regreso conserva fuente explícita');
        equal(returnEvent.actor_nombre, 'Cuidador A1', 'regreso conserva actor de finalización');
        const offlineTimeline = r.body.items.find(item => item.source === 'administracion' && Number(item.source_id) === offlineAdministrationId);
        const instantTimeline = r.body.items.find(item => item.source === 'evolucion' && Number(item.source_id) === instantEvolutionId);
        equal(new Date(offlineTimeline.ocurrido_at).toISOString(),'2026-10-18T02:45:00.000Z','timeline convierte pared 23:45 AR al instante correcto');
        equal(new Date(instantTimeline.ocurrido_at).toISOString(),'2026-10-18T03:00:00.000Z','timeline conserva TIMESTAMPTZ absoluto');
        check(r.body.items.indexOf(instantTimeline) < r.body.items.indexOf(offlineTimeline),'timeline ordena correctamente el cruce de medianoche');
        check(r.body.items.every((item,index,items) => index === 0 || new Date(items[index-1].ocurrido_at) >= new Date(item.ocurrido_at)),'timeline ordenado descendentemente');
        let appendOnly = false;
        try { await db.query("UPDATE historial_esquemas_medicacion_b2b SET motivo='alterado'"); } catch { appendOnly = true; }
        check(appendOnly,'historial de esquemas es append-only');
        const administrationsBeforeRetire = Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=1101')).rows[0].count);
        const schemesBeforeRetire = Number((await db.query('SELECT COUNT(*) FROM historial_esquemas_medicacion_b2b WHERE medicamento_id=1101')).rows[0].count);
        r = await request('DELETE','/api/b2b/medicamentos/1101',adminA);
        equal(r.status,200,'retirar prescripción responde OK');
        equal((await db.query('SELECT activo FROM medicamentos_b2b WHERE id=1101')).rows[0].activo,false,'retirada desactiva sin borrar la prescripción');
        equal(Number((await db.query('SELECT COUNT(*) FROM historial_medicamentos_b2b WHERE medicamento_id=1101')).rows[0].count),administrationsBeforeRetire,'retirada conserva administraciones');
        equal(Number((await db.query('SELECT COUNT(*) FROM historial_esquemas_medicacion_b2b WHERE medicamento_id=1101')).rows[0].count),schemesBeforeRetire,'retirada conserva versiones de esquema');
        check(Number((await db.query("SELECT COUNT(*) FROM auditoria_eventos_b2b WHERE recurso_tipo='medicamento' AND recurso_id=1101 AND accion='SOFT_DELETE'")).rows[0].count) >= 1,'retirada conserva trazabilidad SOFT_DELETE');
        equal(Number((await db.query('SELECT COUNT(*) FROM usuarios')).rows[0].count),b2cBefore,'B2C continúa intacto');
        equal(externalAttempts,0,'cero tráfico externo');

        console.log('LA2 LONGITUDINAL MEDICATION TEST: PASS');
        console.log(`TOTAL_ASSERTIONS=${assertions}`);
        console.log(`MIGRATION=la_002_longitudinal_medication`);
        console.log(`MIGRATION_CHECKSUM=${checksum}`);
        console.log(`EXTERNAL_REQUEST_ATTEMPTS=${externalAttempts}`);
        console.log(`POSTGRES=18 local ephemeral 127.0.0.1:${port}/${TEST_DB}`);
        console.log('DATA=synthetic fixtures only');
    } finally {
        https.request = originalHttpsRequest;
        https.get = originalHttpsGet;
        global.fetch = originalFetch;
        if (server) await new Promise(resolve => server.close(resolve));
        if (appPool) await appPool.end().catch(() => {});
        if (db) await db.end().catch(() => {});
        if (adminClient) await adminClient.end().catch(() => {});
        if (pgStarted) spawnSync(PG_CTL,['-D',dataDir,'-m','fast','-w','stop'],{encoding:'utf8'});
        const resolved = path.resolve(tempRoot);
        if (resolved.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(resolved).startsWith('cuidadiario-la2-')) fs.rmSync(resolved,{recursive:true,force:true});
    }
}

main().catch(error => {
    console.error('LA2 LONGITUDINAL MEDICATION TEST: FAIL');
    console.error(error.stack || error.message);
    process.exitCode = 1;
});
