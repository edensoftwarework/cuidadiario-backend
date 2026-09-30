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

const PG_BIN = 'C:\\Program Files\\PostgreSQL\\18\\bin';
const INITDB = path.join(PG_BIN, 'initdb.exe');
const PG_CTL = path.join(PG_BIN, 'pg_ctl.exe');
const TEST_SECRET = 'p0c-local-synthetic-secret-never-production';
const TEST_DB = `cuidadiario_p0c_test_${process.pid}`;

let unitAssertions = 0;
let httpAssertions = 0;
let phase = 'unit';
function check(value, message) {
    if (phase === 'unit') unitAssertions += 1;
    else httpAssertions += 1;
    assert.ok(value, message);
}
function equal(actual, expected, message) {
    if (phase === 'unit') unitAssertions += 1;
    else httpAssertions += 1;
    assert.strictEqual(actual, expected, message);
}
function hasNoForbidden(body, label) {
    const serialized = typeof body === 'string' ? body : JSON.stringify(body);
    check(!serialized.includes('A2-SECRET'), `${label}: no debe incluir datos de A2`);
    check(!serialized.includes('B-SECRET'), `${label}: no debe incluir datos del tenant B`);
}

function run(command, args, options = {}) {
    const result = spawnSync(command, args, { encoding: 'utf8', ...options });
    if (result.status !== 0) {
        throw new Error(`${path.basename(command)} falló (${result.status}): ${result.stderr || result.stdout}`);
    }
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

const schemaSql = `
CREATE TABLE instituciones_b2b (
  id INTEGER PRIMARY KEY, nombre TEXT NOT NULL, tipo TEXT, direccion TEXT, telefono TEXT, email TEXT,
  plan TEXT DEFAULT 'total', activa BOOLEAN DEFAULT TRUE, permisos_equipo JSONB DEFAULT '{}'::jsonb,
  onboarding_done BOOLEAN DEFAULT TRUE, stock_modelo TEXT DEFAULT 'familiar', shared_mode BOOLEAN DEFAULT FALSE,
  trial_started_at TIMESTAMP DEFAULT NOW(), discount_expires_at TIMESTAMP, plan_manual_expires_at TIMESTAMP,
  mp_preapproval_id TEXT, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE usuarios_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, nombre TEXT, email TEXT UNIQUE, password_hash TEXT,
  rol TEXT, activo BOOLEAN DEFAULT TRUE, email_verified BOOLEAN DEFAULT TRUE, turno TEXT,
  notif_prefs JSONB DEFAULT '{}'::jsonb, notif_last_seen_at TIMESTAMP,
  reset_token TEXT, reset_token_expiry TIMESTAMP, email_verification_token TEXT,
  email_verification_expiry TIMESTAMP, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE pacientes_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, nombre TEXT, apellido TEXT, fecha_nacimiento DATE,
  dni TEXT, foto_url TEXT, habitacion TEXT, obra_social TEXT, num_afiliado TEXT,
  contacto_familiar_nombre TEXT, contacto_familiar_tel TEXT, diagnostico TEXT, alergias TEXT,
  medico_cabecera TEXT, antecedentes TEXT, notas_ingreso TEXT, fecha_ingreso DATE DEFAULT CURRENT_DATE,
  fecha_egreso TIMESTAMP, motivo_egreso TEXT, activo BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE asignaciones_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, cuidador_id INTEGER NOT NULL,
  paciente_id INTEGER NOT NULL, activa BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW(),
  UNIQUE(cuidador_id, paciente_id)
);
CREATE TABLE catalogo_medicamentos_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER, nombre TEXT,
  principio_activo TEXT, presentacion TEXT, unidad TEXT, categoria TEXT,
  stock_actual INTEGER DEFAULT 0, stock_minimo INTEGER DEFAULT 5, activo BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE medicamentos_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL, catalogo_id INTEGER,
  nombre TEXT, dosis TEXT, frecuencia TEXT, hora_inicio TIME, hora_fin TIME, horarios_custom JSONB,
  instrucciones TEXT, stock INTEGER, activo BOOLEAN DEFAULT TRUE, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE historial_medicamentos_b2b (
  id SERIAL PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL, medicamento_id INTEGER,
  medicamento_nombre TEXT, dosis TEXT, administrado_por INTEGER, administrador_nombre TEXT, notas TEXT,
  cantidad INTEGER DEFAULT 1, fecha TIMESTAMP DEFAULT NOW()
);
CREATE TABLE citas_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL, titulo TEXT,
  descripcion TEXT, fecha TIMESTAMP, medico TEXT, especialidad TEXT, lugar TEXT,
  estado TEXT DEFAULT 'pendiente', created_by INTEGER, created_at TIMESTAMP DEFAULT NOW(), updated_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE tareas_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL, titulo TEXT,
  descripcion TEXT, categoria TEXT, frecuencia TEXT, hora TIME, activa BOOLEAN DEFAULT TRUE,
  created_by INTEGER, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE historial_tareas_b2b (
  id SERIAL PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL, tarea_id INTEGER,
  tarea_titulo TEXT, completado_por INTEGER, completador_nombre TEXT, notas TEXT, fecha TIMESTAMP DEFAULT NOW()
);
CREATE TABLE sintomas_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL, descripcion TEXT,
  intensidad TEXT, registrado_por INTEGER, registrador_nombre TEXT, fecha TIMESTAMP DEFAULT NOW()
);
CREATE TABLE signos_vitales_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL, tipo TEXT,
  valor TEXT, unidad TEXT, notas TEXT, registrado_por INTEGER, registrador_nombre TEXT, fecha TIMESTAMP DEFAULT NOW()
);
CREATE TABLE contactos_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL, nombre TEXT,
  relacion TEXT, telefono TEXT, email TEXT, es_principal BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE notas_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL, titulo TEXT,
  contenido TEXT, urgente BOOLEAN DEFAULT FALSE, autor_id INTEGER, autor_nombre TEXT, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE documentos_b2b (
  id INTEGER PRIMARY KEY, institucion_id INTEGER NOT NULL, paciente_id INTEGER NOT NULL,
  nombre_archivo TEXT, tipo_mime TEXT, tamanio_bytes INTEGER, datos TEXT,
  subido_por INTEGER, subido_nombre TEXT, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE historial_restock_b2b (
  id SERIAL PRIMARY KEY, institucion_id INTEGER NOT NULL, catalogo_id INTEGER, paciente_id INTEGER,
  nombre_item TEXT, stock_anterior INTEGER, cantidad_repuesta INTEGER, stock_nuevo INTEGER,
  notas TEXT, registrado_por INTEGER, registrado_nombre TEXT, created_at TIMESTAMP DEFAULT NOW()
);
CREATE TABLE usuarios (
  id INTEGER PRIMARY KEY, nombre TEXT, email TEXT UNIQUE, password_hash TEXT, premium BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT NOW()
);
`;

const fixtureSql = `
INSERT INTO instituciones_b2b (id,nombre,plan,activa,permisos_equipo) VALUES
(1,'Institución A Sintética','total',TRUE,'{"cuidador_staff_ver_todos_pacientes":false,"cuidador_staff_gestionar_catalogo":true,"cuidador_staff_eliminar_paciente":true,"familiar_ver_medicamentos":true,"familiar_ver_citas":true,"familiar_ver_tareas":true,"familiar_ver_sintomas":true,"familiar_ver_signos":true,"familiar_ver_contactos":false,"familiar_ver_notas":false,"familiar_ver_documentos":true}'),
(2,'Institución B Sintética','total',TRUE,'{}'),
(3,'Institución Inactiva Sintética','total',FALSE,'{}');
INSERT INTO usuarios_b2b (id,institucion_id,nombre,email,password_hash,rol,activo,email_verified) VALUES
(101,1,'Admin A','admin.a@example.invalid','x','admin_institucion',TRUE,TRUE),
(102,1,'Cuidador A1','cuidador.a1@example.invalid','x','cuidador_staff',TRUE,TRUE),
(103,1,'Cuidador A2','cuidador.a2@example.invalid','x','cuidador_staff',TRUE,TRUE),
(104,1,'Familiar A','familiar.a@example.invalid','x','familiar',TRUE,TRUE),
(105,1,'Médico A','medico.a@example.invalid','x','medico',TRUE,TRUE),
(106,1,'Inactivo A','inactivo.a@example.invalid','x','cuidador_staff',FALSE,TRUE),
(107,1,'No verificado A','no-verificado.a@example.invalid','x','cuidador_staff',TRUE,FALSE),
(109,1,'Rol inválido A','rol-invalido.a@example.invalid','x','rol_inventado',TRUE,TRUE),
(110,1,'Staff A para baja','staff.baja.a@example.invalid','x','cuidador_staff',TRUE,TRUE),
(201,2,'Admin B','admin.b@example.invalid','x','admin_institucion',TRUE,TRUE),
(301,3,'Admin Inactivo','admin.inactivo@example.invalid','x','admin_institucion',TRUE,TRUE);
INSERT INTO pacientes_b2b (id,institucion_id,nombre,apellido,fecha_nacimiento,diagnostico,activo) VALUES
(1001,1,'Residente A1','Sintético','1940-01-01','A1 permitido',TRUE),
(1002,1,'Residente A2','Sintético','1941-01-01','A2-SECRET diagnóstico',TRUE),
(1003,1,'Residente A3','Sintético','1942-01-01','A3 para baja',TRUE),
(2001,2,'Residente B1','Sintético','1943-01-01','B-SECRET diagnóstico',TRUE);
INSERT INTO asignaciones_b2b (id,institucion_id,cuidador_id,paciente_id,activa) VALUES
(1,1,102,1001,TRUE),(2,1,102,1003,TRUE),(3,1,104,1001,TRUE),(4,1,110,1002,TRUE),(5,2,201,2001,TRUE),
(6,2,102,2001,TRUE),(7,2,104,2001,TRUE);
INSERT INTO catalogo_medicamentos_b2b (id,institucion_id,paciente_id,nombre,stock_actual,stock_minimo) VALUES
(1200,1,NULL,'Catálogo institucional A',2,5),(1201,1,1001,'Catálogo A1',2,5),
(1202,1,1002,'A2-SECRET catálogo',2,5),(1203,1,NULL,'Catálogo A borrar',2,5),(2201,2,2001,'B-SECRET catálogo',2,5);
INSERT INTO medicamentos_b2b (id,institucion_id,paciente_id,catalogo_id,nombre,dosis,frecuencia,stock) VALUES
(1101,1,1001,NULL,'Medicamento A1','1','diaria',5),(1102,1,1002,NULL,'A2-SECRET medicamento','2','diaria',5),
(1103,1,1003,NULL,'Medicamento A3','1','diaria',5),(1104,1,1001,NULL,'Medicamento A1 borrar','1','diaria',5),
(2101,2,2001,NULL,'B-SECRET medicamento','1','diaria',5);
INSERT INTO historial_medicamentos_b2b (institucion_id,paciente_id,medicamento_id,medicamento_nombre,dosis,administrado_por,administrador_nombre,notas,fecha) VALUES
(1,1001,1101,'Medicamento A1','1',102,'Cuidador A1','A1 historial',NOW()),
(1,1002,1102,'A2-SECRET medicamento','2',103,'Cuidador A2','A2-SECRET historial',NOW()),
(2,2001,2101,'B-SECRET medicamento','1',201,'Admin B','B-SECRET historial',NOW());
INSERT INTO citas_b2b (id,institucion_id,paciente_id,titulo,descripcion,fecha,estado) VALUES
(1301,1,1001,'Cita A1','A1 cita',NOW()+INTERVAL '1 day','pendiente'),
(1302,1,1002,'A2-SECRET cita','A2-SECRET',NOW()+INTERVAL '1 day','pendiente'),
(1303,1,1001,'Cita A1 borrar','A1',NOW()+INTERVAL '2 day','pendiente'),
(2301,2,2001,'B-SECRET cita','B-SECRET',NOW()+INTERVAL '1 day','pendiente');
INSERT INTO tareas_b2b (id,institucion_id,paciente_id,titulo,descripcion,activa) VALUES
(1401,1,1001,'Tarea A1','A1 tarea',TRUE),(1402,1,1002,'A2-SECRET tarea','A2-SECRET',TRUE),
(1403,1,1001,'Tarea A1 borrar','A1',TRUE),(2401,2,2001,'B-SECRET tarea','B-SECRET',TRUE);
INSERT INTO historial_tareas_b2b (institucion_id,paciente_id,tarea_id,tarea_titulo,completado_por,completador_nombre,notas,fecha) VALUES
(1,1001,1401,'Tarea A1',102,'Cuidador A1','A1 cumplida',NOW()),
(1,1002,1402,'A2-SECRET tarea',103,'Cuidador A2','A2-SECRET cumplida',NOW()),
(2,2001,2401,'B-SECRET tarea',201,'Admin B','B-SECRET cumplida',NOW());
INSERT INTO sintomas_b2b (id,institucion_id,paciente_id,descripcion,intensidad,fecha) VALUES
(1501,1,1001,'Síntoma A1','1',NOW()),(1502,1,1002,'A2-SECRET síntoma','2',NOW()),
(1503,1,1001,'Síntoma A1 borrar','1',NOW()),(2501,2,2001,'B-SECRET síntoma','3',NOW());
INSERT INTO signos_vitales_b2b (id,institucion_id,paciente_id,tipo,valor,unidad,notas,fecha) VALUES
(1601,1,1001,'temperatura','36.5','C','A1 signo',NOW()),(1602,1,1002,'temperatura','39','C','A2-SECRET signo',NOW()),
(1603,1,1001,'pulso','70','lpm','A1 borrar',NOW()),(2601,2,2001,'temperatura','38','C','B-SECRET signo',NOW());
INSERT INTO contactos_b2b (id,institucion_id,paciente_id,nombre,relacion,telefono,email,es_principal) VALUES
(1701,1,1001,'Contacto A1','hijo','111','a1@example.invalid',TRUE),
(1702,1,1002,'A2-SECRET contacto','hijo','222','a2@example.invalid',TRUE),
(1703,1,1001,'Contacto A1 borrar','otro','333','a3@example.invalid',FALSE),
(2701,2,2001,'B-SECRET contacto','hijo','444','b@example.invalid',TRUE);
INSERT INTO notas_b2b (id,institucion_id,paciente_id,titulo,contenido,urgente) VALUES
(1801,1,1001,'Nota A1','A1 contenido',TRUE),(1802,1,1002,'A2-SECRET nota','A2-SECRET contenido',TRUE),
(1803,1,1001,'Nota A1 borrar','A1 borrar',FALSE),(1804,1,9999,'Nota huérfana','ORPHAN-SECRET',FALSE),
(2801,2,2001,'B-SECRET nota','B-SECRET contenido',TRUE);
INSERT INTO documentos_b2b (id,institucion_id,paciente_id,nombre_archivo,tipo_mime,tamanio_bytes,datos,subido_por,subido_nombre) VALUES
(1901,1,1001,'a1.txt','text/plain',11,'QTEtRE9DVU1FTlQ=',102,'Cuidador A1'),
(1902,1,1002,'a2-secret.txt','text/plain',9,'QTItU0VDUkVU',102,'Cuidador A1'),
(1903,1,1001,'a1-delete.txt','text/plain',9,'QTEtREVMRVRF',102,'Cuidador A1'),
(1904,1,1002,'a2-admin-delete.txt','text/plain',9,'QTIrQURNSU4=',101,'Admin A'),
(2901,2,2001,'b-secret.txt','text/plain',8,'Qi1TRUNSRVQ=',201,'Admin B');
INSERT INTO historial_restock_b2b (institucion_id,catalogo_id,paciente_id,nombre_item,stock_anterior,cantidad_repuesta,stock_nuevo,notas,registrado_por,registrado_nombre) VALUES
(1,1201,1001,'Catálogo A1',0,2,2,'A1 restock',102,'Cuidador A1'),
(1,1202,1002,'A2-SECRET catálogo',0,2,2,'A2-SECRET restock',103,'Cuidador A2'),
(2,2201,2001,'B-SECRET catálogo',0,2,2,'B-SECRET restock',201,'Admin B');
`;

async function main() {
    const progress = message => console.log(`[P0-C] ${message}`);
    check(fs.existsSync(INITDB), 'PostgreSQL initdb 18 debe estar disponible');
    check(fs.existsSync(PG_CTL), 'PostgreSQL pg_ctl 18 debe estar disponible');

    const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cuidadiario-p0c-'));
    const dataDir = path.join(tempRoot, 'pgdata');
    const logFile = path.join(tempRoot, 'postgres.log');
    const port = await freePort();
    let pgStarted = false;
    let server;
    let appPool;
    let adminClient;
    let db;
    let externalAttempts = 0;
    const originalHttpsRequest = https.request;
    const originalHttpsGet = https.get;
    const originalFetch = global.fetch;

    try {
        progress('Inicializando PostgreSQL efímero');
        run(INITDB, ['-D', dataDir, '--auth=trust', '--username=p0c_admin', '--no-locale', '--encoding=UTF8']);
        // En Windows el proceso postgres conserva abiertos los pipes de pg_ctl;
        // stdio=ignore evita que spawnSync espere indefinidamente por ese handle heredado.
        run(PG_CTL, ['-D', dataDir, '-l', logFile, '-o', `-h 127.0.0.1 -p ${port}`, '-w', 'start'], { stdio: 'ignore' });
        pgStarted = true;

        progress('Creando base y fixtures sintéticos');
        adminClient = new Client({ host: '127.0.0.1', port, user: 'p0c_admin', database: 'postgres', ssl: false });
        await adminClient.connect();
        await adminClient.query(`CREATE DATABASE ${TEST_DB}`);
        await adminClient.end();
        adminClient = null;

        db = new Client({ host: '127.0.0.1', port, user: 'p0c_admin', database: TEST_DB, ssl: false });
        await db.connect();
        await db.query(schemaSql);
        await db.query(fixtureSql);
        const b2cHash = await bcrypt.hash('synthetic-b2c-password', 4);
        await db.query("INSERT INTO usuarios (id,nombre,email,password_hash,premium) VALUES (501,'B2C Sintético','b2c@example.invalid',$1,FALSE)", [b2cHash]);

        Object.assign(process.env, {
            P0C_TEST_MODE: '1', PGHOST: '127.0.0.1', PGPORT: String(port),
            PGUSER: 'p0c_admin', PGPASSWORD: '', PGDATABASE: TEST_DB,
            JWT_SECRET: TEST_SECRET, NODE_ENV: 'test'
        });
        for (const name of [
            'DATABASE_URL','DATABASE_PUBLIC_URL','RESEND_API_KEY','MP_ACCESS_TOKEN','MP_WEBHOOK_SECRET',
            'PAYPAL_CLIENT_ID','PAYPAL_CLIENT_SECRET','VAPID_PUBLIC_KEY','VAPID_PRIVATE_KEY',
            'BACKEND_URL','RAILWAY_STATIC_URL'
        ]) delete process.env[name];

        https.request = function blockedHttpsRequest() {
            externalAttempts += 1;
            throw new Error('P0-C test guard: HTTPS externo bloqueado');
        };
        https.get = function blockedHttpsGet() {
            externalAttempts += 1;
            throw new Error('P0-C test guard: HTTPS externo bloqueado');
        };
        global.fetch = async function guardedFetch(input, init) {
            const url = new URL(typeof input === 'string' ? input : input.url);
            if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '::1'].includes(url.hostname)) {
                externalAttempts += 1;
                throw new Error(`P0-C test guard: fetch externo bloqueado (${url.hostname})`);
            }
            return originalFetch(input, init);
        };

        progress('Cargando backend con integraciones externas bloqueadas');
        const backend = require('../index');
        appPool = backend.pool;
        check(backend.checkB2BCanDo({ rol: 'admin_institucion', institucion_permisos: {} }, 'editar_paciente'), 'admin conserva permisos institucionales');
        check(!backend.checkB2BCanDo({ rol: 'familiar', institucion_permisos: {} }, 'editar_paciente'), 'familiar no obtiene permiso de mutación');
        check(backend.checkB2BFamiliarCanSee({ rol: 'familiar', institucion_permisos: {} }, 'medicamentos'), 'default familiar permite medicamentos');
        check(!backend.checkB2BFamiliarCanSee({ rol: 'familiar', institucion_permisos: {} }, 'notas'), 'default familiar niega notas');
        check(!backend.checkB2BFamiliarCanSee({ rol: 'familiar', institucion_permisos: { familiar_ver_documentos: false } }, 'documentos'), 'flag familiar deshabilita documentos');

        const badHost = spawnSync(process.execPath, ['-e', "require('./db')"], {
            cwd: path.join(__dirname, '..'), encoding: 'utf8', env: {
                ...process.env, PGHOST: 'railway.invalid', PGDATABASE: TEST_DB, P0C_TEST_MODE: '1'
            }
        });
        check(badHost.status !== 0, 'guard rechaza host no loopback');
        const badExternal = spawnSync(process.execPath, ['-e', "require('./db')"], {
            cwd: path.join(__dirname, '..'), encoding: 'utf8', env: {
                ...process.env, PGHOST: '127.0.0.1', PGDATABASE: TEST_DB,
                P0C_TEST_MODE: '1', RESEND_API_KEY: 'synthetic-must-be-rejected'
            }
        });
        check(badExternal.status !== 0, 'guard rechaza integraciones externas configuradas');

        progress('Iniciando HTTP local y ejecutando matriz');
        server = await new Promise((resolve, reject) => {
            const candidate = backend.app.listen(0, '127.0.0.1', () => resolve(candidate));
            candidate.once('error', reject);
        });
        const base = `http://127.0.0.1:${server.address().port}`;
        phase = 'http';

        async function request(method, route, token, body) {
            const headers = {};
            if (token) headers.Authorization = `Bearer ${token}`;
            if (body !== undefined) headers['Content-Type'] = 'application/json';
            const response = await fetch(`${base}${route}`, {
                method, headers, body: body === undefined ? undefined : JSON.stringify(body)
            });
            const text = await response.text();
            let parsed = text;
            try { parsed = text ? JSON.parse(text) : null; } catch {}
            return { status: response.status, headers: response.headers, body: parsed, text };
        }

        const token = (id, institucion_id, rol, extra = {}) => jwt.sign({
            id, institucion_id, rol, email: `${id}@example.invalid`, nombre: `Usuario ${id}`,
            b2b: true, email_verified: true, ...extra
        }, TEST_SECRET, { expiresIn: '1h' });
        const adminA = token(101, 1, 'admin_institucion');
        const caregiverA = token(102, 1, 'cuidador_staff');
        const caregiverA2 = token(103, 1, 'cuidador_staff');
        const familyA = token(104, 1, 'familiar');
        const doctorA = token(105, 1, 'medico');
        const adminB = token(201, 2, 'admin_institucion');

        // P0-4: estado vigente y claims actuales.
        let r = await request('GET', '/api/b2b/auth/me', adminA);
        equal(r.status, 200, 'A: JWT válido + usuario vigente');
        equal(r.body.rol, 'admin_institucion', 'A: rol vigente devuelto');
        r = await request('GET', '/api/b2b/auth/me', token(999, 1, 'admin_institucion'));
        equal(r.status, 401, 'B: usuario inexistente falla cerrado');
        r = await request('GET', '/api/b2b/auth/me', token(106, 1, 'cuidador_staff'));
        equal(r.status, 401, 'C: usuario deshabilitado falla cerrado');
        r = await request('GET', '/api/b2b/auth/me', token(201, 1, 'admin_institucion'));
        equal(r.status, 401, 'D: cambio/incoherencia de institución falla cerrado');
        r = await request('GET', '/api/b2b/reporte/export', token(102, 1, 'admin_institucion'));
        equal(r.status, 403, 'E: cambio de rol usa rol actual y no claim obsoleto');
        r = await request('GET', '/api/b2b/auth/me', token(301, 3, 'admin_institucion'));
        equal(r.status, 401, 'institución inactiva falla cerrado');
        r = await request('GET', '/api/b2b/auth/me', token(107, 1, 'cuidador_staff'));
        equal(r.status, 401, 'email no verificado falla cerrado');
        r = await request('GET', '/api/b2b/auth/me', token(109, 1, 'rol_inventado'));
        equal(r.status, 401, 'rol inválido falla cerrado');
        const b2cOnlyToken = jwt.sign({ id: 501, email: 'b2c@example.invalid' }, TEST_SECRET, { expiresIn: '1h' });
        r = await request('GET', '/api/b2b/auth/me', b2cOnlyToken);
        equal(r.status, 401, 'JWT B2C no atraviesa middleware B2B');
        const truthyButNotBooleanB2B = jwt.sign({ id: 101, institucion_id: 1, b2b: 'true' }, TEST_SECRET, { expiresIn: '1h' });
        r = await request('GET', '/api/b2b/auth/me', truthyButNotBooleanB2B);
        equal(r.status, 401, 'claim b2b debe ser booleano true, no sólo truthy');
        const malformedBearer = await fetch(`${base}/api/b2b/auth/me`, { headers: { Authorization: `Bearer ${adminA} extra` } });
        equal(malformedBearer.status, 401, 'Bearer con segmentos extra se rechaza');
        r = await request('GET', '/api/b2b/documentos/1901/download');
        equal(r.status, 401, 'documento sin autenticación responde 401');
        check(String(r.headers.get('cache-control')).includes('no-store'), '401 de documentos también usa no-store');

        // P0-6: todas las listas sensibles con filtro omitible.
        const listFamilies = [
            ['/api/b2b/medicamentos', 'medicamentos'],
            ['/api/b2b/medicamentos/historial', 'historial medicamentos'],
            ['/api/b2b/citas', 'citas'],
            ['/api/b2b/citas/historial', 'historial citas'],
            ['/api/b2b/tareas', 'tareas'],
            ['/api/b2b/tareas/historial', 'historial tareas'],
            ['/api/b2b/sintomas', 'síntomas'],
            ['/api/b2b/signos-vitales', 'signos'],
            ['/api/b2b/contactos', 'contactos'],
            ['/api/b2b/notas', 'notas'],
        ];
        for (const [route, label] of listFamilies) {
            r = await request('GET', route, caregiverA);
            equal(r.status, 400, `J ${label}: restringido sin paciente_id falla cerrado`);
        }
        for (const [route, label] of listFamilies) {
            r = await request('GET', `${route}?paciente_id=1001`, caregiverA);
            equal(r.status, 200, `K ${label}: residente asignado permitido`);
            hasNoForbidden(r.body, `K ${label}`);
            r = await request('GET', `${route}?paciente_id=1002`, caregiverA);
            equal(r.status, 403, `L ${label}: residente no asignado denegado`);
        }
        r = await request('GET', '/api/b2b/medicamentos', adminA);
        equal(r.status, 200, 'T: administrador conserva listado global legítimo');
        check(JSON.stringify(r.body).includes('A2-SECRET medicamento'), 'T: listado admin incluye ambos residentes del tenant');
        check(!JSON.stringify(r.body).includes('B-SECRET'), 'T: listado admin no cruza tenant');
        r = await request('GET', '/api/b2b/notas?paciente_id=1001', familyA);
        equal(r.status, 403, 'N: familiar con sección notas deshabilitada recibe 403');
        r = await request('GET', '/api/b2b/medicamentos?paciente_id=1001', familyA);
        equal(r.status, 200, 'M: familiar con sección medicamentos habilitada accede');
        hasNoForbidden(r.body, 'M medicamentos familiar');
        r = await request('GET', '/api/b2b/notificaciones', caregiverA);
        equal(r.status, 200, 'notificaciones de personal restringido responden');
        hasNoForbidden(r.body, 'notificaciones personal restringido');
        r = await request('GET', '/api/b2b/catalogo/stock-bajo', caregiverA);
        equal(r.status, 200, 'stock bajo sin filtro conserva inventario institucional/asignado');
        hasNoForbidden(r.body, 'stock bajo personal restringido');
        r = await request('GET', '/api/b2b/catalogo/stock-bajo?paciente_id=1002', caregiverA);
        equal(r.status, 403, 'stock bajo de residente no asignado se deniega');
        r = await request('GET', '/api/b2b/catalogo/restock-historial', caregiverA);
        equal(r.status, 200, 'restock sin filtro se limita a institucional/asignado');
        hasNoForbidden(r.body, 'restock personal restringido');
        r = await request('GET', '/api/b2b/catalogo/restock-historial?paciente_id=1002', caregiverA);
        equal(r.status, 403, 'restock de residente no asignado se deniega');
        r = await request('GET', '/api/b2b/catalogo/restock-historial', familyA);
        equal(r.status, 400, 'restock familiar sin paciente_id falla cerrado');
        r = await request('GET', '/api/b2b/medicamentos?paciente_id=1001abc', caregiverA);
        equal(r.status, 400, 'paciente_id ambiguo se rechaza sin parseo parcial');
        r = await request('GET', '/api/b2b/pacientes?mis_asignados=1', caregiverA);
        equal(r.status, 200, 'listado de residentes asignados responde para personal restringido');
        hasNoForbidden(r.body, 'asignación inconsistente cross-tenant no amplía listado de personal');
        r = await request('GET', '/api/b2b/pacientes', familyA);
        equal(r.status, 200, 'listado de residentes asignados responde para familiar');
        hasNoForbidden(r.body, 'asignación inconsistente cross-tenant no amplía listado familiar');

        // Dashboard/reportes: flags familiares aplicadas por bloque.
        r = await request('GET', '/api/b2b/dashboard', familyA);
        equal(r.status, 200, 'R: dashboard familiar responde');
        equal(r.body.notas_urgentes.length, 0, 'R: dashboard omite notas deshabilitadas');
        check(r.body.sintomas_recientes.length > 0, 'R: dashboard conserva síntomas habilitados');
        hasNoForbidden(r.body, 'R dashboard familiar');
        r = await request('GET', '/api/b2b/reportes?paciente_id=1001', familyA);
        equal(r.status, 200, 'S: reporte familiar responde');
        equal(r.body.notas.length, 0, 'S: reporte omite notas deshabilitadas');
        equal(r.body.contactos.length, 0, 'S: reporte omite contactos deshabilitados');
        check(r.body.medicamentos.length > 0, 'S: reporte conserva medicamentos habilitados');
        hasNoForbidden(r.body, 'S reporte familiar');

        await db.query(`UPDATE instituciones_b2b
                        SET permisos_equipo=permisos_equipo || '{"familiar_ver_medicamentos":false,"familiar_ver_citas":false,"familiar_ver_tareas":false}'::jsonb
                        WHERE id=1`);
        r = await request('GET', '/api/b2b/dashboard', familyA);
        equal(r.status, 200, 'R: dashboard familiar responde con más secciones deshabilitadas');
        equal(r.body.resumen.tomas_hoy, 0, 'R: dashboard omite conteo de medicación deshabilitada');
        equal(r.body.resumen.tareas_completadas_hoy, 0, 'R: dashboard omite conteo de tareas deshabilitadas');
        equal(r.body.citas_proximas.length, 0, 'R: dashboard omite citas deshabilitadas');
        check(r.body.sintomas_recientes.length > 0, 'R: dashboard conserva síntomas aún habilitados');
        hasNoForbidden(r.body, 'R dashboard con secciones deshabilitadas');
        r = await request('GET', '/api/b2b/reportes?paciente_id=1001', familyA);
        equal(r.status, 200, 'S: reporte familiar responde con más secciones deshabilitadas');
        equal(r.body.medicamentos.length, 0, 'S: reporte omite medicamentos deshabilitados');
        equal(r.body.historial_medicamentos.length, 0, 'S: reporte omite historial de medicación deshabilitado');
        equal(r.body.citas.length, 0, 'S: reporte omite citas deshabilitadas');
        equal(r.body.historial_tareas.length, 0, 'S: reporte omite historial de tareas deshabilitado');
        check(r.body.sintomas.length > 0, 'S: reporte conserva síntomas aún habilitados');
        hasNoForbidden(r.body, 'S reporte con secciones deshabilitadas');
        r = await request('GET', '/api/b2b/catalogo?paciente_id=1001', familyA);
        equal(r.status, 403, 'N: catálogo por residente respeta sección medicamentos deshabilitada');
        r = await request('GET', '/api/b2b/catalogo/restock-historial?paciente_id=1001', familyA);
        equal(r.status, 403, 'N: historial de restock respeta sección medicamentos deshabilitada');
        await db.query(`UPDATE instituciones_b2b
                        SET permisos_equipo=permisos_equipo || '{"familiar_ver_medicamentos":true,"familiar_ver_citas":true,"familiar_ver_tareas":true}'::jsonb
                        WHERE id=1`);

        // P0-5: cadena documento -> tenant -> residente -> sección -> ownership.
        r = await request('GET', '/api/b2b/documentos?paciente_id=1001', familyA);
        equal(r.status, 200, 'O: listado de documento permitido');
        check(String(r.headers.get('cache-control')).includes('no-store'), 'listado documentos usa no-store');
        equal(r.headers.get('pragma'), 'no-cache', 'listado documentos usa Pragma no-cache');
        r = await request('GET', '/api/b2b/documentos/1901/download', familyA);
        equal(r.status, 200, 'O: descarga permitida por residente/sección');
        equal(r.text, 'A1-DOCUMENT', 'O: bytes ficticios autorizados intactos');
        check(String(r.headers.get('cache-control')).includes('no-store'), 'descarga usa no-store');
        equal(r.headers.get('pragma'), 'no-cache', 'descarga usa Pragma no-cache');
        equal(r.headers.get('expires'), '0', 'descarga usa Expires 0');
        r = await request('GET', '/api/b2b/documentos/1902/download', familyA);
        equal(r.status, 404, 'P: documento de residente no asignado se oculta');
        hasNoForbidden(r.body, 'P documento no asignado');
        r = await request('GET', '/api/b2b/documentos/2901/download', familyA);
        equal(r.status, 404, 'Q: documento de otro tenant se oculta');
        hasNoForbidden(r.body, 'Q documento otro tenant');
        await db.query("UPDATE instituciones_b2b SET permisos_equipo=permisos_equipo || '{\"familiar_ver_documentos\":false}'::jsonb WHERE id=1");
        r = await request('GET', '/api/b2b/documentos/1901/download', familyA);
        equal(r.status, 404, 'documento se deniega al deshabilitar sección vigente');
        await db.query("UPDATE instituciones_b2b SET permisos_equipo=permisos_equipo || '{\"familiar_ver_documentos\":true}'::jsonb WHERE id=1");
        r = await request('DELETE', '/api/b2b/documentos/1902', caregiverA);
        equal(r.status, 404, 'DELETE documento exige acceso al residente aunque sea subidor');
        equal((await db.query('SELECT COUNT(*)::int AS n FROM documentos_b2b WHERE id=1902')).rows[0].n, 1, 'documento denegado no se elimina');
        r = await request('DELETE', '/api/b2b/documentos/1903', caregiverA);
        equal(r.status, 200, 'DELETE documento permite subidor con residente autorizado');
        equal((await db.query('SELECT COUNT(*)::int AS n FROM documentos_b2b WHERE id=1903')).rows[0].n, 0, 'documento autorizado sí se elimina');
        r = await request('DELETE', '/api/b2b/documentos/1904', adminA);
        equal(r.status, 200, 'admin puede eliminar documento de su tenant');

        // P0-7: mutaciones por ID resuelven recurso y residente antes de escribir.
        r = await request('PATCH','/api/b2b/staff/201',adminA,{nombre:'intrusión'});
        equal(r.status,404,'staff por ID de otro tenant permanece oculto');
        r = await request('PATCH','/api/b2b/staff/110',adminA,{nombre:'Staff A actualizado'});
        equal(r.status,200,'staff del tenant con admin permanece editable');
        r = await request('DELETE','/api/b2b/staff/201',adminA);
        equal(r.status,404,'staff DELETE cross-tenant permanece oculto');
        r = await request('DELETE','/api/b2b/staff/110',adminA);
        equal(r.status,200,'staff DELETE del tenant permanece permitido');
        r = await request('DELETE','/api/b2b/asignaciones/5',adminA);
        equal(r.status,404,'asignación DELETE cross-tenant permanece oculta');
        r = await request('DELETE','/api/b2b/asignaciones/4',adminA);
        equal(r.status,200,'asignación DELETE institucional autorizada permanece permitida');
        async function expectUnchanged(method, route, body, sql, expected, label) {
            const before = (await db.query(sql)).rows[0].value;
            equal(String(before), String(expected), `${label}: fixture inicial`);
            const response = await request(method, route, caregiverA, body);
            check([403, 404].includes(response.status), `${label}: mutación no autorizada denegada`);
            const after = (await db.query(sql)).rows[0].value;
            equal(String(after), String(expected), `${label}: datos permanecen intactos`);
        }
        await expectUnchanged('PATCH','/api/b2b/pacientes/1002',{nombre:'intrusión'},"SELECT nombre AS value FROM pacientes_b2b WHERE id=1002",'Residente A2','paciente PATCH no asignado');
        r = await request('PATCH','/api/b2b/pacientes/1001',caregiverA,{habitacion:'A1-controlada'});
        equal(r.status,200,'paciente PATCH asignado permitido');
        equal((await db.query('SELECT habitacion AS value FROM pacientes_b2b WHERE id=1001')).rows[0].value,'A1-controlada','paciente PATCH autorizado persiste');
        await expectUnchanged('PATCH','/api/b2b/medicamentos/1102',{nombre:'intrusión'},"SELECT nombre AS value FROM medicamentos_b2b WHERE id=1102",'A2-SECRET medicamento','medicamento PATCH no asignado');
        r = await request('PATCH','/api/b2b/medicamentos/1101',caregiverA,{nombre:'Medicamento A1 actualizado'});
        equal(r.status,200,'medicamento PATCH asignado permitido');
        r = await request('PATCH','/api/b2b/medicamentos/1101',caregiverA,{catalogo_id:1202});
        equal(r.status,403,'medicamento no puede vincular catálogo de otro residente');
        equal((await db.query('SELECT catalogo_id AS value FROM medicamentos_b2b WHERE id=1101')).rows[0].value,null,'vínculo de catálogo denegado no se persiste');
        r = await request('POST','/api/b2b/medicamentos',caregiverA,{paciente_id:1001,nombre:'No crear',catalogo_id:1202});
        equal(r.status,403,'alta de medicamento rechaza catálogo de otro residente');
        r = await request('PATCH','/api/b2b/medicamentos/2101',caregiverA,{nombre:'intrusión'});
        equal(r.status,404,'medicamento PATCH cross-tenant oculto');
        r = await request('PATCH','/api/b2b/medicamentos/999999',caregiverA,{nombre:'intrusión'});
        equal(r.status,404,'medicamento PATCH ID inexistente oculto');
        const historyBefore = Number((await db.query('SELECT COUNT(*) AS n FROM historial_medicamentos_b2b')).rows[0].n);
        r = await request('POST','/api/b2b/medicamentos/1102/toma',caregiverA,{cantidad:1});
        equal(r.status,404,'toma no asignada denegada antes de insertar');
        equal(Number((await db.query('SELECT COUNT(*) AS n FROM historial_medicamentos_b2b')).rows[0].n),historyBefore,'toma denegada no crea historial');
        r = await request('POST','/api/b2b/medicamentos/1101/toma',caregiverA,{cantidad:1});
        equal(r.status,201,'toma asignada permitida');
        equal(Number((await db.query('SELECT COUNT(*) AS n FROM historial_medicamentos_b2b')).rows[0].n),historyBefore+1,'toma autorizada crea historial');
        r = await request('DELETE','/api/b2b/medicamentos/1102',caregiverA);
        equal(r.status,404,'medicamento DELETE no asignado denegado');
        equal((await db.query('SELECT activo AS value FROM medicamentos_b2b WHERE id=1102')).rows[0].value,true,'medicamento denegado permanece activo');
        r = await request('DELETE','/api/b2b/medicamentos/1104',caregiverA);
        equal(r.status,200,'medicamento DELETE asignado permitido');
        await expectUnchanged('PATCH','/api/b2b/citas/1302',{titulo:'intrusión'},"SELECT titulo AS value FROM citas_b2b WHERE id=1302",'A2-SECRET cita','cita PATCH no asignada');
        r = await request('PATCH','/api/b2b/citas/1301',caregiverA,{titulo:'Cita A1 actualizada'});
        equal(r.status,200,'cita PATCH asignada permitida');
        r = await request('DELETE','/api/b2b/citas/1302',caregiverA);
        equal(r.status,404,'cita DELETE no asignada denegada');
        r = await request('DELETE','/api/b2b/citas/1303',caregiverA);
        equal(r.status,200,'cita DELETE asignada permitida');
        await expectUnchanged('PATCH','/api/b2b/tareas/1402',{titulo:'intrusión'},"SELECT titulo AS value FROM tareas_b2b WHERE id=1402",'A2-SECRET tarea','tarea PATCH no asignada');
        r = await request('PATCH','/api/b2b/tareas/1401',caregiverA,{titulo:'Tarea A1 actualizada'});
        equal(r.status,200,'tarea PATCH asignada permitida');
        const tasksBefore = Number((await db.query('SELECT COUNT(*) AS n FROM historial_tareas_b2b')).rows[0].n);
        r = await request('POST','/api/b2b/tareas/1402/completar',caregiverA,{notas:'intrusión'});
        equal(r.status,403,'completar tarea no asignada denegado');
        equal(Number((await db.query('SELECT COUNT(*) AS n FROM historial_tareas_b2b')).rows[0].n),tasksBefore,'tarea denegada no crea historial');
        r = await request('POST','/api/b2b/tareas/1401/completar',caregiverA,{notas:'A1 completada'});
        equal(r.status,201,'completar tarea asignada permitido');
        r = await request('DELETE','/api/b2b/tareas/1402',caregiverA);
        equal(r.status,404,'tarea DELETE no asignada denegada');
        r = await request('DELETE','/api/b2b/tareas/1403',caregiverA);
        equal(r.status,200,'tarea DELETE asignada permitida');
        await expectUnchanged('PATCH','/api/b2b/sintomas/1502',{descripcion:'intrusión'},"SELECT descripcion AS value FROM sintomas_b2b WHERE id=1502",'A2-SECRET síntoma','síntoma PATCH no asignado');
        r = await request('PATCH','/api/b2b/sintomas/1501',caregiverA,{descripcion:'Síntoma A1 actualizado',intensidad:'2'});
        equal(r.status,200,'síntoma PATCH asignado permitido');
        r = await request('DELETE','/api/b2b/sintomas/1502',caregiverA);
        equal(r.status,404,'síntoma DELETE no asignado denegado');
        r = await request('DELETE','/api/b2b/sintomas/1503',caregiverA);
        equal(r.status,200,'síntoma DELETE asignado permitido');
        r = await request('DELETE','/api/b2b/signos-vitales/1602',caregiverA);
        equal(r.status,404,'signo DELETE no asignado denegado');
        equal((await db.query('SELECT COUNT(*)::int AS n FROM signos_vitales_b2b WHERE id=1602')).rows[0].n,1,'signo denegado permanece');
        r = await request('DELETE','/api/b2b/signos-vitales/1603',caregiverA);
        equal(r.status,200,'signo DELETE asignado permitido');
        await expectUnchanged('PATCH','/api/b2b/contactos/1702',{nombre:'intrusión'},"SELECT nombre AS value FROM contactos_b2b WHERE id=1702",'A2-SECRET contacto','contacto PATCH no asignado');
        r = await request('PATCH','/api/b2b/contactos/1701',caregiverA,{nombre:'Contacto A1 actualizado'});
        equal(r.status,200,'contacto PATCH asignado permitido');
        r = await request('DELETE','/api/b2b/contactos/1702',caregiverA);
        equal(r.status,404,'contacto DELETE no asignado denegado');
        r = await request('DELETE','/api/b2b/contactos/1703',caregiverA);
        equal(r.status,200,'contacto DELETE asignado permitido');
        await expectUnchanged('PATCH','/api/b2b/notas/1802',{contenido:'intrusión'},"SELECT contenido AS value FROM notas_b2b WHERE id=1802",'A2-SECRET contenido','nota PATCH no asignada');
        r = await request('PATCH','/api/b2b/notas/1801',caregiverA,{contenido:'Nota A1 actualizada'});
        equal(r.status,200,'nota PATCH asignada permitida');
        r = await request('PATCH','/api/b2b/notas/1804',caregiverA,{contenido:'intrusión'});
        equal(r.status,404,'recurso con padre irresoluble falla cerrado');
        r = await request('DELETE','/api/b2b/notas/1802',caregiverA);
        equal(r.status,404,'nota DELETE no asignada denegada');
        r = await request('DELETE','/api/b2b/notas/1803',caregiverA);
        equal(r.status,200,'nota DELETE asignada permitida');
        await expectUnchanged('PATCH','/api/b2b/catalogo/1202',{stock_actual:99},"SELECT stock_actual::text AS value FROM catalogo_medicamentos_b2b WHERE id=1202",'2','catálogo de paciente no asignado');
        r = await request('PATCH','/api/b2b/catalogo/1201',caregiverA,{stock_actual:4});
        equal(r.status,200,'catálogo de paciente asignado permitido');
        r = await request('PATCH','/api/b2b/catalogo/1200',caregiverA,{stock_actual:3});
        equal(r.status,200,'catálogo institucional conserva permiso gestionar_catalogo');
        r = await request('DELETE','/api/b2b/catalogo/2201',adminA);
        equal(r.status,404,'catálogo DELETE cross-tenant permanece oculto');
        r = await request('DELETE','/api/b2b/catalogo/1203',adminA);
        equal(r.status,200,'catálogo DELETE institucional admin permanece permitido');
        r = await request('DELETE','/api/b2b/pacientes/1003',caregiverA);
        equal(r.status,200,'paciente DELETE asignado con permiso explícito permitido');
        equal((await db.query('SELECT activo AS value FROM pacientes_b2b WHERE id=1003')).rows[0].value,false,'paciente DELETE autorizado desactiva');
        r = await request('DELETE','/api/b2b/pacientes/1002',caregiverA);
        equal(r.status,404,'paciente DELETE no asignado denegado');
        equal((await db.query('SELECT activo AS value FROM pacientes_b2b WHERE id=1002')).rows[0].value,true,'paciente no asignado permanece activo');
        r = await request('PATCH','/api/b2b/notas/1801',familyA,{contenido:'intrusión familiar'});
        equal(r.status,403,'rol familiar no puede mutar aunque conozca ID asignado');

        // Revalidación inmediata entre requests.
        await db.query("UPDATE usuarios_b2b SET activo=FALSE WHERE id=103");
        r = await request('GET','/api/b2b/auth/me',caregiverA2);
        equal(r.status,401,'desactivación se aplica en el request siguiente');
        await db.query("UPDATE usuarios_b2b SET rol='familiar' WHERE id=105");
        r = await request('GET','/api/b2b/reporte/export',doctorA);
        equal(r.status,403,'cambio de rol se aplica en el request siguiente');
        await db.query('ALTER TABLE usuarios_b2b RENAME TO usuarios_b2b_temporalmente_inaccesible');
        try {
            r = await request('GET','/api/b2b/auth/me',adminA);
            equal(r.status,503,'falla de revalidación server-side deniega acceso');
        } finally {
            await db.query('ALTER TABLE usuarios_b2b_temporalmente_inaccesible RENAME TO usuarios_b2b');
        }

        // Regresión B2C: middleware/rutas originales no dependen de revalidación B2B.
        r = await request('GET','/api/test');
        equal(r.status,200,'B2C público /api/test permanece operativo');
        r = await request('POST','/api/login',null,{email:'b2c@example.invalid',password:'synthetic-b2c-password'});
        equal(r.status,200,'B2C login sintético permanece operativo');
        check(typeof r.body.token === 'string' && r.body.token.length > 20,'B2C login emite token');
        const b2cLoginToken = r.body.token;
        check(!jwt.decode(b2cLoginToken).b2b,'token B2C conserva contrato sin claim b2b');
        r = await request('GET','/dbtest',b2cLoginToken);
        equal(r.status,200,'middleware B2C acepta su token y consulta DB local');

        equal(externalAttempts,0,'ninguna prueba intentó contactar proveedores o dominios externos');
        progress('Matriz completa');
        console.log('P0-C AUTHORIZATION TEST: PASS');
        console.log(`UNIT_ASSERTIONS=${unitAssertions}`);
        console.log(`HTTP_ASSERTIONS=${httpAssertions}`);
        console.log(`TOTAL_ASSERTIONS=${unitAssertions + httpAssertions}`);
        console.log(`EXTERNAL_REQUEST_ATTEMPTS=${externalAttempts}`);
        console.log(`POSTGRES=18 local ephemeral 127.0.0.1:${port}/${TEST_DB}`);
    } finally {
        https.request = originalHttpsRequest;
        https.get = originalHttpsGet;
        global.fetch = originalFetch;
        if (server) await new Promise(resolve => server.close(resolve));
        if (appPool) await appPool.end().catch(() => {});
        if (db) await db.end().catch(() => {});
        if (adminClient) await adminClient.end().catch(() => {});
        if (pgStarted) spawnSync(PG_CTL, ['-D', dataDir, '-m', 'fast', '-w', 'stop'], { encoding: 'utf8' });
        const resolvedTemp = path.resolve(tempRoot);
        const resolvedOsTemp = path.resolve(os.tmpdir()) + path.sep;
        if (resolvedTemp.startsWith(resolvedOsTemp) && path.basename(resolvedTemp).startsWith('cuidadiario-p0c-')) {
            fs.rmSync(resolvedTemp, { recursive: true, force: true });
        }
    }
}

main().catch(error => {
    console.error('P0-C AUTHORIZATION TEST: FAIL');
    console.error(error.stack || error.message);
    process.exitCode = 1;
});
