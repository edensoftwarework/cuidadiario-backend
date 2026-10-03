'use strict';

const crypto = require('crypto');

const SOFT_DELETE_TABLES = Object.freeze([
    'citas_b2b',
    'sintomas_b2b',
    'signos_vitales_b2b',
    'contactos_b2b',
    'notas_b2b',
    'documentos_b2b',
]);

const VERSIONED_TABLES = Object.freeze([
    'instituciones_b2b',
    'usuarios_b2b',
    'pacientes_b2b',
    'asignaciones_b2b',
    'medicamentos_b2b',
    'catalogo_medicamentos_b2b',
    'citas_b2b',
    'tareas_b2b',
    'sintomas_b2b',
    'signos_vitales_b2b',
    'contactos_b2b',
    'notas_b2b',
    'documentos_b2b',
]);

const COMMON_AUDIT_FIELDS = [
    'id', 'institucion_id', 'paciente_id', 'activo', 'activa', 'version',
    'deleted_at', 'deleted_by', 'deletion_reason', 'created_at', 'updated_at',
];

const AUDIT_FIELD_ALLOWLIST = Object.freeze({
    institucion: [...COMMON_AUDIT_FIELDS, 'nombre', 'tipo', 'direccion', 'telefono', 'email', 'plan',
        'stock_modelo', 'permisos_equipo', 'onboarding_done', 'shared_mode', 'trial_started_at',
        'discount_expires_at', 'plan_manual_expires_at', 'mp_preapproval_id'],
    usuario: [...COMMON_AUDIT_FIELDS, 'nombre', 'email', 'rol', 'email_verified', 'turno', 'notif_prefs', 'notif_last_seen_at'],
    paciente: [...COMMON_AUDIT_FIELDS, 'nombre', 'apellido', 'fecha_nacimiento', 'dni', 'foto_url',
        'habitacion', 'obra_social', 'num_afiliado', 'contacto_familiar_nombre', 'contacto_familiar_tel',
        'diagnostico', 'alergias', 'medico_cabecera', 'antecedentes', 'notas_ingreso', 'fecha_ingreso',
        'fecha_egreso', 'motivo_egreso'],
    asignacion: [...COMMON_AUDIT_FIELDS, 'cuidador_id'],
    medicamento: [...COMMON_AUDIT_FIELDS, 'catalogo_id', 'nombre', 'dosis', 'frecuencia', 'hora_inicio',
        'hora_fin', 'horarios_custom', 'instrucciones', 'stock'],
    administracion_medicamento: ['id', 'institucion_id', 'paciente_id', 'medicamento_id',
        'medicamento_nombre', 'dosis', 'administrado_por', 'administrador_nombre', 'notas', 'cantidad', 'fecha'],
    catalogo: [...COMMON_AUDIT_FIELDS, 'nombre', 'principio_activo', 'presentacion', 'unidad', 'categoria',
        'stock_actual', 'stock_minimo'],
    restock: ['id', 'institucion_id', 'paciente_id', 'catalogo_id', 'nombre_item', 'stock_anterior',
        'cantidad_repuesta', 'stock_nuevo', 'notas', 'registrado_por', 'registrado_nombre', 'created_at'],
    cita: [...COMMON_AUDIT_FIELDS, 'titulo', 'descripcion', 'fecha', 'medico', 'especialidad', 'lugar',
        'estado', 'created_by'],
    tarea: [...COMMON_AUDIT_FIELDS, 'titulo', 'descripcion', 'categoria', 'frecuencia', 'hora', 'created_by'],
    tarea_completada: ['id', 'institucion_id', 'paciente_id', 'tarea_id', 'tarea_titulo', 'completado_por',
        'completador_nombre', 'notas', 'fecha'],
    sintoma: [...COMMON_AUDIT_FIELDS, 'descripcion', 'intensidad', 'registrado_por', 'registrador_nombre', 'fecha'],
    signo_vital: [...COMMON_AUDIT_FIELDS, 'tipo', 'valor', 'unidad', 'notas', 'registrado_por',
        'registrador_nombre', 'fecha'],
    contacto: [...COMMON_AUDIT_FIELDS, 'nombre', 'relacion', 'telefono', 'email', 'es_principal'],
    nota: [...COMMON_AUDIT_FIELDS, 'titulo', 'contenido', 'urgente', 'autor_id', 'autor_nombre'],
    documento: [...COMMON_AUDIT_FIELDS, 'nombre_archivo', 'tipo_mime', 'tamanio_bytes', 'subido_por',
        'subido_nombre'],
    seguridad: ['id', 'institucion_id', 'email_verified', 'activo', 'rol', 'version'],
    plan: ['id', 'institucion_id', 'plan', 'plan_manual_expires_at', 'trial_started_at', 'mp_preapproval_id',
        'discount_expires_at', 'version'],
});

const FORBIDDEN_KEYS = /(?:password|password_hash|token|jwt|secret|authorization|api[_-]?key|datos|base64)/i;

const MIGRATIONS = Object.freeze([
    {
        version: 'p1_001_foundations',
        sql: `
CREATE TABLE IF NOT EXISTS auditoria_eventos_b2b (
    id BIGSERIAL PRIMARY KEY,
    institucion_id INTEGER NOT NULL,
    paciente_id INTEGER NULL,
    actor_usuario_id INTEGER NULL,
    actor_tipo VARCHAR(30) NOT NULL CHECK (actor_tipo IN ('usuario','sistema','proveedor','superadmin_key')),
    operador_usuario_id INTEGER NULL,
    recurso_tipo VARCHAR(80) NOT NULL,
    recurso_id BIGINT NULL,
    accion VARCHAR(30) NOT NULL CHECK (accion IN ('CREATE','UPDATE','CORRECTION','SOFT_DELETE','RESTORE','TRANSITION','SECURITY','EVENT')),
    recurso_version BIGINT NULL,
    ocurrido_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    motivo TEXT NULL,
    before_data JSONB NULL,
    after_data JSONB NULL,
    capture_mode VARCHAR(30) NOT NULL CHECK (capture_mode IN ('FULL_CREATE','FULL_BASELINE','DIFF','REDACTED','REFERENCE')),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_id UUID NULL
);
CREATE INDEX IF NOT EXISTS auditoria_b2b_tenant_fecha_idx
    ON auditoria_eventos_b2b (institucion_id, ocurrido_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS auditoria_b2b_recurso_idx
    ON auditoria_eventos_b2b (institucion_id, recurso_tipo, recurso_id, id);
CREATE INDEX IF NOT EXISTS auditoria_b2b_paciente_idx
    ON auditoria_eventos_b2b (institucion_id, paciente_id, ocurrido_at DESC)
    WHERE paciente_id IS NOT NULL;

CREATE OR REPLACE FUNCTION prevent_auditoria_eventos_b2b_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'auditoria_eventos_b2b es append-only'
        USING ERRCODE = '55000';
END;
$$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'auditoria_eventos_b2b_append_only'
          AND tgrelid = 'auditoria_eventos_b2b'::regclass
    ) THEN
        CREATE TRIGGER auditoria_eventos_b2b_append_only
        BEFORE UPDATE OR DELETE ON auditoria_eventos_b2b
        FOR EACH ROW EXECUTE FUNCTION prevent_auditoria_eventos_b2b_mutation();
    END IF;
END;
$$;

CREATE TABLE IF NOT EXISTS operaciones_idempotentes_b2b (
    id BIGSERIAL PRIMARY KEY,
    institucion_id INTEGER NOT NULL,
    paciente_id INTEGER NULL,
    actor_usuario_id INTEGER NOT NULL,
    operacion VARCHAR(100) NOT NULL,
    clave VARCHAR(128) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    estado VARCHAR(20) NOT NULL CHECK (estado IN ('processing','completed')),
    resultado_tipo VARCHAR(80) NULL,
    resultado_id BIGINT NULL,
    http_status INTEGER NULL,
    resultado JSONB NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    completed_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    UNIQUE (institucion_id, actor_usuario_id, operacion, clave)
);
CREATE INDEX IF NOT EXISTS idempotencia_b2b_expiry_idx
    ON operaciones_idempotentes_b2b (expires_at);
`,
    },
    {
        version: 'p1_002_versions',
        sql: VERSIONED_TABLES.map(table =>
            `ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0);`
        ).join('\n'),
    },
    {
        version: 'p1_003_soft_delete',
        sql: SOFT_DELETE_TABLES.map(table => `
ALTER TABLE ${table}
    ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS deleted_by INTEGER NULL,
    ADD COLUMN IF NOT EXISTS deletion_reason TEXT NULL;
`).join('\n'),
    },
]);

function migrationChecksum(sql) {
    return crypto.createHash('sha256').update(sql).digest('hex');
}

async function runB2BP1Migrations(pool) {
    const bootstrap = await pool.connect();
    try {
        await bootstrap.query(`
            CREATE TABLE IF NOT EXISTS schema_migrations_b2b (
                version TEXT PRIMARY KEY,
                checksum CHAR(64) NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
        `);
    } finally {
        bootstrap.release();
    }

    for (const migration of MIGRATIONS) {
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            await client.query("SELECT pg_advisory_xact_lock(hashtext('cuidadiario-b2b-p1-migrations'))");
            const checksum = migrationChecksum(migration.sql);
            const previous = await client.query(
                'SELECT checksum FROM schema_migrations_b2b WHERE version=$1 FOR UPDATE',
                [migration.version]
            );
            if (previous.rowCount > 0) {
                if (previous.rows[0].checksum !== checksum) {
                    throw new Error(`Checksum inválido para migración B2B ${migration.version}`);
                }
                await client.query('COMMIT');
                continue;
            }
            await client.query(migration.sql);
            await client.query(
                'INSERT INTO schema_migrations_b2b (version, checksum) VALUES ($1,$2)',
                [migration.version, checksum]
            );
            await client.query('COMMIT');
        } catch (error) {
            await client.query('ROLLBACK').catch(() => {});
            throw new Error(`Migración B2B ${migration.version} falló: ${error.message}`);
        } finally {
            client.release();
        }
    }
}

async function withB2BTransaction(pool, work) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const result = await work(client);
        await client.query('COMMIT');
        return result;
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
    } finally {
        client.release();
    }
}

function normalizeAuditValue(value) {
    if (value instanceof Date) return value.toISOString();
    if (Buffer.isBuffer(value)) return undefined;
    return value;
}

function sanitizeAuditObject(resourceType, value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const allowed = new Set(AUDIT_FIELD_ALLOWLIST[resourceType] || []);
    const result = {};
    for (const key of allowed) {
        if (FORBIDDEN_KEYS.test(key) || !Object.prototype.hasOwnProperty.call(value, key)) continue;
        const normalized = normalizeAuditValue(value[key]);
        if (normalized !== undefined) result[key] = normalized;
    }
    return result;
}

function sanitizeMetadata(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
    const allowed = new Set(['channel', 'result', 'reason_code', 'source', 'idempotent_replay', 'provider_event_id']);
    const clean = {};
    for (const [key, raw] of Object.entries(value)) {
        if (!allowed.has(key) || FORBIDDEN_KEYS.test(key)) continue;
        if (['string', 'number', 'boolean'].includes(typeof raw) || raw === null) clean[key] = raw;
    }
    return clean;
}

function sanitizeReferenceData(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
    const allowed = new Set([
        'id', 'institucion_id', 'paciente_id', 'medicamento_id', 'tarea_id', 'catalogo_id',
        'administrado_por', 'completado_por', 'registrado_por', 'cantidad', 'stock_anterior',
        'cantidad_repuesta', 'stock_nuevo', 'fecha', 'created_at'
    ]);
    const result = {};
    for (const key of allowed) {
        if (!Object.prototype.hasOwnProperty.call(value, key)) continue;
        const normalized = normalizeAuditValue(value[key]);
        if (normalized !== undefined) result[key] = normalized;
    }
    return result;
}

function changedFields(before, after) {
    const left = before || {};
    const right = after || {};
    const keys = new Set([...Object.keys(left), ...Object.keys(right)]);
    const beforeDiff = {};
    const afterDiff = {};
    for (const key of keys) {
        if (JSON.stringify(left[key]) !== JSON.stringify(right[key])) {
            beforeDiff[key] = left[key] ?? null;
            afterDiff[key] = right[key] ?? null;
        }
    }
    return { beforeDiff, afterDiff };
}

async function appendB2BAudit(client, input) {
    const before = sanitizeAuditObject(input.resourceType, input.before);
    const after = sanitizeAuditObject(input.resourceType, input.after);
    let captureMode = input.captureMode;
    let beforeData = before;
    let afterData = after;

    if (!captureMode && input.action === 'CREATE') captureMode = 'FULL_CREATE';
    if (!captureMode && input.action === 'EVENT') captureMode = 'REFERENCE';
    if (!captureMode && ['SECURITY'].includes(input.action)) captureMode = 'REDACTED';

    if (captureMode === 'REFERENCE') {
        beforeData = null;
        afterData = sanitizeReferenceData(input.after);
    }

    if (!captureMode) {
        const prior = await client.query(
            `SELECT 1 FROM auditoria_eventos_b2b
             WHERE institucion_id=$1 AND recurso_tipo=$2 AND recurso_id=$3 LIMIT 1`,
            [input.institutionId, input.resourceType, input.resourceId]
        );
        if (prior.rowCount === 0) {
            captureMode = 'FULL_BASELINE';
        } else {
            captureMode = 'DIFF';
            const diff = changedFields(before, after);
            beforeData = diff.beforeDiff;
            afterData = diff.afterDiff;
        }
    }

    const actor = input.actor || null;
    const actorType = input.actorType || (actor ? 'usuario' : 'sistema');
    const inserted = await client.query(
        `INSERT INTO auditoria_eventos_b2b
         (institucion_id, paciente_id, actor_usuario_id, actor_tipo, operador_usuario_id,
          recurso_tipo, recurso_id, accion, recurso_version, motivo, before_data, after_data,
          capture_mode, metadata, request_id)
         VALUES ($1,$2,$3,$4,NULL,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
         RETURNING id`,
        [
            input.institutionId,
            input.patientId || null,
            actor ? actor.id : null,
            actorType,
            input.resourceType,
            input.resourceId || null,
            input.action,
            input.version || null,
            input.reason || null,
            beforeData,
            afterData,
            captureMode,
            sanitizeMetadata(input.metadata),
            input.requestId || null,
        ]
    );
    return inserted.rows[0].id;
}

function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (!value || typeof value !== 'object') return value;
    const result = {};
    for (const key of Object.keys(value).sort()) {
        if (key === '_quien') continue;
        if (FORBIDDEN_KEYS.test(key)) continue;
        result[key] = canonicalize(value[key]);
    }
    return result;
}

function hashIdempotencyRequest(operation, resourceId, body) {
    const normalizedBody = canonicalize(body || {});
    if (typeof body?.datos === 'string') {
        normalizedBody.__document_sha256 = crypto.createHash('sha256').update(body.datos).digest('hex');
    }
    return crypto.createHash('sha256')
        .update(JSON.stringify({ operation, resourceId: resourceId || null, body: normalizedBody }))
        .digest('hex');
}

function getIdempotencyKey(req) {
    const raw = req.get ? req.get('Idempotency-Key') : req.headers?.['idempotency-key'];
    if (raw === undefined || raw === null || raw === '') return null;
    const key = String(raw).trim();
    if (!key || key.length > 128 || !/^[A-Za-z0-9._:-]+$/.test(key)) {
        const error = new Error('Idempotency-Key inválida');
        error.status = 400;
        error.code = 'INVALID_IDEMPOTENCY_KEY';
        throw error;
    }
    return key;
}

async function beginIdempotentOperation(client, { req, actor, operation, patientId, resourceId }) {
    const key = getIdempotencyKey(req);
    if (!key) return { enabled: false };
    const requestHash = hashIdempotencyRequest(operation, resourceId, req.body);
    const inserted = await client.query(
        `INSERT INTO operaciones_idempotentes_b2b
         (institucion_id,paciente_id,actor_usuario_id,operacion,clave,request_hash,estado,expires_at)
         VALUES ($1,$2,$3,$4,$5,$6,'processing',clock_timestamp()+INTERVAL '90 days')
         ON CONFLICT (institucion_id,actor_usuario_id,operacion,clave) DO NOTHING
         RETURNING id`,
        [actor.institucion_id, patientId || null, actor.id, operation, key, requestHash]
    );
    if (inserted.rowCount > 0) {
        return { enabled: true, id: inserted.rows[0].id, key, requestHash, replay: false };
    }

    const existing = await client.query(
        `SELECT * FROM operaciones_idempotentes_b2b
         WHERE institucion_id=$1 AND actor_usuario_id=$2 AND operacion=$3 AND clave=$4
         FOR UPDATE`,
        [actor.institucion_id, actor.id, operation, key]
    );
    const row = existing.rows[0];
    if (!row) throw new Error('No se pudo resolver la operación idempotente');

    if (new Date(row.expires_at).getTime() <= Date.now()) {
        const renewed = await client.query(
            `UPDATE operaciones_idempotentes_b2b
             SET paciente_id=$2,request_hash=$3,estado='processing',resultado_tipo=NULL,resultado_id=NULL,
                 http_status=NULL,resultado=NULL,created_at=clock_timestamp(),completed_at=NULL,
                 expires_at=clock_timestamp()+INTERVAL '90 days'
             WHERE id=$1 RETURNING id`,
            [row.id, patientId || null, requestHash]
        );
        return { enabled: true, id: renewed.rows[0].id, key, requestHash, replay: false };
    }
    if (row.request_hash !== requestHash) {
        const error = new Error('La Idempotency-Key ya fue usada con otro payload');
        error.status = 409;
        error.code = 'IDEMPOTENCY_KEY_REUSED';
        throw error;
    }
    if (row.estado !== 'completed') {
        throw new Error('Operación idempotente previa incompleta');
    }
    return { enabled: true, id: row.id, key, requestHash, replay: true, previous: row };
}

async function completeIdempotentOperation(client, context, result) {
    if (!context?.enabled || context.replay) return;
    const safeResult = result?.safeResult && typeof result.safeResult === 'object'
        ? canonicalize(result.safeResult)
        : null;
    await client.query(
        `UPDATE operaciones_idempotentes_b2b
         SET estado='completed',resultado_tipo=$2,resultado_id=$3,http_status=$4,resultado=$5,
             completed_at=clock_timestamp()
         WHERE id=$1 AND estado='processing'`,
        [context.id, result?.resultType || null, result?.resultId || null, result?.httpStatus || 200, safeResult]
    );
}

function p1HttpError(status, code, message) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    return error;
}

async function assertPatientMutationAllowed(client, actor, patientId, options = {}) {
    const id = Number(patientId);
    const result = await client.query(
        `SELECT id,institucion_id,activo,fecha_egreso,motivo_egreso,version
         FROM pacientes_b2b WHERE id=$1 AND institucion_id=$2 FOR UPDATE`,
        [id, actor.institucion_id]
    );
    if (result.rowCount === 0 || !result.rows[0].activo) {
        throw p1HttpError(404, 'PATIENT_NOT_FOUND', 'Paciente no encontrado');
    }
    const patient = result.rows[0];
    if (!patient.fecha_egreso) return patient;

    if (options.allowAdministrativeClose) return patient;
    if (options.allowCorrection) {
        const reason = String(options.correctionReason || '').trim();
        if (actor.rol !== 'admin_institucion') {
            throw p1HttpError(409, 'PATIENT_DISCHARGED', 'El residente se encuentra egresado');
        }
        if (!reason) {
            throw p1HttpError(400, 'CORRECTION_REASON_REQUIRED', 'La corrección post-egreso requiere un motivo');
        }
        return patient;
    }
    throw p1HttpError(409, 'PATIENT_DISCHARGED', 'El residente se encuentra egresado');
}

function sendP1Error(res, error, fallback) {
    if (error?.status) {
        return res.status(error.status).json({ error: error.message, code: error.code });
    }
    return res.status(500).json({ error: fallback });
}

function maybeInjectP1Failure(req, stage) {
    if (process.env.P1_TEST_MODE !== '1') return;
    if (req.headers?.['x-p1-fail-stage'] === stage) {
        throw new Error(`P1_TEST_INJECTED_FAILURE:${stage}`);
    }
}

const BRIDGE_MUTATING_GETS = new Set(['/verify-subscription', '/auth/verify-email']);
function b2bP1BridgeMiddleware(req, res, next) {
    if (process.env.B2B_P1_BRIDGE_MODE !== '1') return next();
    const isRead = req.method === 'GET' && !BRIDGE_MUTATING_GETS.has(req.path);
    const isLogin = req.method === 'POST' && req.path === '/auth/login';
    if (isRead || isLogin) return next();
    return res.status(503).json({
        error: 'CuidaDiario PRO se encuentra temporalmente en modo de continuidad de sólo lectura',
        code: 'B2B_P1_BRIDGE_READ_ONLY',
    });
}

module.exports = {
    SOFT_DELETE_TABLES,
    VERSIONED_TABLES,
    AUDIT_FIELD_ALLOWLIST,
    MIGRATIONS,
    runB2BP1Migrations,
    withB2BTransaction,
    appendB2BAudit,
    sanitizeAuditObject,
    beginIdempotentOperation,
    completeIdempotentOperation,
    assertPatientMutationAllowed,
    sendP1Error,
    maybeInjectP1Failure,
    b2bP1BridgeMiddleware,
};
