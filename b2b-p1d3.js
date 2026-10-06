'use strict';

const crypto = require('crypto');

const EXPORT_SCHEMA = 'cuidadiario-institutional-export/v1';
const LIFECYCLE_ACTIVE = 'active';
const LIFECYCLE_PREPARED = 'offboarding_prepared';
const LIFECYCLE_RETAINED = 'retained';
const FINAL_EXPORT_RECEIPT_MAX_AGE_HOURS = 24;
const OPERATIONAL_LIFECYCLE_STATES = Object.freeze([LIFECYCLE_ACTIVE, LIFECYCLE_PREPARED]);

const P1D3_MIGRATION = Object.freeze({
    version: 'p1d3_001_institution_lifecycle',
    sql: `
CREATE TABLE IF NOT EXISTS institucion_exportaciones_b2b (
    id UUID PRIMARY KEY,
    institucion_id INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE RESTRICT,
    actor_usuario_id INTEGER NOT NULL,
    export_schema VARCHAR(100) NOT NULL,
    export_sha256 CHAR(64) NOT NULL,
    export_bytes BIGINT NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    used_for_offboarding_at TIMESTAMPTZ NULL,
    used_for_offboarding_by INTEGER NULL,
    CONSTRAINT institucion_exportaciones_b2b_schema_check
        CHECK (export_schema = 'cuidadiario-institutional-export/v1'),
    CONSTRAINT institucion_exportaciones_b2b_sha256_check CHECK (export_sha256 ~ '^[0-9a-f]{64}$'),
    CONSTRAINT institucion_exportaciones_b2b_bytes_check CHECK (export_bytes > 0)
);
CREATE INDEX IF NOT EXISTS institucion_exportaciones_b2b_tenant_fecha_idx
    ON institucion_exportaciones_b2b (institucion_id, generated_at DESC, id);
CREATE INDEX IF NOT EXISTS institucion_exportaciones_b2b_unused_idx
    ON institucion_exportaciones_b2b (institucion_id, generated_at DESC)
    WHERE used_for_offboarding_at IS NULL;

ALTER TABLE instituciones_b2b
    ADD COLUMN IF NOT EXISTS lifecycle_state VARCHAR(32) NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS offboarding_started_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS offboarding_started_by INTEGER NULL,
    ADD COLUMN IF NOT EXISTS offboarding_reason TEXT NULL,
    ADD COLUMN IF NOT EXISTS final_export_receipt_id UUID NULL,
    ADD COLUMN IF NOT EXISTS offboarded_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS offboarded_by INTEGER NULL,
    ADD COLUMN IF NOT EXISTS retention_review_at TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS retention_note TEXT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='instituciones_b2b_lifecycle_state_check') THEN
        ALTER TABLE instituciones_b2b ADD CONSTRAINT instituciones_b2b_lifecycle_state_check
            CHECK (lifecycle_state IN ('active','offboarding_prepared','retained'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='instituciones_b2b_offboarding_consistency_check') THEN
        ALTER TABLE instituciones_b2b ADD CONSTRAINT instituciones_b2b_offboarding_consistency_check
            CHECK (
                lifecycle_state = 'active'
                OR (lifecycle_state = 'offboarding_prepared'
                    AND offboarding_started_at IS NOT NULL AND offboarding_started_by IS NOT NULL
                    AND offboarding_reason IS NOT NULL AND final_export_receipt_id IS NOT NULL)
                OR (lifecycle_state = 'retained'
                    AND offboarding_started_at IS NOT NULL AND offboarding_started_by IS NOT NULL
                    AND offboarding_reason IS NOT NULL AND final_export_receipt_id IS NOT NULL
                    AND offboarded_at IS NOT NULL AND offboarded_by IS NOT NULL AND activa = FALSE)
            );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='instituciones_b2b_final_export_receipt_fk') THEN
        ALTER TABLE instituciones_b2b ADD CONSTRAINT instituciones_b2b_final_export_receipt_fk
            FOREIGN KEY (final_export_receipt_id)
            REFERENCES institucion_exportaciones_b2b(id) ON DELETE RESTRICT;
    END IF;
END;
$$;
CREATE INDEX IF NOT EXISTS instituciones_b2b_lifecycle_idx
    ON instituciones_b2b (lifecycle_state, activa, id);
`,
});

function lifecycleError(status, code, message) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    return error;
}

function isOperationalLifecycle(state) {
    return OPERATIONAL_LIFECYCLE_STATES.includes(state || LIFECYCLE_ACTIVE);
}

function requirePrincipalInstitutionAdmin(req, res, next) {
    if (!req.b2bPrincipal || req.b2bPrincipal.rol !== 'admin_institucion') {
        return res.status(403).json({ error: 'Esta acción requiere una cuenta principal administradora', code: 'PRINCIPAL_ADMIN_REQUIRED' });
    }
    if (req.b2bOperator || req.b2bUser?.operador_b2b_id) {
        return res.status(403).json({ error: 'Finalizá el turno del operador secundario para continuar', code: 'SECONDARY_OPERATOR_NOT_ALLOWED' });
    }
    next();
}

function normalizeReason(value) {
    const reason = String(value || '').trim();
    if (reason.length < 10 || reason.length > 1000) {
        throw lifecycleError(400, 'OFFBOARDING_REASON_INVALID', 'El motivo debe tener entre 10 y 1000 caracteres');
    }
    return reason;
}

function normalizePassword(value) {
    const password = typeof value === 'string' ? value : '';
    if (!password || password.length > 200) {
        throw lifecycleError(400, 'CURRENT_PASSWORD_REQUIRED', 'Se requiere la contraseña actual');
    }
    return password;
}

function normalizeReceiptId(value) {
    const id = String(value || '').trim().toLowerCase();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) {
        throw lifecycleError(400, 'FINAL_EXPORT_RECEIPT_INVALID', 'La evidencia de exportación final es inválida');
    }
    return id;
}

function normalizeRetentionReviewAt(value, now = Date.now()) {
    if (value === undefined || value === null || value === '') return null;
    const date = new Date(value);
    if (!Number.isFinite(date.getTime()) || date.getTime() <= now) {
        throw lifecycleError(400, 'RETENTION_REVIEW_DATE_INVALID', 'La fecha de revisión de retención debe ser futura');
    }
    return date;
}

function normalizeRetentionNote(value) {
    if (value === undefined || value === null || value === '') return null;
    const note = String(value).trim();
    if (note.length > 1000) throw lifecycleError(400, 'RETENTION_NOTE_INVALID', 'La nota de retención es demasiado extensa');
    return note || null;
}

function safeLifecycle(row) {
    return {
        lifecycle_state: row.lifecycle_state,
        offboarding_started_at: row.offboarding_started_at || null,
        offboarding_reason: row.offboarding_reason || null,
        final_export_confirmed: !!row.final_export_receipt_id,
        offboarded_at: row.offboarded_at || null,
        retention_review_at: row.retention_review_at || null,
        retention_note: row.retention_note || null,
        automatic_purge: false,
    };
}

function requestUuid(req) {
    const candidate = String(req.get?.('X-Request-ID') || '').trim().toLowerCase();
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(candidate)
        ? candidate
        : crypto.randomUUID();
}

async function verifyPrincipalPassword(client, bcrypt, principal, password) {
    const result = await client.query(
        `SELECT id,password_hash,activo,email_verified,rol FROM usuarios_b2b
         WHERE id=$1 AND institucion_id=$2 FOR UPDATE`,
        [principal.id, principal.institucion_id]
    );
    const user = result.rows[0];
    if (!user || !user.activo || !user.email_verified || user.rol !== 'admin_institucion') {
        throw lifecycleError(403, 'PRINCIPAL_ADMIN_REQUIRED', 'La cuenta principal administradora ya no está vigente');
    }
    if (!(await bcrypt.compare(password, user.password_hash))) {
        throw lifecycleError(403, 'CURRENT_PASSWORD_INVALID', 'La contraseña actual es incorrecta');
    }
}

async function recordInstitutionalExportReceipt(pool, input) {
    if (!input || !Number.isSafeInteger(Number(input.institutionId)) || Number(input.institutionId) <= 0
        || !Number.isSafeInteger(Number(input.actorUserId)) || Number(input.actorUserId) <= 0
        || !/^[0-9a-f]{64}$/.test(String(input.sha256 || ''))
        || !Number.isSafeInteger(Number(input.bytes)) || Number(input.bytes) <= 0
        || input.schema !== EXPORT_SCHEMA) {
        throw lifecycleError(500, 'P1D3_EXPORT_RECEIPT_INVALID', 'No se pudo registrar la evidencia de exportación');
    }
    const id = crypto.randomUUID();
    await pool.query(
        `INSERT INTO institucion_exportaciones_b2b
         (id,institucion_id,actor_usuario_id,export_schema,export_sha256,export_bytes)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [id, Number(input.institutionId), Number(input.actorUserId), input.schema, input.sha256, Number(input.bytes)]
    );
    return id;
}

function registerOffboardingRoutes(app, dependencies) {
    const { pool, bcrypt, authB2BMiddleware, withB2BTransaction, appendB2BAudit,
        beginIdempotentOperation, completeIdempotentOperation, sendP1Error } = dependencies;

    app.get('/api/b2b/offboarding/status', authB2BMiddleware, requirePrincipalInstitutionAdmin, async (req, res) => {
        try {
            const result = await pool.query(
                `SELECT lifecycle_state,offboarding_started_at,offboarding_reason,final_export_receipt_id,
                        offboarded_at,retention_review_at,retention_note
                 FROM instituciones_b2b WHERE id=$1`, [req.b2bPrincipal.institucion_id]
            );
            if (result.rowCount !== 1) throw lifecycleError(404, 'INSTITUTION_NOT_FOUND', 'Institución no encontrada');
            res.json(safeLifecycle(result.rows[0]));
        } catch (error) { sendP1Error(res, error, 'No se pudo consultar el estado de baja'); }
    });

    app.post('/api/b2b/offboarding/prepare', authB2BMiddleware, requirePrincipalInstitutionAdmin, async (req, res) => {
        try {
            const principal = req.b2bPrincipal;
            const reason = normalizeReason(req.body?.reason);
            const password = normalizePassword(req.body?.current_password);
            const receiptId = normalizeReceiptId(req.body?.final_export_receipt_id);
            if (req.body?.confirmation !== 'INICIAR BAJA') {
                throw lifecycleError(400, 'OFFBOARDING_CONFIRMATION_INVALID', 'Escribí INICIAR BAJA para confirmar');
            }
            const requestId = requestUuid(req);
            const outcome = await withB2BTransaction(pool, async client => {
                await verifyPrincipalPassword(client, bcrypt, principal, password);
                const idempotency = await beginIdempotentOperation(client, {
                    req, actor: principal, operation: 'institution_offboarding_prepare', resourceId: principal.institucion_id,
                });
                if (!idempotency.enabled) throw lifecycleError(400, 'IDEMPOTENCY_KEY_REQUIRED', 'Idempotency-Key es obligatoria');
                if (idempotency.replay) return { ...idempotency.previous.resultado, idempotent_replay: true };
                const currentResult = await client.query('SELECT * FROM instituciones_b2b WHERE id=$1 FOR UPDATE', [principal.institucion_id]);
                const current = currentResult.rows[0];
                if (!current || !current.activa || current.lifecycle_state !== LIFECYCLE_ACTIVE) {
                    throw lifecycleError(409, 'OFFBOARDING_TRANSITION_INVALID', 'La institución no está en estado activo');
                }
                const receipt = await client.query(
                    `SELECT id FROM institucion_exportaciones_b2b
                     WHERE id=$1 AND institucion_id=$2 AND used_for_offboarding_at IS NULL
                       AND generated_at >= clock_timestamp()-INTERVAL '24 hours' FOR UPDATE`,
                    [receiptId, principal.institucion_id]
                );
                if (receipt.rowCount !== 1) {
                    throw lifecycleError(409, 'FINAL_EXPORT_RECEIPT_NOT_AVAILABLE', 'La exportación final no pertenece a esta institución o ya fue utilizada');
                }
                const changed = (await client.query(
                    `UPDATE instituciones_b2b SET lifecycle_state=$1,offboarding_started_at=clock_timestamp(),
                     offboarding_started_by=$2,offboarding_reason=$3,final_export_receipt_id=$4,version=version+1
                     WHERE id=$5 RETURNING *`,
                    [LIFECYCLE_PREPARED, principal.id, reason, receiptId, principal.institucion_id]
                )).rows[0];
                await client.query(
                    `UPDATE institucion_exportaciones_b2b
                     SET used_for_offboarding_at=clock_timestamp(),used_for_offboarding_by=$2 WHERE id=$1`,
                    [receiptId, principal.id]
                );
                await appendB2BAudit(client, {
                    institutionId: principal.institucion_id, actor: principal, resourceType: 'institucion',
                    resourceId: principal.institucion_id, action: 'TRANSITION', version: changed.version,
                    before: current, after: changed, reason, metadata: { channel: 'offboarding_prepare' }, requestId,
                });
                const result = { ...safeLifecycle(changed), idempotent_replay: false };
                await completeIdempotentOperation(client, idempotency, {
                    resultType: 'institucion', resultId: principal.institucion_id, httpStatus: 200, safeResult: result,
                });
                return result;
            });
            res.json(outcome);
        } catch (error) { sendP1Error(res, error, 'No se pudo preparar la baja institucional'); }
    });

    app.post('/api/b2b/offboarding/finalize', authB2BMiddleware, requirePrincipalInstitutionAdmin, async (req, res) => {
        try {
            const principal = req.b2bPrincipal;
            const password = normalizePassword(req.body?.current_password);
            const retentionReviewAt = normalizeRetentionReviewAt(req.body?.retention_review_at);
            const retentionNote = normalizeRetentionNote(req.body?.retention_note);
            if (req.body?.confirmation !== 'DAR DE BAJA') {
                throw lifecycleError(400, 'OFFBOARDING_CONFIRMATION_INVALID', 'Escribí DAR DE BAJA para confirmar');
            }
            const requestId = requestUuid(req);
            const outcome = await withB2BTransaction(pool, async client => {
                await verifyPrincipalPassword(client, bcrypt, principal, password);
                const idempotency = await beginIdempotentOperation(client, {
                    req, actor: principal, operation: 'institution_offboarding_finalize', resourceId: principal.institucion_id,
                });
                if (!idempotency.enabled) throw lifecycleError(400, 'IDEMPOTENCY_KEY_REQUIRED', 'Idempotency-Key es obligatoria');
                if (idempotency.replay) return { ...idempotency.previous.resultado, idempotent_replay: true };
                const currentResult = await client.query('SELECT * FROM instituciones_b2b WHERE id=$1 FOR UPDATE', [principal.institucion_id]);
                const current = currentResult.rows[0];
                if (!current || !current.activa || current.lifecycle_state !== LIFECYCLE_PREPARED || !current.final_export_receipt_id) {
                    throw lifecycleError(409, 'OFFBOARDING_TRANSITION_INVALID', 'La baja no está preparada con una exportación final confirmada');
                }
                const changed = (await client.query(
                    `UPDATE instituciones_b2b SET lifecycle_state=$1,activa=FALSE,offboarded_at=clock_timestamp(),
                     offboarded_by=$2,retention_review_at=$3,retention_note=$4,version=version+1
                     WHERE id=$5 RETURNING *`,
                    [LIFECYCLE_RETAINED, principal.id, retentionReviewAt, retentionNote, principal.institucion_id]
                )).rows[0];
                await client.query(
                    `UPDATE operador_sesiones_b2b SET revoked_at=COALESCE(revoked_at,clock_timestamp())
                     WHERE institucion_id=$1 AND revoked_at IS NULL`, [principal.institucion_id]
                );
                await client.query(
                    `UPDATE usuarios_b2b SET reset_token=NULL,reset_token_expiry=NULL,
                     email_verification_token=NULL,email_verification_expiry=NULL,version=version+1
                     WHERE institucion_id=$1 AND (reset_token IS NOT NULL OR email_verification_token IS NOT NULL)`,
                    [principal.institucion_id]
                );
                await appendB2BAudit(client, {
                    institutionId: principal.institucion_id, actor: principal, resourceType: 'institucion',
                    resourceId: principal.institucion_id, action: 'TRANSITION', version: changed.version,
                    before: current, after: changed, reason: current.offboarding_reason,
                    metadata: { channel: 'offboarding_finalize' }, requestId,
                });
                const result = { ...safeLifecycle(changed), logout_required: true, idempotent_replay: false };
                await completeIdempotentOperation(client, idempotency, {
                    resultType: 'institucion', resultId: principal.institucion_id, httpStatus: 200, safeResult: result,
                });
                return result;
            });
            res.json(outcome);
        } catch (error) { sendP1Error(res, error, 'No se pudo efectivizar la baja institucional'); }
    });
}

module.exports = {
    EXPORT_SCHEMA, LIFECYCLE_ACTIVE, LIFECYCLE_PREPARED, LIFECYCLE_RETAINED,
    FINAL_EXPORT_RECEIPT_MAX_AGE_HOURS,
    OPERATIONAL_LIFECYCLE_STATES, P1D3_MIGRATION, isOperationalLifecycle,
    recordInstitutionalExportReceipt, registerOffboardingRoutes,
};
