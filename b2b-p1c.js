'use strict';

const crypto = require('crypto');

const OPERATOR_CONTEXT_MAX_MS = 8 * 60 * 60 * 1000;
const OPERATOR_IDLE_MAX_MS = 60 * 60 * 1000;
const OPERATOR_ACTIVATION_WINDOW_MS = 15 * 60 * 1000;
const OPERATOR_TOKEN_HEADER = 'x-b2b-operator-token';
const OPERATOR_ROLES = Object.freeze(['admin_institucion', 'medico', 'cuidador_staff']);
const PIN_PATTERN = /^\d{6}$/;
const activationAttempts = new Map();

const P1C_MIGRATION = Object.freeze({
    version: 'p1c_001_operator_identity',
    sql: `
CREATE TABLE IF NOT EXISTS operadores_b2b (
    id BIGSERIAL PRIMARY KEY,
    institucion_id INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE RESTRICT,
    nombre TEXT NOT NULL CHECK (char_length(btrim(nombre)) BETWEEN 2 AND 120),
    rol VARCHAR(30) NOT NULL CHECK (rol IN ('admin_institucion','medico','cuidador_staff')),
    activo BOOLEAN NOT NULL DEFAULT TRUE,
    pin_hash TEXT NOT NULL,
    credential_version BIGINT NOT NULL DEFAULT 1 CHECK (credential_version > 0),
    created_by_usuario_id INTEGER NULL REFERENCES usuarios_b2b(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0)
);
CREATE UNIQUE INDEX IF NOT EXISTS operadores_b2b_tenant_nombre_uq
    ON operadores_b2b (institucion_id, lower(btrim(nombre)));
CREATE INDEX IF NOT EXISTS operadores_b2b_tenant_activo_idx
    ON operadores_b2b (institucion_id, activo, nombre);

CREATE TABLE IF NOT EXISTS operador_sesiones_b2b (
    id UUID PRIMARY KEY,
    institucion_id INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE RESTRICT,
    operador_b2b_id BIGINT NOT NULL REFERENCES operadores_b2b(id) ON DELETE RESTRICT,
    principal_usuario_id INTEGER NOT NULL REFERENCES usuarios_b2b(id) ON DELETE RESTRICT,
    token_hash CHAR(64) NOT NULL UNIQUE,
    credential_version BIGINT NOT NULL CHECK (credential_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS operador_sesiones_b2b_lookup_idx
    ON operador_sesiones_b2b (institucion_id, principal_usuario_id, token_hash)
    WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS operador_sesiones_b2b_expiry_idx
    ON operador_sesiones_b2b (expires_at) WHERE revoked_at IS NULL;

ALTER TABLE auditoria_eventos_b2b
    ADD COLUMN IF NOT EXISTS operador_b2b_id BIGINT NULL REFERENCES operadores_b2b(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS auditoria_b2b_operador_idx
    ON auditoria_eventos_b2b (institucion_id, operador_b2b_id, ocurrido_at DESC)
    WHERE operador_b2b_id IS NOT NULL;

ALTER TABLE operaciones_idempotentes_b2b
    ADD COLUMN IF NOT EXISTS operador_b2b_id BIGINT NULL REFERENCES operadores_b2b(id) ON DELETE RESTRICT;
CREATE INDEX IF NOT EXISTS idempotencia_b2b_operador_idx
    ON operaciones_idempotentes_b2b (institucion_id, operador_b2b_id, created_at DESC)
    WHERE operador_b2b_id IS NOT NULL;
`,
});

function operatorHttpError(status, code, message) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    return error;
}

function normalizeOperatorName(value) {
    return String(value == null ? '' : value).trim().replace(/\s+/g, ' ');
}

function validateOperatorRole(value) {
    return OPERATOR_ROLES.includes(value) ? value : null;
}

function validatePin(value) {
    const pin = String(value == null ? '' : value);
    if (!PIN_PATTERN.test(pin)) {
        throw operatorHttpError(400, 'INVALID_OPERATOR_PIN', 'El PIN debe contener exactamente 6 dígitos');
    }
    return pin;
}

function operatorTokenFromRequest(req) {
    const raw = req.get ? req.get(OPERATOR_TOKEN_HEADER) : req.headers?.[OPERATOR_TOKEN_HEADER];
    if (!raw) return null;
    const token = String(raw).trim();
    return /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}

function hasOperatorTokenFromRequest(req) {
    const raw = req.get ? req.get(OPERATOR_TOKEN_HEADER) : req.headers?.[OPERATOR_TOKEN_HEADER];
    return raw !== undefined && raw !== null && String(raw).trim() !== '';
}

function hashOperatorToken(token) {
    return crypto.createHash('sha256').update(token).digest('hex');
}

function isOperatorBootstrapRoute(req) {
    const path = String(req.path || req.originalUrl || '').split('?')[0];
    return path === '/api/b2b/auth/me'
        || path === '/api/b2b/auth/resend-verification'
        || path === '/api/b2b/operators'
        || path.startsWith('/api/b2b/operators/');
}

function activationKey(req, principal, operatorId) {
    return `${principal.institucion_id}:${operatorId}:${req.ip || req.socket?.remoteAddress || 'unknown'}`;
}

function assertActivationAllowed(req, principal, operatorId) {
    const key = activationKey(req, principal, operatorId);
    const now = Date.now();
    const state = activationAttempts.get(key);
    if (!state || state.resetAt <= now) {
        activationAttempts.set(key, { count: 0, resetAt: now + OPERATOR_ACTIVATION_WINDOW_MS });
        return key;
    }
    if (state.count >= 5) {
        throw operatorHttpError(429, 'OPERATOR_PIN_RATE_LIMITED', 'Demasiados intentos. Esperá 15 minutos e intentá nuevamente.');
    }
    return key;
}

function recordActivationFailure(key) {
    const current = activationAttempts.get(key) || { count: 0, resetAt: Date.now() + OPERATOR_ACTIVATION_WINDOW_MS };
    current.count += 1;
    activationAttempts.set(key, current);
}

async function resolveOperatorContext(pool, req, principal, options = {}) {
    const token = operatorTokenFromRequest(req);
    if (!token) throw operatorHttpError(428, 'OPERATOR_REQUIRED', 'Seleccioná e identificá al operador para continuar');
    const tokenHash = hashOperatorToken(token);
    const touch = options.touch !== false;
    const query = touch ? `
        UPDATE operador_sesiones_b2b s
           SET last_seen_at=clock_timestamp()
          FROM operadores_b2b o
         WHERE s.token_hash=$1 AND s.institucion_id=$2 AND s.principal_usuario_id=$3
           AND s.operador_b2b_id=o.id AND o.institucion_id=s.institucion_id
           AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
           AND s.last_seen_at>clock_timestamp()-INTERVAL '60 minutes'
           AND o.activo=TRUE AND o.credential_version=s.credential_version
        RETURNING o.id,o.nombre,o.rol,o.activo,o.credential_version,s.expires_at,s.last_seen_at
    ` : `
        SELECT o.id,o.nombre,o.rol,o.activo,o.credential_version,s.expires_at,s.last_seen_at
          FROM operador_sesiones_b2b s
          JOIN operadores_b2b o ON o.id=s.operador_b2b_id AND o.institucion_id=s.institucion_id
         WHERE s.token_hash=$1 AND s.institucion_id=$2 AND s.principal_usuario_id=$3
           AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
           AND s.last_seen_at>clock_timestamp()-INTERVAL '60 minutes'
           AND o.activo=TRUE AND o.credential_version=s.credential_version
    `;
    const result = await pool.query(query, [tokenHash, principal.institucion_id, principal.id]);
    if (result.rowCount === 0) {
        throw operatorHttpError(428, 'OPERATOR_REQUIRED', 'El contexto de operador venció o dejó de ser válido');
    }
    const row = result.rows[0];
    return {
        id: Number(row.id),
        nombre: row.nombre,
        rol: row.rol,
        activo: !!row.activo,
        credential_version: Number(row.credential_version),
        expires_at: row.expires_at,
    };
}

async function revokeOperatorToken(pool, req, principal) {
    const token = operatorTokenFromRequest(req);
    if (!token) return false;
    const result = await pool.query(
        `UPDATE operador_sesiones_b2b SET revoked_at=COALESCE(revoked_at,clock_timestamp())
         WHERE token_hash=$1 AND institucion_id=$2 AND principal_usuario_id=$3 AND revoked_at IS NULL`,
        [hashOperatorToken(token), principal.institucion_id, principal.id]
    );
    return result.rowCount > 0;
}

function publicOperator(row, includeAdministrative = false) {
    const result = {
        id: Number(row.id), nombre: row.nombre, rol: row.rol, activo: !!row.activo,
    };
    if (includeAdministrative) {
        result.version = Number(row.version);
        result.credential_version = Number(row.credential_version);
        result.pin_configured = !!row.pin_hash;
        result.created_at = row.created_at;
        result.updated_at = row.updated_at;
        result.usuario_b2b_id = row.usuario_b2b_id == null ? null : Number(row.usuario_b2b_id);
    }
    return result;
}

function registerOperatorRoutes(app, dependencies) {
    const { pool, bcrypt, saltRounds, authB2BMiddleware, appendB2BAudit, withB2BTransaction, sendP1Error } = dependencies;

    function requirePrincipalAdmin(req, res, next) {
        const principal = req.b2bPrincipal || req.b2bUser;
        if (!principal || principal.rol !== 'admin_institucion') {
            return res.status(403).json({ error: 'La administración de operadores requiere una cuenta principal administradora', code: 'PRINCIPAL_ADMIN_REQUIRED' });
        }
        next();
    }

    app.get('/api/b2b/operators', authB2BMiddleware, async (req, res) => {
        try {
            const principal = req.b2bPrincipal || req.b2bUser;
            const administrative = req.query.all === '1';
            if (administrative && principal.rol !== 'admin_institucion') return requirePrincipalAdmin(req, res, () => {});
            const result = await pool.query(
                `SELECT id,usuario_b2b_id,nombre,rol,activo,credential_version,pin_hash,created_at,updated_at,version
                 FROM operadores_b2b WHERE institucion_id=$1 ${administrative ? '' : 'AND activo=TRUE'}
                 ORDER BY activo DESC,nombre,id`,
                [principal.institucion_id]
            );
            res.json(result.rows.map(row => publicOperator(row, administrative)));
        } catch (error) {
            console.error('GET /api/b2b/operators:', error.message);
            res.status(500).json({ error: 'Error al obtener operadores' });
        }
    });

    app.post('/api/b2b/operators', authB2BMiddleware, requirePrincipalAdmin, async (req, res) => {
        try {
            const principal = req.b2bPrincipal || req.b2bUser;
            const pin = validatePin(req.body?.pin);
            const pinHash = await bcrypt.hash(pin, saltRounds);
            const created = await withB2BTransaction(pool, async client => {
                const requestedStaffId = req.body?.usuario_b2b_id == null ? null : Number(req.body.usuario_b2b_id);
                let nombre;
                let rol;
                if (requestedStaffId !== null) {
                    if (!Number.isSafeInteger(requestedStaffId) || requestedStaffId <= 0) {
                        throw operatorHttpError(400, 'INVALID_STAFF_ID', 'Miembro del staff inválido');
                    }
                    const staffResult = await client.query(
                        `SELECT id,nombre,rol,activo FROM usuarios_b2b
                         WHERE id=$1 AND institucion_id=$2 FOR UPDATE`,
                        [requestedStaffId, principal.institucion_id]
                    );
                    if (staffResult.rowCount === 0 || !staffResult.rows[0].activo) {
                        throw operatorHttpError(404, 'STAFF_NOT_AVAILABLE', 'El miembro del staff no está disponible');
                    }
                    const staff = staffResult.rows[0];
                    if (!OPERATOR_ROLES.includes(staff.rol)) {
                        throw operatorHttpError(400, 'STAFF_ROLE_NOT_COMPATIBLE', 'Este rol de Staff no puede operar una estación compartida');
                    }
                    nombre = normalizeOperatorName(staff.nombre);
                    rol = staff.rol;
                } else {
                    nombre = normalizeOperatorName(req.body?.nombre);
                    rol = validateOperatorRole(req.body?.rol);
                    if (nombre.length < 2 || nombre.length > 120) throw operatorHttpError(400, 'INVALID_OPERATOR_NAME', 'El nombre debe tener entre 2 y 120 caracteres');
                    if (!rol) throw operatorHttpError(400, 'INVALID_OPERATOR_ROLE', 'Rol de operador inválido');
                }
                const inserted = await client.query(
                    `INSERT INTO operadores_b2b (institucion_id,usuario_b2b_id,nombre,rol,pin_hash,created_by_usuario_id)
                     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
                    [principal.institucion_id, requestedStaffId, nombre, rol, pinHash, principal.id]
                );
                await appendB2BAudit(client, {
                    institutionId: principal.institucion_id, actor: principal, resourceType: 'operador',
                    resourceId: inserted.rows[0].id, action: 'CREATE', version: inserted.rows[0].version,
                    after: inserted.rows[0], metadata: { channel: requestedStaffId ? 'operator_enable_from_staff' : 'operator_create' },
                });
                return inserted.rows[0];
            });
            res.status(201).json(publicOperator(created, true));
        } catch (error) {
            if (error?.code === '23505') return res.status(409).json({ error: 'Este miembro del Staff ya está habilitado o existe un operador con ese nombre', code: 'OPERATOR_CONFLICT' });
            sendP1Error(res, error, 'Error al crear operador');
        }
    });

    app.patch('/api/b2b/operators/:id', authB2BMiddleware, requirePrincipalAdmin, async (req, res) => {
        try {
            const principal = req.b2bPrincipal || req.b2bUser;
            const operatorId = Number(req.params.id);
            if (!Number.isSafeInteger(operatorId) || operatorId <= 0) throw operatorHttpError(400, 'INVALID_OPERATOR_ID', 'Operador inválido');
            const nombre = req.body?.nombre === undefined ? null : normalizeOperatorName(req.body.nombre);
            const rol = req.body?.rol === undefined ? null : validateOperatorRole(req.body.rol);
            const activo = req.body?.activo === undefined ? null : req.body.activo;
            if (nombre !== null && (nombre.length < 2 || nombre.length > 120)) throw operatorHttpError(400, 'INVALID_OPERATOR_NAME', 'El nombre debe tener entre 2 y 120 caracteres');
            if (req.body?.rol !== undefined && !rol) throw operatorHttpError(400, 'INVALID_OPERATOR_ROLE', 'Rol de operador inválido');
            if (activo !== null && typeof activo !== 'boolean') throw operatorHttpError(400, 'INVALID_OPERATOR_STATUS', 'Estado de operador inválido');
            const pinHash = req.body?.pin === undefined ? null : await bcrypt.hash(validatePin(req.body.pin), saltRounds);
            const changed = await withB2BTransaction(pool, async client => {
                const currentResult = await client.query('SELECT * FROM operadores_b2b WHERE id=$1 AND institucion_id=$2 FOR UPDATE', [operatorId, principal.institucion_id]);
                if (currentResult.rowCount === 0) throw operatorHttpError(404, 'OPERATOR_NOT_FOUND', 'Operador no encontrado');
                const current = currentResult.rows[0];
                const invalidates = pinHash !== null || rol !== null || (activo !== null && activo !== current.activo);
                const updated = await client.query(
                    `UPDATE operadores_b2b SET nombre=COALESCE($1,nombre),rol=COALESCE($2,rol),
                     activo=COALESCE($3,activo),pin_hash=COALESCE($4,pin_hash),
                     credential_version=credential_version+CASE WHEN $5 THEN 1 ELSE 0 END,
                     version=version+1,updated_at=clock_timestamp()
                     WHERE id=$6 AND institucion_id=$7 RETURNING *`,
                    [nombre, rol, activo, pinHash, invalidates, operatorId, principal.institucion_id]
                );
                if (invalidates) {
                    await client.query('UPDATE operador_sesiones_b2b SET revoked_at=COALESCE(revoked_at,clock_timestamp()) WHERE operador_b2b_id=$1 AND revoked_at IS NULL', [operatorId]);
                }
                await appendB2BAudit(client, {
                    institutionId: principal.institucion_id, actor: principal, resourceType: 'operador',
                    resourceId: operatorId, action: pinHash ? 'SECURITY' : 'UPDATE', version: updated.rows[0].version,
                    before: current, after: updated.rows[0], metadata: { channel: pinHash ? 'operator_pin_reset' : 'operator_update' },
                });
                return updated.rows[0];
            });
            res.json(publicOperator(changed, true));
        } catch (error) {
            if (error?.code === '23505') return res.status(409).json({ error: 'Ya existe un operador con ese nombre', code: 'OPERATOR_NAME_CONFLICT' });
            sendP1Error(res, error, 'Error al actualizar operador');
        }
    });

    app.post('/api/b2b/operators/activate', authB2BMiddleware, async (req, res) => {
        try {
            const principal = req.b2bPrincipal || req.b2bUser;
            if (!principal.shared_mode) throw operatorHttpError(409, 'SHARED_MODE_DISABLED', 'La institución no utiliza estación compartida');
            if (principal.rol === 'familiar') {
                throw operatorHttpError(403, 'OPERATOR_NOT_ALLOWED_FOR_PRINCIPAL', 'La cuenta familiar no puede asumir un operador de estación');
            }
            const operatorId = Number(req.body?.operator_id);
            if (!Number.isSafeInteger(operatorId) || operatorId <= 0) throw operatorHttpError(401, 'OPERATOR_PIN_INVALID', 'Operador o PIN inválido');
            const pin = String(req.body?.pin == null ? '' : req.body.pin);
            const key = assertActivationAllowed(req, principal, operatorId);
            const operatorResult = await pool.query(
                'SELECT * FROM operadores_b2b WHERE id=$1 AND institucion_id=$2 AND activo=TRUE',
                [operatorId, principal.institucion_id]
            );
            const operator = operatorResult.rows[0];
            if (operator?.rol === 'admin_institucion' && principal.rol !== 'admin_institucion') {
                recordActivationFailure(key);
                throw operatorHttpError(403, 'PRINCIPAL_ADMIN_REQUIRED', 'Un operador administrador requiere una cuenta principal administradora');
            }
            const valid = operator && PIN_PATTERN.test(pin) && await bcrypt.compare(pin, operator.pin_hash);
            if (!valid) {
                recordActivationFailure(key);
                throw operatorHttpError(401, 'OPERATOR_PIN_INVALID', 'Operador o PIN inválido');
            }
            activationAttempts.delete(key);
            const token = crypto.randomBytes(32).toString('base64url');
            const sessionId = crypto.randomUUID();
            const expiresAt = new Date(Date.now() + OPERATOR_CONTEXT_MAX_MS);
            await pool.query(
                `INSERT INTO operador_sesiones_b2b
                 (id,institucion_id,operador_b2b_id,principal_usuario_id,token_hash,credential_version,expires_at)
                 VALUES ($1,$2,$3,$4,$5,$6,$7)`,
                [sessionId, principal.institucion_id, operator.id, principal.id, hashOperatorToken(token), operator.credential_version, expiresAt]
            );
            res.setHeader('Cache-Control', 'private, no-store, max-age=0');
            res.json({
                operator_token: token,
                operator: publicOperator(operator),
                expires_at: expiresAt.toISOString(),
                idle_timeout_seconds: OPERATOR_IDLE_MAX_MS / 1000,
            });
        } catch (error) {
            if (error?.status) return res.status(error.status).json({ error: error.message, code: error.code });
            console.error('POST /api/b2b/operators/activate:', error.message);
            res.status(500).json({ error: 'No se pudo activar el operador' });
        }
    });

    app.get('/api/b2b/operators/context', authB2BMiddleware, async (req, res) => {
        try {
            const principal = req.b2bPrincipal || req.b2bUser;
            const operator = await resolveOperatorContext(pool, req, principal);
            res.setHeader('Cache-Control', 'private, no-store, max-age=0');
            res.json({ operator: publicOperator(operator), expires_at: operator.expires_at, idle_timeout_seconds: OPERATOR_IDLE_MAX_MS / 1000 });
        } catch (error) {
            res.status(error.status || 500).json({ error: error.message, code: error.code || 'OPERATOR_CONTEXT_ERROR' });
        }
    });

    app.post('/api/b2b/operators/end-shift', authB2BMiddleware, async (req, res) => {
        try {
            const principal = req.b2bPrincipal || req.b2bUser;
            await revokeOperatorToken(pool, req, principal);
            res.json({ success: true });
        } catch (error) {
            console.error('POST /api/b2b/operators/end-shift:', error.message);
            res.status(500).json({ error: 'No se pudo finalizar el turno' });
        }
    });
}

module.exports = {
    OPERATOR_CONTEXT_MAX_MS,
    OPERATOR_IDLE_MAX_MS,
    OPERATOR_ACTIVATION_WINDOW_MS,
    OPERATOR_TOKEN_HEADER,
    OPERATOR_ROLES,
    P1C_MIGRATION,
    isOperatorBootstrapRoute,
    resolveOperatorContext,
    registerOperatorRoutes,
    operatorTokenFromRequest,
    hasOperatorTokenFromRequest,
    hashOperatorToken,
};
