'use strict';

const { LA4_ALERT_TYPES } = require('./b2b-la4');

const LA1_PERSISTED_ALERT_TYPES = LA4_ALERT_TYPES;
const LA1_ALERT_SEVERITIES = Object.freeze(['informativa', 'moderada', 'alta']);
const LA1_INCIDENT_CATEGORIES = Object.freeze([
    'caida', 'golpe_herida', 'error_medicacion', 'omision_medicacion',
    'episodio_conductual', 'derivacion', 'otro',
]);
const LA1_INCIDENT_SEVERITIES = Object.freeze(['leve', 'moderada', 'alta', 'critica']);
const LA1_INCIDENT_STATUSES = Object.freeze(['abierto', 'en_seguimiento', 'cerrado']);
const LA1_TEMPORARY_STATE_TYPES = Object.freeze(['internado', 'salida_medica', 'salida_familiar', 'otro']);
const LA1_DOCUMENT_CATEGORIES = Object.freeze([
    'receta', 'estudio_analisis', 'epicrisis', 'indicacion', 'dni', 'cobertura', 'otro',
]);
const LA1_CARE_PROFILE_ENUMS = Object.freeze({
    movilidad: ['independiente', 'asistencia_parcial', 'asistencia_total', 'inmovil'],
    nivel_dependencia: ['baja', 'media', 'alta', 'total'],
    riesgo_caida: ['bajo', 'moderado', 'alto'],
    continencia: ['continente', 'asistencia', 'incontinencia_urinaria', 'incontinencia_fecal', 'incontinencia_mixta'],
});

const LA1_MIGRATION = Object.freeze({
    version: 'la_001_resident_core',
    sql: `
ALTER TABLE pacientes_b2b
    ADD COLUMN IF NOT EXISTS dieta_restricciones TEXT NULL,
    ADD COLUMN IF NOT EXISTS movilidad VARCHAR(30) NULL,
    ADD COLUMN IF NOT EXISTS nivel_dependencia VARCHAR(20) NULL,
    ADD COLUMN IF NOT EXISTS riesgo_caida VARCHAR(20) NULL,
    ADD COLUMN IF NOT EXISTS continencia VARCHAR(40) NULL,
    ADD COLUMN IF NOT EXISTS aspectos_cognitivos TEXT NULL;

ALTER TABLE contactos_b2b
    ADD COLUMN IF NOT EXISTS prioridad INTEGER NULL,
    ADD COLUMN IF NOT EXISTS observaciones TEXT NULL,
    ADD COLUMN IF NOT EXISTS alcance_autorizacion TEXT NULL;

ALTER TABLE documentos_b2b
    ADD COLUMN IF NOT EXISTS categoria VARCHAR(40) NULL,
    ADD COLUMN IF NOT EXISTS fecha_documento DATE NULL,
    ADD COLUMN IF NOT EXISTS descripcion TEXT NULL;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='pacientes_b2b_movilidad_check') THEN
        ALTER TABLE pacientes_b2b ADD CONSTRAINT pacientes_b2b_movilidad_check
            CHECK (movilidad IS NULL OR movilidad IN ('independiente','asistencia_parcial','asistencia_total','inmovil'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='pacientes_b2b_dependencia_check') THEN
        ALTER TABLE pacientes_b2b ADD CONSTRAINT pacientes_b2b_dependencia_check
            CHECK (nivel_dependencia IS NULL OR nivel_dependencia IN ('baja','media','alta','total'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='pacientes_b2b_riesgo_caida_check') THEN
        ALTER TABLE pacientes_b2b ADD CONSTRAINT pacientes_b2b_riesgo_caida_check
            CHECK (riesgo_caida IS NULL OR riesgo_caida IN ('bajo','moderado','alto'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='pacientes_b2b_continencia_check') THEN
        ALTER TABLE pacientes_b2b ADD CONSTRAINT pacientes_b2b_continencia_check
            CHECK (continencia IS NULL OR continencia IN ('continente','asistencia','incontinencia_urinaria','incontinencia_fecal','incontinencia_mixta'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='contactos_b2b_prioridad_check') THEN
        ALTER TABLE contactos_b2b ADD CONSTRAINT contactos_b2b_prioridad_check
            CHECK (prioridad IS NULL OR prioridad BETWEEN 1 AND 99);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='documentos_b2b_categoria_check') THEN
        ALTER TABLE documentos_b2b ADD CONSTRAINT documentos_b2b_categoria_check
            CHECK (categoria IS NULL OR categoria IN ('receta','estudio_analisis','epicrisis','indicacion','dni','cobertura','otro'));
    END IF;
END;
$$;

CREATE UNIQUE INDEX IF NOT EXISTS pacientes_b2b_tenant_id_uq
    ON pacientes_b2b (institucion_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS usuarios_b2b_tenant_id_uq
    ON usuarios_b2b (institucion_id, id);
CREATE UNIQUE INDEX IF NOT EXISTS operadores_b2b_tenant_id_uq
    ON operadores_b2b (institucion_id, id);
ALTER TABLE operadores_b2b
    ADD COLUMN IF NOT EXISTS usuario_b2b_id INTEGER NULL;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='operadores_b2b_staff_fk') THEN
        ALTER TABLE operadores_b2b ADD CONSTRAINT operadores_b2b_staff_fk
            FOREIGN KEY (institucion_id,usuario_b2b_id)
            REFERENCES usuarios_b2b(institucion_id,id) ON DELETE SET NULL (usuario_b2b_id);
    END IF;
END;
$$;
CREATE UNIQUE INDEX IF NOT EXISTS operadores_b2b_staff_uq
    ON operadores_b2b (institucion_id,usuario_b2b_id)
    WHERE usuario_b2b_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS contactos_b2b_tenant_patient_id_uq
    ON contactos_b2b (institucion_id, paciente_id, id);

CREATE TABLE IF NOT EXISTS alertas_residente_b2b (
    id BIGSERIAL PRIMARY KEY,
    institucion_id INTEGER NOT NULL,
    paciente_id INTEGER NOT NULL,
    tipo VARCHAR(40) NOT NULL CHECK (tipo IN ('anticoagulacion','diabetes','personalizada','otra')),
    etiqueta VARCHAR(160) NOT NULL CHECK (length(btrim(etiqueta)) BETWEEN 2 AND 160),
    severidad VARCHAR(20) NOT NULL DEFAULT 'moderada' CHECK (severidad IN ('informativa','moderada','alta')),
    vigente_desde TIMESTAMPTZ NULL,
    vigente_hasta TIMESTAMPTZ NULL,
    activa BOOLEAN NOT NULL DEFAULT TRUE,
    creado_por INTEGER NULL,
    operador_b2b_id BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    deleted_at TIMESTAMPTZ NULL,
    deleted_by INTEGER NULL,
    deletion_reason TEXT NULL,
    CONSTRAINT alertas_residente_b2b_vigencia_check CHECK (vigente_hasta IS NULL OR vigente_desde IS NULL OR vigente_hasta >= vigente_desde),
    CONSTRAINT alertas_residente_b2b_patient_fk FOREIGN KEY (institucion_id,paciente_id)
        REFERENCES pacientes_b2b(institucion_id,id) ON DELETE CASCADE,
    CONSTRAINT alertas_residente_b2b_creator_fk FOREIGN KEY (institucion_id,creado_por)
        REFERENCES usuarios_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT alertas_residente_b2b_operator_fk FOREIGN KEY (institucion_id,operador_b2b_id)
        REFERENCES operadores_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT alertas_residente_b2b_deleted_by_fk FOREIGN KEY (institucion_id,deleted_by)
        REFERENCES usuarios_b2b(institucion_id,id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS alertas_residente_b2b_patient_idx
    ON alertas_residente_b2b (institucion_id,paciente_id,activa,severidad)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS alertas_residente_b2b_vigencia_idx
    ON alertas_residente_b2b (institucion_id,vigente_hasta)
    WHERE deleted_at IS NULL AND activa=TRUE;

CREATE TABLE IF NOT EXISTS incidentes_b2b (
    id BIGSERIAL PRIMARY KEY,
    institucion_id INTEGER NOT NULL,
    paciente_id INTEGER NOT NULL,
    categoria VARCHAR(40) NOT NULL CHECK (categoria IN ('caida','golpe_herida','error_medicacion','omision_medicacion','episodio_conductual','derivacion','otro')),
    severidad VARCHAR(20) NOT NULL DEFAULT 'moderada' CHECK (severidad IN ('leve','moderada','alta','critica')),
    ocurrido_at TIMESTAMPTZ NOT NULL,
    descripcion TEXT NOT NULL CHECK (length(btrim(descripcion)) BETWEEN 3 AND 4000),
    accion_tomada TEXT NULL,
    estado VARCHAR(30) NOT NULL DEFAULT 'abierto' CHECK (estado IN ('abierto','en_seguimiento','cerrado')),
    notificacion_realizada BOOLEAN NOT NULL DEFAULT FALSE,
    contacto_notificado_id INTEGER NULL,
    notificacion_detalle TEXT NULL,
    notificada_at TIMESTAMPTZ NULL,
    creado_por INTEGER NULL,
    operador_b2b_id BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    deleted_at TIMESTAMPTZ NULL,
    deleted_by INTEGER NULL,
    deletion_reason TEXT NULL,
    CONSTRAINT incidentes_b2b_notification_check CHECK (
        (notificacion_realizada=FALSE AND notificada_at IS NULL)
        OR (notificacion_realizada=TRUE AND notificada_at IS NOT NULL)
    ),
    CONSTRAINT incidentes_b2b_patient_fk FOREIGN KEY (institucion_id,paciente_id)
        REFERENCES pacientes_b2b(institucion_id,id) ON DELETE CASCADE,
    CONSTRAINT incidentes_b2b_contact_fk FOREIGN KEY (institucion_id,paciente_id,contacto_notificado_id)
        REFERENCES contactos_b2b(institucion_id,paciente_id,id) ON DELETE RESTRICT,
    CONSTRAINT incidentes_b2b_creator_fk FOREIGN KEY (institucion_id,creado_por)
        REFERENCES usuarios_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT incidentes_b2b_operator_fk FOREIGN KEY (institucion_id,operador_b2b_id)
        REFERENCES operadores_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT incidentes_b2b_deleted_by_fk FOREIGN KEY (institucion_id,deleted_by)
        REFERENCES usuarios_b2b(institucion_id,id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS incidentes_b2b_patient_date_idx
    ON incidentes_b2b (institucion_id,paciente_id,ocurrido_at DESC,id DESC)
    WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS incidentes_b2b_metrics_idx
    ON incidentes_b2b (institucion_id,categoria,estado,ocurrido_at DESC)
    WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS estados_residente_b2b (
    id BIGSERIAL PRIMARY KEY,
    institucion_id INTEGER NOT NULL,
    paciente_id INTEGER NOT NULL,
    tipo VARCHAR(40) NOT NULL CHECK (tipo IN ('internado','salida_medica','salida_familiar','otro')),
    iniciado_at TIMESTAMPTZ NOT NULL,
    finalizado_at TIMESTAMPTZ NULL,
    motivo TEXT NULL,
    iniciado_por INTEGER NULL,
    iniciado_operador_b2b_id BIGINT NULL,
    finalizado_por INTEGER NULL,
    finalizado_operador_b2b_id BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    CONSTRAINT estados_residente_b2b_dates_check CHECK (finalizado_at IS NULL OR finalizado_at >= iniciado_at),
    CONSTRAINT estados_residente_b2b_patient_fk FOREIGN KEY (institucion_id,paciente_id)
        REFERENCES pacientes_b2b(institucion_id,id) ON DELETE CASCADE,
    CONSTRAINT estados_residente_b2b_started_by_fk FOREIGN KEY (institucion_id,iniciado_por)
        REFERENCES usuarios_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT estados_residente_b2b_started_operator_fk FOREIGN KEY (institucion_id,iniciado_operador_b2b_id)
        REFERENCES operadores_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT estados_residente_b2b_finished_by_fk FOREIGN KEY (institucion_id,finalizado_por)
        REFERENCES usuarios_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT estados_residente_b2b_finished_operator_fk FOREIGN KEY (institucion_id,finalizado_operador_b2b_id)
        REFERENCES operadores_b2b(institucion_id,id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX IF NOT EXISTS estados_residente_b2b_one_open_uq
    ON estados_residente_b2b (institucion_id,paciente_id)
    WHERE finalizado_at IS NULL;
CREATE INDEX IF NOT EXISTS estados_residente_b2b_history_idx
    ON estados_residente_b2b (institucion_id,paciente_id,iniciado_at DESC,id DESC);
`,
});

function httpError(status, code, message) {
    return Object.assign(new Error(message), { status, code });
}

function normalizedText(value, field, { required = false, min = 0, max = 2000 } = {}) {
    if (value === undefined) return undefined;
    if (value === null) return null;
    const text = String(value).trim();
    if (!text) {
        if (required) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} es obligatorio`);
        return null;
    }
    if (text.length < min) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} debe tener al menos ${min} caracteres`);
    if (text.length > max) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} supera el largo permitido`);
    return text;
}

function enumValue(value, allowed, field, { required = false } = {}) {
    if (value === undefined) return undefined;
    if (value === null || value === '') {
        if (required) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} es obligatorio`);
        return null;
    }
    if (!allowed.includes(value)) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} inválido`);
    return value;
}

function booleanValue(value, field) {
    if (value === undefined) return undefined;
    if (typeof value !== 'boolean') throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} debe ser booleano`);
    return value;
}

function dateTimeValue(value, field, { required = false } = {}) {
    if (value === undefined) return undefined;
    if (value === null || value === '') {
        if (required) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} es obligatorio`);
        return null;
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} inválido`);
    return parsed.toISOString();
}

function dateValue(value, field) {
    if (value === undefined) return undefined;
    if (value === null || value === '') return null;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(String(value))) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} inválida`);
    return String(value);
}

function validateCareProfilePayload(body) {
    const result = {};
    result.dieta_restricciones = normalizedText(body.dieta_restricciones, 'dieta_restricciones', { max: 2000 });
    result.aspectos_cognitivos = normalizedText(body.aspectos_cognitivos, 'aspectos_cognitivos', { max: 2000 });
    for (const [field, allowed] of Object.entries(LA1_CARE_PROFILE_ENUMS)) {
        result[field] = enumValue(body[field], allowed, field);
    }
    return Object.fromEntries(Object.entries(result).filter(([, value]) => value !== undefined));
}

function validateContactMetadata(body) {
    const result = {};
    if (body.prioridad !== undefined) {
        if (body.prioridad === null || body.prioridad === '') result.prioridad = null;
        else {
            const priority = Number(body.prioridad);
            if (!Number.isInteger(priority) || priority < 1 || priority > 99) throw httpError(400, 'INVALID_PRIORIDAD', 'prioridad debe estar entre 1 y 99');
            result.prioridad = priority;
        }
    }
    result.observaciones = normalizedText(body.observaciones, 'observaciones', { max: 2000 });
    result.alcance_autorizacion = normalizedText(body.alcance_autorizacion, 'alcance_autorizacion', { max: 1000 });
    return Object.fromEntries(Object.entries(result).filter(([, value]) => value !== undefined));
}

function validateDocumentMetadata(body) {
    const result = {
        categoria: enumValue(body.categoria, LA1_DOCUMENT_CATEGORIES, 'categoria'),
        fecha_documento: dateValue(body.fecha_documento, 'fecha_documento'),
        descripcion: normalizedText(body.descripcion, 'descripcion', { max: 2000 }),
    };
    return Object.fromEntries(Object.entries(result).filter(([, value]) => value !== undefined));
}

function derivedAlerts(patient) {
    const alerts = [];
    if (String(patient.alergias || '').trim()) {
        alerts.push({ id: 'perfil:alergias', origen: 'perfil', derivada: true, tipo: 'alergia',
            etiqueta: `Alergias: ${String(patient.alergias).trim()}`, severidad: 'alta', activa: true });
    }
    if (patient.riesgo_caida === 'moderado' || patient.riesgo_caida === 'alto') {
        alerts.push({ id: 'perfil:riesgo_caida', origen: 'perfil', derivada: true, tipo: 'riesgo_caida',
            etiqueta: `Riesgo de caída ${patient.riesgo_caida}`, severidad: patient.riesgo_caida === 'alto' ? 'alta' : 'moderada', activa: true });
    }
    if (String(patient.dieta_restricciones || '').trim()) {
        alerts.push({ id: 'perfil:dieta', origen: 'perfil', derivada: true, tipo: 'dieta_especial',
            etiqueta: `Dieta: ${String(patient.dieta_restricciones).trim()}`, severidad: 'moderada', activa: true });
    }
    return alerts;
}

function registerLA1Routes(app, dependencies) {
    const {
        pool, authB2BMiddleware, requireB2BRole, checkB2BPacienteAccess,
        checkB2BCanDo, checkB2BFamiliarCanSee, loadAndAuthorizeB2BPatientResource,
        withB2BTransaction, appendB2BAudit, beginIdempotentOperation,
        completeIdempotentOperation, assertB2BVersion, getExpectedB2BVersion,
        guardB2BPatientMutation, softDeleteB2BPatientResource, sendP1Error,
    } = dependencies;

    const mutableRoles = requireB2BRole('admin_institucion', 'medico', 'cuidador_staff');
    const assertAction = (req, action) => {
        if (!checkB2BCanDo(req.b2bUser, action)) throw httpError(403, 'FORBIDDEN', 'No tenés permisos para esta acción');
    };
    const assertFamilySection = (req, section) => {
        if (req.b2bUser.rol === 'familiar' && !checkB2BFamiliarCanSee(req.b2bUser, section)) {
            throw httpError(403, 'FORBIDDEN', 'Acceso restringido por la institución');
        }
    };
    const assertPatientAccess = async (req, patientId, queryable = pool) => {
        if (!(await checkB2BPacienteAccess(req.b2bUser, patientId, queryable))) {
            throw httpError(404, 'PATIENT_NOT_FOUND', 'Paciente no encontrado');
        }
    };
    const replayHeader = (res, replayed) => { if (replayed) res.setHeader('Idempotent-Replayed', 'true'); };

    app.get('/api/b2b/pacientes/:id/alertas', authB2BMiddleware, async (req, res) => {
        try {
            assertFamilySection(req, 'alertas');
            await assertPatientAccess(req, req.params.id);
            const patient = (await pool.query(
                `SELECT id,alergias,riesgo_caida,dieta_restricciones FROM pacientes_b2b
                 WHERE id=$1 AND institucion_id=$2 AND activo=TRUE`,
                [req.params.id, req.b2bUser.institucion_id]
            )).rows[0];
            const stored = await pool.query(
                `SELECT a.*,COALESCE(o.nombre,u.nombre,'Sistema') AS actor_nombre
                 FROM alertas_residente_b2b a
                 LEFT JOIN usuarios_b2b u ON u.id=a.creado_por AND u.institucion_id=a.institucion_id
                 LEFT JOIN operadores_b2b o ON o.id=a.operador_b2b_id AND o.institucion_id=a.institucion_id
                 WHERE a.institucion_id=$1 AND a.paciente_id=$2 AND a.deleted_at IS NULL
                 ORDER BY a.activa DESC,CASE a.severidad WHEN 'alta' THEN 1 WHEN 'moderada' THEN 2 ELSE 3 END,a.created_at DESC`,
                [req.b2bUser.institucion_id, req.params.id]
            );
            res.json([...derivedAlerts(patient), ...stored.rows.map(row => ({ ...row, origen: 'manual', derivada: false }))]);
        } catch (error) { sendP1Error(res, error, 'Error al obtener alertas'); }
    });

    app.post('/api/b2b/pacientes/:id/alertas', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'gestionar_alertas');
            const type = enumValue(req.body.tipo, LA1_PERSISTED_ALERT_TYPES, 'tipo', { required: true });
            const label = normalizedText(req.body.etiqueta, 'etiqueta', { required: true, max: 160 });
            const severity = enumValue(req.body.severidad ?? 'moderada', LA1_ALERT_SEVERITIES, 'severidad', { required: true });
            const from = dateTimeValue(req.body.vigente_desde, 'vigente_desde');
            const until = dateTimeValue(req.body.vigente_hasta, 'vigente_hasta');
            if (from && until && new Date(until) < new Date(from)) throw httpError(400, 'INVALID_ALERT_VALIDITY', 'La vigencia final no puede ser anterior a la inicial');
            const outcome = await withB2BTransaction(pool, async client => {
                await assertPatientAccess(req, req.params.id, client);
                await guardB2BPatientMutation(client, req, req.params.id, 'new');
                const idem = await beginIdempotentOperation(client, { req, actor: req.b2bUser, operation: 'la1_alerta_crear', patientId: Number(req.params.id) });
                if (idem.replay) {
                    const prior = await client.query('SELECT * FROM alertas_residente_b2b WHERE id=$1 AND institucion_id=$2 AND deleted_at IS NULL', [idem.previous.resultado_id, req.b2bUser.institucion_id]);
                    if (!prior.rows[0]) throw new Error('Resultado idempotente no disponible');
                    return { row: prior.rows[0], replayed: true };
                }
                const inserted = await client.query(
                    `INSERT INTO alertas_residente_b2b
                     (institucion_id,paciente_id,tipo,etiqueta,severidad,vigente_desde,vigente_hasta,activa,creado_por,operador_b2b_id)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
                    [req.b2bUser.institucion_id, req.params.id, type, label, severity, from, until,
                        req.body.activa === undefined ? true : booleanValue(req.body.activa, 'activa'),
                        req.b2bUser.principal_usuario_id || req.b2bUser.id, req.b2bUser.operador_b2b_id || null]
                );
                await appendB2BAudit(client, { institutionId: req.b2bUser.institucion_id, patientId: Number(req.params.id), actor: req.b2bUser,
                    resourceType: 'alerta_residente', resourceId: inserted.rows[0].id, action: 'CREATE', version: inserted.rows[0].version, after: inserted.rows[0] });
                await completeIdempotentOperation(client, idem, { resultType: 'alerta_residente', resultId: inserted.rows[0].id, httpStatus: 201, safeResult: { id: inserted.rows[0].id } });
                return { row: inserted.rows[0], replayed: false };
            });
            replayHeader(res, outcome.replayed);
            res.status(201).json(outcome.row);
        } catch (error) { sendP1Error(res, error, 'Error al crear alerta'); }
    });

    app.patch('/api/b2b/alertas/:id', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'gestionar_alertas');
            const changed = await withB2BTransaction(pool, async client => {
                const access = await loadAndAuthorizeB2BPatientResource(req.b2bUser, 'alertas_residente_b2b', req.params.id, client, { forUpdate: true });
                if (!access.found || !access.allowed) throw httpError(404, 'RESOURCE_NOT_FOUND', 'Alerta no encontrada');
                await guardB2BPatientMutation(client, req, access.row.paciente_id, 'correction');
                assertB2BVersion(access.row, getExpectedB2BVersion(req));
                const type = enumValue(req.body.tipo ?? access.row.tipo, LA1_PERSISTED_ALERT_TYPES, 'tipo', { required: true });
                const label = normalizedText(req.body.etiqueta ?? access.row.etiqueta, 'etiqueta', { required: true, max: 160 });
                const severity = enumValue(req.body.severidad ?? access.row.severidad, LA1_ALERT_SEVERITIES, 'severidad', { required: true });
                const from = dateTimeValue(req.body.vigente_desde === undefined ? access.row.vigente_desde : req.body.vigente_desde, 'vigente_desde');
                const until = dateTimeValue(req.body.vigente_hasta === undefined ? access.row.vigente_hasta : req.body.vigente_hasta, 'vigente_hasta');
                if (from && until && new Date(until) < new Date(from)) throw httpError(400, 'INVALID_ALERT_VALIDITY', 'La vigencia final no puede ser anterior a la inicial');
                const active = req.body.activa === undefined ? access.row.activa : booleanValue(req.body.activa, 'activa');
                const updated = await client.query(
                    `UPDATE alertas_residente_b2b SET tipo=$1,etiqueta=$2,severidad=$3,vigente_desde=$4,vigente_hasta=$5,
                     activa=$6,updated_at=clock_timestamp(),version=version+1 WHERE id=$7 AND institucion_id=$8 RETURNING *`,
                    [type, label, severity, from, until, active, access.row.id, req.b2bUser.institucion_id]
                );
                await appendB2BAudit(client, { institutionId: req.b2bUser.institucion_id, patientId: access.row.paciente_id, actor: req.b2bUser,
                    resourceType: 'alerta_residente', resourceId: access.row.id, action: 'UPDATE', version: updated.rows[0].version,
                    before: access.row, after: updated.rows[0] });
                return updated.rows[0];
            });
            res.json(changed);
        } catch (error) { sendP1Error(res, error, 'Error al actualizar alerta'); }
    });

    app.delete('/api/b2b/alertas/:id', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'gestionar_alertas');
            const outcome = await softDeleteB2BPatientResource(req, 'alertas_residente_b2b', 'alerta_residente', 'Alerta');
            res.json({ success: true, already_deleted: outcome.alreadyDeleted, version: outcome.version });
        } catch (error) { sendP1Error(res, error, 'Error al archivar alerta'); }
    });

    app.get('/api/b2b/pacientes/:id/incidentes', authB2BMiddleware, async (req, res) => {
        try {
            assertFamilySection(req, 'incidentes');
            await assertPatientAccess(req, req.params.id);
            const archiveFilter = String(req.query.archivo || 'activos');
            if (!['activos', 'archivados', 'todos'].includes(archiveFilter)) {
                throw httpError(400, 'INVALID_ARCHIVE_FILTER', 'Filtro de incidentes inválido');
            }
            const archiveClause = archiveFilter === 'archivados'
                ? 'AND i.deleted_at IS NOT NULL'
                : archiveFilter === 'todos' ? '' : 'AND i.deleted_at IS NULL';
            const result = await pool.query(
                `SELECT i.*,c.nombre AS contacto_notificado_nombre,COALESCE(o.nombre,u.nombre,'Sistema') AS actor_nombre,
                        COALESCE(archive_operator.nombre,archive_user.nombre,deleted_user.nombre) AS archivado_por_nombre,
                        COALESCE(archive_event.ocurrido_at,i.deleted_at) AS archivado_at
                 FROM incidentes_b2b i
                 LEFT JOIN contactos_b2b c ON c.id=i.contacto_notificado_id AND c.institucion_id=i.institucion_id AND c.paciente_id=i.paciente_id
                 LEFT JOIN usuarios_b2b u ON u.id=i.creado_por AND u.institucion_id=i.institucion_id
                 LEFT JOIN operadores_b2b o ON o.id=i.operador_b2b_id AND o.institucion_id=i.institucion_id
                 LEFT JOIN usuarios_b2b deleted_user ON deleted_user.id=i.deleted_by AND deleted_user.institucion_id=i.institucion_id
                 LEFT JOIN LATERAL (
                    SELECT a.actor_usuario_id,a.operador_b2b_id,a.ocurrido_at
                    FROM auditoria_eventos_b2b a
                    WHERE a.institucion_id=i.institucion_id AND a.recurso_tipo='incidente'
                      AND a.recurso_id=i.id AND a.accion='SOFT_DELETE'
                    ORDER BY a.id DESC LIMIT 1
                 ) archive_event ON TRUE
                 LEFT JOIN usuarios_b2b archive_user ON archive_user.id=archive_event.actor_usuario_id AND archive_user.institucion_id=i.institucion_id
                 LEFT JOIN operadores_b2b archive_operator ON archive_operator.id=archive_event.operador_b2b_id AND archive_operator.institucion_id=i.institucion_id
                 WHERE i.institucion_id=$1 AND i.paciente_id=$2 ${archiveClause}
                 ORDER BY i.ocurrido_at DESC,i.id DESC LIMIT 250`,
                [req.b2bUser.institucion_id, req.params.id]
            );
            res.json(result.rows);
        } catch (error) { sendP1Error(res, error, 'Error al obtener incidentes'); }
    });

    app.post('/api/b2b/pacientes/:id/incidentes', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'gestionar_incidentes');
            const category = enumValue(req.body.categoria, LA1_INCIDENT_CATEGORIES, 'categoria', { required: true });
            const severity = enumValue(req.body.severidad ?? 'moderada', LA1_INCIDENT_SEVERITIES, 'severidad', { required: true });
            const occurredAt = dateTimeValue(req.body.ocurrido_at, 'ocurrido_at', { required: true });
            const description = normalizedText(req.body.descripcion, 'descripcion', { required: true, min: 3, max: 4000 });
            const actionTaken = normalizedText(req.body.accion_tomada, 'accion_tomada', { max: 4000 });
            const status = enumValue(req.body.estado ?? 'abierto', LA1_INCIDENT_STATUSES, 'estado', { required: true });
            const notified = req.body.notificacion_realizada === undefined ? false : booleanValue(req.body.notificacion_realizada, 'notificacion_realizada');
            const contactRaw = notified ? req.body.contacto_notificado_id : null;
            const contactId = contactRaw === undefined || contactRaw === null || contactRaw === ''
                ? null : Number(contactRaw);
            if (contactId !== null && (!Number.isSafeInteger(contactId) || contactId <= 0)) throw httpError(400, 'INVALID_CONTACT', 'Contacto notificado inválido');
            const detail = notified ? normalizedText(req.body.notificacion_detalle, 'notificacion_detalle', { max: 2000 }) : null;
            const notifiedAt = notified ? dateTimeValue(req.body.notificada_at || new Date().toISOString(), 'notificada_at', { required: true }) : null;
            if (notified && contactId === null) throw httpError(400, 'NOTIFICATION_CONTACT_REQUIRED', 'Seleccioná el contacto notificado');
            const outcome = await withB2BTransaction(pool, async client => {
                await assertPatientAccess(req, req.params.id, client);
                await guardB2BPatientMutation(client, req, req.params.id, 'new');
                if (contactId !== null) {
                    const contact = await client.query(
                        `SELECT id FROM contactos_b2b WHERE id=$1 AND institucion_id=$2 AND paciente_id=$3 AND deleted_at IS NULL`,
                        [contactId, req.b2bUser.institucion_id, req.params.id]
                    );
                    if (contact.rowCount === 0) throw httpError(400, 'INVALID_CONTACT', 'El contacto notificado no pertenece al residente');
                }
                const idem = await beginIdempotentOperation(client, { req, actor: req.b2bUser, operation: 'la1_incidente_crear', patientId: Number(req.params.id) });
                if (idem.replay) {
                    const prior = await client.query('SELECT * FROM incidentes_b2b WHERE id=$1 AND institucion_id=$2 AND deleted_at IS NULL', [idem.previous.resultado_id, req.b2bUser.institucion_id]);
                    if (!prior.rows[0]) throw new Error('Resultado idempotente no disponible');
                    return { row: prior.rows[0], replayed: true };
                }
                const inserted = await client.query(
                    `INSERT INTO incidentes_b2b
                     (institucion_id,paciente_id,categoria,severidad,ocurrido_at,descripcion,accion_tomada,estado,
                      notificacion_realizada,contacto_notificado_id,notificacion_detalle,notificada_at,creado_por,operador_b2b_id)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
                    [req.b2bUser.institucion_id, req.params.id, category, severity, occurredAt, description, actionTaken, status,
                        notified, notified ? contactId : null, detail, notifiedAt, req.b2bUser.principal_usuario_id || req.b2bUser.id, req.b2bUser.operador_b2b_id || null]
                );
                await appendB2BAudit(client, { institutionId: req.b2bUser.institucion_id, patientId: Number(req.params.id), actor: req.b2bUser,
                    resourceType: 'incidente', resourceId: inserted.rows[0].id, action: 'CREATE', version: inserted.rows[0].version, after: inserted.rows[0] });
                await completeIdempotentOperation(client, idem, { resultType: 'incidente', resultId: inserted.rows[0].id, httpStatus: 201, safeResult: { id: inserted.rows[0].id } });
                return { row: inserted.rows[0], replayed: false };
            });
            replayHeader(res, outcome.replayed);
            res.status(201).json(outcome.row);
        } catch (error) { sendP1Error(res, error, 'Error al registrar incidente'); }
    });

    app.patch('/api/b2b/incidentes/:id', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'gestionar_incidentes');
            const changed = await withB2BTransaction(pool, async client => {
                const access = await loadAndAuthorizeB2BPatientResource(req.b2bUser, 'incidentes_b2b', req.params.id, client, { forUpdate: true });
                if (!access.found || !access.allowed) throw httpError(404, 'RESOURCE_NOT_FOUND', 'Incidente no encontrado');
                await guardB2BPatientMutation(client, req, access.row.paciente_id, 'correction');
                assertB2BVersion(access.row, getExpectedB2BVersion(req));
                const category = enumValue(req.body.categoria ?? access.row.categoria, LA1_INCIDENT_CATEGORIES, 'categoria', { required: true });
                const severity = enumValue(req.body.severidad ?? access.row.severidad, LA1_INCIDENT_SEVERITIES, 'severidad', { required: true });
                const occurredAt = dateTimeValue(req.body.ocurrido_at ?? access.row.ocurrido_at, 'ocurrido_at', { required: true });
                const description = normalizedText(req.body.descripcion ?? access.row.descripcion, 'descripcion', { required: true, min: 3, max: 4000 });
                const actionTaken = normalizedText(req.body.accion_tomada === undefined ? access.row.accion_tomada : req.body.accion_tomada, 'accion_tomada', { max: 4000 });
                const status = enumValue(req.body.estado ?? access.row.estado, LA1_INCIDENT_STATUSES, 'estado', { required: true });
                const notified = req.body.notificacion_realizada === undefined ? access.row.notificacion_realizada : booleanValue(req.body.notificacion_realizada, 'notificacion_realizada');
                const contactRaw = notified
                    ? (req.body.contacto_notificado_id === undefined ? access.row.contacto_notificado_id : req.body.contacto_notificado_id)
                    : null;
                const contactId = contactRaw === null || contactRaw === '' ? null : Number(contactRaw);
                if (contactId !== null) {
                    if (!Number.isSafeInteger(contactId) || contactId <= 0) throw httpError(400, 'INVALID_CONTACT', 'Contacto notificado inválido');
                    const contact = await client.query(
                        `SELECT id FROM contactos_b2b WHERE id=$1 AND institucion_id=$2 AND paciente_id=$3 AND deleted_at IS NULL`,
                        [contactId, req.b2bUser.institucion_id, access.row.paciente_id]
                    );
                    if (contact.rowCount === 0) throw httpError(400, 'INVALID_CONTACT', 'El contacto notificado no pertenece al residente');
                }
                if (notified && contactId === null) throw httpError(400, 'NOTIFICATION_CONTACT_REQUIRED', 'Seleccioná el contacto notificado');
                const detail = notified
                    ? normalizedText(req.body.notificacion_detalle === undefined ? access.row.notificacion_detalle : req.body.notificacion_detalle, 'notificacion_detalle', { max: 2000 })
                    : null;
                const notifiedAt = notified
                    ? dateTimeValue(req.body.notificada_at === undefined ? (access.row.notificada_at || new Date().toISOString()) : req.body.notificada_at, 'notificada_at', { required: true })
                    : null;
                const updated = await client.query(
                    `UPDATE incidentes_b2b SET categoria=$1,severidad=$2,ocurrido_at=$3,descripcion=$4,accion_tomada=$5,
                     estado=$6,notificacion_realizada=$7,contacto_notificado_id=$8,notificacion_detalle=$9,notificada_at=$10,
                     updated_at=clock_timestamp(),version=version+1 WHERE id=$11 AND institucion_id=$12 RETURNING *`,
                    [category, severity, occurredAt, description, actionTaken, status, notified, contactId, detail, notifiedAt, access.row.id, req.b2bUser.institucion_id]
                );
                await appendB2BAudit(client, { institutionId: req.b2bUser.institucion_id, patientId: access.row.paciente_id, actor: req.b2bUser,
                    resourceType: 'incidente', resourceId: access.row.id, action: 'UPDATE', version: updated.rows[0].version,
                    before: access.row, after: updated.rows[0] });
                return updated.rows[0];
            });
            res.json(changed);
        } catch (error) { sendP1Error(res, error, 'Error al actualizar incidente'); }
    });

    app.delete('/api/b2b/incidentes/:id', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'gestionar_incidentes');
            const outcome = await softDeleteB2BPatientResource(req, 'incidentes_b2b', 'incidente', 'Incidente');
            res.json({ success: true, already_deleted: outcome.alreadyDeleted, version: outcome.version });
        } catch (error) { sendP1Error(res, error, 'Error al archivar incidente'); }
    });

    app.get('/api/b2b/pacientes/:id/estados', authB2BMiddleware, async (req, res) => {
        try {
            assertFamilySection(req, 'estados');
            await assertPatientAccess(req, req.params.id);
            const result = await pool.query(
                `SELECT e.*,COALESCE(oi.nombre,ui.nombre,'Sistema') AS iniciado_por_nombre,
                        COALESCE(ofi.nombre,uf.nombre) AS finalizado_por_nombre
                 FROM estados_residente_b2b e
                 LEFT JOIN usuarios_b2b ui ON ui.id=e.iniciado_por AND ui.institucion_id=e.institucion_id
                 LEFT JOIN operadores_b2b oi ON oi.id=e.iniciado_operador_b2b_id AND oi.institucion_id=e.institucion_id
                 LEFT JOIN usuarios_b2b uf ON uf.id=e.finalizado_por AND uf.institucion_id=e.institucion_id
                 LEFT JOIN operadores_b2b ofi ON ofi.id=e.finalizado_operador_b2b_id AND ofi.institucion_id=e.institucion_id
                 WHERE e.institucion_id=$1 AND e.paciente_id=$2 ORDER BY e.iniciado_at DESC,e.id DESC LIMIT 250`,
                [req.b2bUser.institucion_id, req.params.id]
            );
            const current = result.rows.find(row => row.finalizado_at === null) || null;
            res.json({ actual: current || { tipo: 'presente', presente: true, version: null }, historial: result.rows });
        } catch (error) { sendP1Error(res, error, 'Error al obtener estados temporales'); }
    });

    app.post('/api/b2b/pacientes/:id/estados/transiciones', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'gestionar_estado_temporal');
            const requested = req.body.tipo === 'regreso' ? 'presente' : req.body.tipo;
            if (requested !== 'presente' && !LA1_TEMPORARY_STATE_TYPES.includes(requested)) {
                throw httpError(400, 'INVALID_TEMPORARY_STATE', 'Estado temporal inválido');
            }
            const transitionAt = dateTimeValue(req.body.ocurrido_at || new Date().toISOString(), 'ocurrido_at', { required: true });
            const reason = normalizedText(req.body.motivo, 'motivo', { max: 2000 });
            const outcome = await withB2BTransaction(pool, async client => {
                const patient = await client.query(
                    `SELECT id,fecha_egreso FROM pacientes_b2b WHERE id=$1 AND institucion_id=$2 AND activo=TRUE FOR UPDATE`,
                    [req.params.id, req.b2bUser.institucion_id]
                );
                if (patient.rowCount === 0) throw httpError(404, 'PATIENT_NOT_FOUND', 'Paciente no encontrado');
                if (!(await checkB2BPacienteAccess(req.b2bUser, req.params.id, client))) throw httpError(404, 'PATIENT_NOT_FOUND', 'Paciente no encontrado');
                await guardB2BPatientMutation(client, req, req.params.id, 'new');
                const idem = await beginIdempotentOperation(client, { req, actor: req.b2bUser, operation: 'la1_estado_transicion', patientId: Number(req.params.id) });
                if (idem.replay) return { result: idem.previous.resultado, replayed: true };
                const currentResult = await client.query(
                    `SELECT * FROM estados_residente_b2b WHERE institucion_id=$1 AND paciente_id=$2 AND finalizado_at IS NULL FOR UPDATE`,
                    [req.b2bUser.institucion_id, req.params.id]
                );
                const current = currentResult.rows[0] || null;
                if (current) assertB2BVersion(current, getExpectedB2BVersion(req));
                if (current && new Date(transitionAt) < new Date(current.iniciado_at)) {
                    throw httpError(400, 'INVALID_TRANSITION_TIME', 'La transición no puede ser anterior al estado vigente');
                }
                let closed = null;
                if (current) {
                    const closedResult = await client.query(
                        `UPDATE estados_residente_b2b SET finalizado_at=$1,finalizado_por=$2,finalizado_operador_b2b_id=$3,
                         updated_at=clock_timestamp(),version=version+1 WHERE id=$4 AND institucion_id=$5 RETURNING *`,
                        [transitionAt, req.b2bUser.principal_usuario_id || req.b2bUser.id, req.b2bUser.operador_b2b_id || null,
                            current.id, req.b2bUser.institucion_id]
                    );
                    closed = closedResult.rows[0];
                    await appendB2BAudit(client, { institutionId: req.b2bUser.institucion_id, patientId: Number(req.params.id), actor: req.b2bUser,
                        resourceType: 'estado_residente', resourceId: current.id, action: 'TRANSITION', version: closed.version,
                        reason, before: current, after: closed });
                }
                let active = null;
                if (requested !== 'presente') {
                    const inserted = await client.query(
                        `INSERT INTO estados_residente_b2b
                         (institucion_id,paciente_id,tipo,iniciado_at,motivo,iniciado_por,iniciado_operador_b2b_id)
                         VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
                        [req.b2bUser.institucion_id, req.params.id, requested, transitionAt, reason,
                            req.b2bUser.principal_usuario_id || req.b2bUser.id, req.b2bUser.operador_b2b_id || null]
                    );
                    active = inserted.rows[0];
                    await appendB2BAudit(client, { institutionId: req.b2bUser.institucion_id, patientId: Number(req.params.id), actor: req.b2bUser,
                        resourceType: 'estado_residente', resourceId: active.id, action: 'TRANSITION', version: active.version,
                        reason, before: current, after: active });
                }
                const result = { actual: active || { tipo: 'presente', presente: true, version: null }, cerrado: closed };
                await completeIdempotentOperation(client, idem, { resultType: 'estado_residente', resultId: active?.id || closed?.id || null,
                    httpStatus: 200, safeResult: result });
                return { result, replayed: false };
            });
            replayHeader(res, outcome.replayed);
            res.json(outcome.result);
        } catch (error) {
            if (error?.code === '23505') return res.status(409).json({ error: 'El residente ya posee un estado temporal abierto', code: 'TEMPORARY_STATE_CONFLICT' });
            sendP1Error(res, error, 'Error al registrar transición');
        }
    });
}

module.exports = {
    LA1_MIGRATION,
    LA1_CARE_PROFILE_ENUMS,
    LA1_DOCUMENT_CATEGORIES,
    validateCareProfilePayload,
    validateContactMetadata,
    validateDocumentMetadata,
    registerLA1Routes,
};
