'use strict';

const LA2_EVOLUTION_TYPES = Object.freeze(['evaluacion', 'seguimiento', 'observacion', 'cambio_clinico']);
const LA2_ADMIN_RESULTS = Object.freeze(['administrada', 'omitida', 'rechazada', 'no_disponible']);
const LA2_MEDICATION_FIELDS = Object.freeze([
    'nombre', 'dosis', 'frecuencia', 'hora_inicio', 'hora_fin', 'horarios_custom', 'instrucciones',
    'via', 'indicacion', 'prescriptor', 'vigente_desde', 'vigente_hasta', 'horarios_programados', 'activo',
]);

const LA2_MIGRATION = Object.freeze({
    version: 'la_002_longitudinal_medication',
    sql: `
ALTER TABLE medicamentos_b2b
    ADD COLUMN IF NOT EXISTS via VARCHAR(80) NULL,
    ADD COLUMN IF NOT EXISTS indicacion TEXT NULL,
    ADD COLUMN IF NOT EXISTS prescriptor VARCHAR(240) NULL,
    ADD COLUMN IF NOT EXISTS vigente_desde TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS vigente_hasta TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS horarios_programados JSONB NULL,
    ADD COLUMN IF NOT EXISTS esquema_version BIGINT NOT NULL DEFAULT 1;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='medicamentos_b2b_esquema_version_check') THEN
        ALTER TABLE medicamentos_b2b ADD CONSTRAINT medicamentos_b2b_esquema_version_check CHECK (esquema_version > 0);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='medicamentos_b2b_vigencia_check') THEN
        ALTER TABLE medicamentos_b2b ADD CONSTRAINT medicamentos_b2b_vigencia_check
            CHECK (vigente_hasta IS NULL OR vigente_desde IS NULL OR vigente_hasta >= vigente_desde);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='medicamentos_b2b_horarios_programados_check') THEN
        ALTER TABLE medicamentos_b2b ADD CONSTRAINT medicamentos_b2b_horarios_programados_check
            CHECK (horarios_programados IS NULL OR jsonb_typeof(horarios_programados)='array');
    END IF;
END;
$$;

CREATE UNIQUE INDEX IF NOT EXISTS medicamentos_b2b_tenant_id_uq
    ON medicamentos_b2b (institucion_id,id);

CREATE TABLE IF NOT EXISTS evoluciones_b2b (
    id BIGSERIAL PRIMARY KEY,
    institucion_id INTEGER NOT NULL,
    paciente_id INTEGER NOT NULL,
    tipo VARCHAR(30) NOT NULL CHECK (tipo IN ('evaluacion','seguimiento','observacion','cambio_clinico')),
    ocurrido_at TIMESTAMPTZ NOT NULL,
    titulo VARCHAR(200) NULL,
    contenido TEXT NOT NULL CHECK (length(btrim(contenido)) BETWEEN 3 AND 8000),
    creado_por INTEGER NULL,
    operador_b2b_id BIGINT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    deleted_at TIMESTAMPTZ NULL,
    deleted_by INTEGER NULL,
    deletion_reason TEXT NULL,
    CONSTRAINT evoluciones_b2b_patient_fk FOREIGN KEY (institucion_id,paciente_id)
        REFERENCES pacientes_b2b(institucion_id,id) ON DELETE CASCADE,
    CONSTRAINT evoluciones_b2b_creator_fk FOREIGN KEY (institucion_id,creado_por)
        REFERENCES usuarios_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT evoluciones_b2b_operator_fk FOREIGN KEY (institucion_id,operador_b2b_id)
        REFERENCES operadores_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT evoluciones_b2b_deleted_by_fk FOREIGN KEY (institucion_id,deleted_by)
        REFERENCES usuarios_b2b(institucion_id,id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS evoluciones_b2b_patient_date_idx
    ON evoluciones_b2b (institucion_id,paciente_id,ocurrido_at DESC,id DESC) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS historial_esquemas_medicacion_b2b (
    id BIGSERIAL PRIMARY KEY,
    institucion_id INTEGER NOT NULL,
    paciente_id INTEGER NOT NULL,
    medicamento_id INTEGER NOT NULL,
    esquema_version BIGINT NOT NULL CHECK (esquema_version > 0),
    snapshot JSONB NOT NULL CHECK (jsonb_typeof(snapshot)='object'),
    vigente_desde TIMESTAMPTZ NULL,
    vigente_hasta TIMESTAMPTZ NULL,
    motivo TEXT NULL,
    actor_usuario_id INTEGER NULL,
    operador_b2b_id BIGINT NULL,
    registrado_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT historial_esquemas_medication_uq UNIQUE (institucion_id,medicamento_id,esquema_version),
    CONSTRAINT historial_esquemas_patient_fk FOREIGN KEY (institucion_id,paciente_id)
        REFERENCES pacientes_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT historial_esquemas_medication_fk FOREIGN KEY (institucion_id,medicamento_id)
        REFERENCES medicamentos_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT historial_esquemas_actor_fk FOREIGN KEY (institucion_id,actor_usuario_id)
        REFERENCES usuarios_b2b(institucion_id,id) ON DELETE RESTRICT,
    CONSTRAINT historial_esquemas_operator_fk FOREIGN KEY (institucion_id,operador_b2b_id)
        REFERENCES operadores_b2b(institucion_id,id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS historial_esquemas_med_patient_idx
    ON historial_esquemas_medicacion_b2b (institucion_id,paciente_id,registrado_at DESC,id DESC);

CREATE OR REPLACE FUNCTION prevent_historial_esquemas_medicacion_b2b_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'historial_esquemas_medicacion_b2b es append-only' USING ERRCODE='55000';
END;
$$;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname='historial_esquemas_medicacion_b2b_append_only'
        AND tgrelid='historial_esquemas_medicacion_b2b'::regclass) THEN
        CREATE TRIGGER historial_esquemas_medicacion_b2b_append_only
        BEFORE UPDATE OR DELETE ON historial_esquemas_medicacion_b2b
        FOR EACH ROW EXECUTE FUNCTION prevent_historial_esquemas_medicacion_b2b_mutation();
    END IF;
END;
$$;

ALTER TABLE historial_medicamentos_b2b
    ADD COLUMN IF NOT EXISTS resultado VARCHAR(30) NOT NULL DEFAULT 'administrada',
    ADD COLUMN IF NOT EXISTS motivo_omision TEXT NULL,
    ADD COLUMN IF NOT EXISTS programada_para TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS via VARCHAR(80) NULL,
    ADD COLUMN IF NOT EXISTS esquema_version BIGINT NULL,
    ADD COLUMN IF NOT EXISTS operador_b2b_id BIGINT NULL;
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='historial_medicamentos_b2b_resultado_check') THEN
        ALTER TABLE historial_medicamentos_b2b ADD CONSTRAINT historial_medicamentos_b2b_resultado_check
            CHECK (resultado IN ('administrada','omitida','rechazada','no_disponible'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='historial_medicamentos_b2b_omision_check') THEN
        ALTER TABLE historial_medicamentos_b2b ADD CONSTRAINT historial_medicamentos_b2b_omision_check
            CHECK (resultado='administrada' OR length(btrim(COALESCE(motivo_omision,''))) >= 3);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='historial_medicamentos_b2b_operator_fk') THEN
        ALTER TABLE historial_medicamentos_b2b ADD CONSTRAINT historial_medicamentos_b2b_operator_fk
            FOREIGN KEY (institucion_id,operador_b2b_id) REFERENCES operadores_b2b(institucion_id,id) ON DELETE RESTRICT;
    END IF;
END;
$$;
CREATE INDEX IF NOT EXISTS historial_medicamentos_b2b_patient_result_idx
    ON historial_medicamentos_b2b (institucion_id,paciente_id,resultado,fecha DESC,id DESC);
`,
});

function httpError(status, code, message) {
    return Object.assign(new Error(message), { status, code });
}

function textValue(value, field, { required = false, max = 8000 } = {}) {
    if (value === undefined) return undefined;
    if (value === null) return null;
    const text = String(value).trim();
    if (!text) {
        if (required) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} es obligatorio`);
        return null;
    }
    if (text.length > max) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} supera el largo permitido`);
    return text;
}

function isoDate(value, field, { required = false } = {}) {
    if (value === undefined) return undefined;
    if (value === null || value === '') {
        if (required) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} es obligatorio`);
        return null;
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) throw httpError(400, `INVALID_${field.toUpperCase()}`, `${field} inválido`);
    return parsed.toISOString();
}

function normalizeSchedule(value) {
    if (value === undefined) return undefined;
    if (value === null || value === '') return null;
    if (!Array.isArray(value) || value.length > 24) throw httpError(400, 'INVALID_HORARIOS_PROGRAMADOS', 'horarios_programados debe ser un arreglo');
    const normalized = value.map(item => String(item).trim());
    if (normalized.some(item => !/^([01]\d|2[0-3]):[0-5]\d$/.test(item))) {
        throw httpError(400, 'INVALID_HORARIOS_PROGRAMADOS', 'Cada horario debe usar HH:MM');
    }
    return [...new Set(normalized)].sort();
}

function medicationSchemeSnapshot(row) {
    return Object.fromEntries(LA2_MEDICATION_FIELDS.map(field => [field, row[field] ?? null]));
}

function medicationSchemeInput(body, current = {}) {
    const next = { ...current };
    for (const field of ['via', 'indicacion', 'prescriptor']) {
        if (Object.prototype.hasOwnProperty.call(body, field)) next[field] = textValue(body[field], field, { max: field === 'indicacion' ? 4000 : 240 });
    }
    for (const field of ['vigente_desde', 'vigente_hasta']) {
        if (Object.prototype.hasOwnProperty.call(body, field)) next[field] = isoDate(body[field], field);
    }
    if (Object.prototype.hasOwnProperty.call(body, 'horarios_programados')) next.horarios_programados = normalizeSchedule(body.horarios_programados);
    if (next.vigente_desde && next.vigente_hasta && new Date(next.vigente_hasta) < new Date(next.vigente_desde)) {
        throw httpError(400, 'INVALID_MEDICATION_VALIDITY', 'La vigencia final no puede ser anterior a la inicial');
    }
    return next;
}

function schemeChanged(before, after) {
    return LA2_MEDICATION_FIELDS.some(field => JSON.stringify(before[field] ?? null) !== JSON.stringify(after[field] ?? null));
}

async function insertSchemeSnapshot(client, medication, actor, reason) {
    return (await client.query(
        `INSERT INTO historial_esquemas_medicacion_b2b
         (institucion_id,paciente_id,medicamento_id,esquema_version,snapshot,vigente_desde,vigente_hasta,motivo,actor_usuario_id,operador_b2b_id)
         VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7,$8,$9,$10)
         ON CONFLICT (institucion_id,medicamento_id,esquema_version) DO NOTHING RETURNING *`,
        [medication.institucion_id, medication.paciente_id, medication.id, medication.esquema_version,
            JSON.stringify(medicationSchemeSnapshot(medication)), medication.vigente_desde || null,
            medication.vigente_hasta || null, reason || null, actor.principal_usuario_id || actor.id,
            actor.operador_b2b_id || null]
    )).rows[0] || null;
}

function encodeCursor(item) {
    return Buffer.from(JSON.stringify([item.ocurrido_at, item.tipo, item.id])).toString('base64url');
}

function decodeCursor(raw) {
    if (!raw) return null;
    try {
        const parsed = JSON.parse(Buffer.from(String(raw), 'base64url').toString('utf8'));
        if (!Array.isArray(parsed) || parsed.length !== 3 || Number.isNaN(new Date(parsed[0]).getTime())) throw new Error();
        return parsed;
    } catch { throw httpError(400, 'INVALID_CURSOR', 'Cursor inválido'); }
}

function timelineSort(a, b) {
    return new Date(b.ocurrido_at) - new Date(a.ocurrido_at)
        || String(a.tipo).localeCompare(String(b.tipo))
        || String(b.id).localeCompare(String(a.id));
}

function registerLA2Routes(app, dependencies) {
    const {
        pool, authB2BMiddleware, requireB2BRole, checkB2BPacienteAccess, checkB2BCanDo,
        checkB2BFamiliarCanSee, loadAndAuthorizeB2BPatientResource, withB2BTransaction,
        appendB2BAudit, beginIdempotentOperation, completeIdempotentOperation,
        assertB2BVersion, getExpectedB2BVersion, guardB2BPatientMutation,
        softDeleteB2BPatientResource, sendP1Error,
    } = dependencies;
    const mutableRoles = requireB2BRole('admin_institucion', 'medico', 'cuidador_staff');
    const assertAccess = async (req, patientId, queryable = pool) => {
        if (!(await checkB2BPacienteAccess(req.b2bUser, patientId, queryable))) throw httpError(404, 'PATIENT_NOT_FOUND', 'Paciente no encontrado');
    };
    const assertAction = (req, action) => {
        if (!checkB2BCanDo(req.b2bUser, action)) throw httpError(403, 'FORBIDDEN', 'No tenés permisos para esta acción');
    };

    app.get('/api/b2b/pacientes/:id/evoluciones', authB2BMiddleware, async (req, res) => {
        try {
            if (req.b2bUser.rol === 'familiar' && !checkB2BFamiliarCanSee(req.b2bUser, 'evoluciones')) throw httpError(403, 'FORBIDDEN', 'Acceso restringido por la institución');
            await assertAccess(req, req.params.id);
            const result = await pool.query(
                `SELECT e.*,COALESCE(o.nombre,u.nombre,'No disponible') AS actor_nombre
                 FROM evoluciones_b2b e
                 LEFT JOIN usuarios_b2b u ON u.id=e.creado_por AND u.institucion_id=e.institucion_id
                 LEFT JOIN operadores_b2b o ON o.id=e.operador_b2b_id AND o.institucion_id=e.institucion_id
                 WHERE e.institucion_id=$1 AND e.paciente_id=$2 AND e.deleted_at IS NULL
                 ORDER BY e.ocurrido_at DESC,e.id DESC LIMIT 250`,
                [req.b2bUser.institucion_id, req.params.id]
            );
            res.json(result.rows);
        } catch (error) { sendP1Error(res, error, 'Error al obtener evoluciones'); }
    });

    app.post('/api/b2b/pacientes/:id/evoluciones', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'registrar_evolucion');
            const type = LA2_EVOLUTION_TYPES.includes(req.body.tipo) ? req.body.tipo : null;
            if (!type) throw httpError(400, 'INVALID_EVOLUTION_TYPE', 'Tipo de evolución inválido');
            const title = textValue(req.body.titulo, 'titulo', { max: 200 });
            const content = textValue(req.body.contenido, 'contenido', { required: true, max: 8000 });
            const occurredAt = isoDate(req.body.ocurrido_at || new Date().toISOString(), 'ocurrido_at', { required: true });
            const outcome = await withB2BTransaction(pool, async client => {
                await assertAccess(req, req.params.id, client);
                await guardB2BPatientMutation(client, req, req.params.id, 'new');
                const idem = await beginIdempotentOperation(client, { req, actor: req.b2bUser, operation: 'la2_evolucion_crear', patientId: Number(req.params.id) });
                if (idem.replay) {
                    const prior = await client.query('SELECT * FROM evoluciones_b2b WHERE id=$1 AND institucion_id=$2', [idem.previous.resultado_id, req.b2bUser.institucion_id]);
                    if (!prior.rows[0]) throw new Error('Resultado idempotente no disponible');
                    return { row: prior.rows[0], replayed: true };
                }
                const inserted = (await client.query(
                    `INSERT INTO evoluciones_b2b (institucion_id,paciente_id,tipo,ocurrido_at,titulo,contenido,creado_por,operador_b2b_id)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
                    [req.b2bUser.institucion_id, req.params.id, type, occurredAt, title, content,
                        req.b2bUser.principal_usuario_id || req.b2bUser.id, req.b2bUser.operador_b2b_id || null]
                )).rows[0];
                await appendB2BAudit(client, { institutionId: req.b2bUser.institucion_id, patientId: Number(req.params.id), actor: req.b2bUser,
                    resourceType: 'evolucion', resourceId: inserted.id, action: 'CREATE', version: inserted.version, after: inserted });
                await completeIdempotentOperation(client, idem, { resultType: 'evolucion', resultId: inserted.id, httpStatus: 201, safeResult: { id: inserted.id } });
                return { row: inserted, replayed: false };
            });
            if (outcome.replayed) res.setHeader('Idempotent-Replayed', 'true');
            res.status(201).json(outcome.row);
        } catch (error) { sendP1Error(res, error, 'Error al registrar evolución'); }
    });

    app.patch('/api/b2b/evoluciones/:id', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'registrar_evolucion');
            const changed = await withB2BTransaction(pool, async client => {
                const access = await loadAndAuthorizeB2BPatientResource(req.b2bUser, 'evoluciones_b2b', req.params.id, client, { forUpdate: true });
                if (!access.found || !access.allowed) throw httpError(404, 'RESOURCE_NOT_FOUND', 'Evolución no encontrada');
                await guardB2BPatientMutation(client, req, access.row.paciente_id, 'correction');
                assertB2BVersion(access.row, getExpectedB2BVersion(req));
                const type = req.body.tipo === undefined ? access.row.tipo : req.body.tipo;
                if (!LA2_EVOLUTION_TYPES.includes(type)) throw httpError(400, 'INVALID_EVOLUTION_TYPE', 'Tipo de evolución inválido');
                const title = textValue(req.body.titulo === undefined ? access.row.titulo : req.body.titulo, 'titulo', { max: 200 });
                const content = textValue(req.body.contenido === undefined ? access.row.contenido : req.body.contenido, 'contenido', { required: true, max: 8000 });
                const occurredAt = isoDate(req.body.ocurrido_at === undefined ? access.row.ocurrido_at : req.body.ocurrido_at, 'ocurrido_at', { required: true });
                const updated = (await client.query(
                    `UPDATE evoluciones_b2b SET tipo=$1,titulo=$2,contenido=$3,ocurrido_at=$4,updated_at=clock_timestamp(),version=version+1
                     WHERE id=$5 AND institucion_id=$6 RETURNING *`,
                    [type, title, content, occurredAt, access.row.id, req.b2bUser.institucion_id]
                )).rows[0];
                await appendB2BAudit(client, { institutionId: req.b2bUser.institucion_id, patientId: access.row.paciente_id, actor: req.b2bUser,
                    resourceType: 'evolucion', resourceId: updated.id, action: 'CORRECTION', version: updated.version, before: access.row, after: updated });
                return updated;
            });
            res.json(changed);
        } catch (error) { sendP1Error(res, error, 'Error al actualizar evolución'); }
    });

    app.delete('/api/b2b/evoluciones/:id', authB2BMiddleware, mutableRoles, async (req, res) => {
        try {
            assertAction(req, 'registrar_evolucion');
            const outcome = await softDeleteB2BPatientResource(req, 'evoluciones_b2b', 'evolucion', 'Evolución');
            res.json({ success: true, already_deleted: outcome.alreadyDeleted, version: outcome.version });
        } catch (error) { sendP1Error(res, error, 'Error al archivar evolución'); }
    });

    app.get('/api/b2b/medicamentos/:id/esquemas', authB2BMiddleware, async (req, res) => {
        try {
            const access = await loadAndAuthorizeB2BPatientResource(req.b2bUser, 'medicamentos_b2b', req.params.id, pool);
            if (!access.found || !access.allowed) throw httpError(404, 'RESOURCE_NOT_FOUND', 'Medicamento no encontrado');
            if (req.b2bUser.rol === 'familiar' && !checkB2BFamiliarCanSee(req.b2bUser, 'medicamentos')) throw httpError(403, 'FORBIDDEN', 'Acceso restringido por la institución');
            const history = await pool.query(
                `SELECT h.*,COALESCE(o.nombre,u.nombre,'No disponible') AS actor_nombre
                 FROM historial_esquemas_medicacion_b2b h
                 LEFT JOIN usuarios_b2b u ON u.id=h.actor_usuario_id AND u.institucion_id=h.institucion_id
                 LEFT JOIN operadores_b2b o ON o.id=h.operador_b2b_id AND o.institucion_id=h.institucion_id
                 WHERE h.institucion_id=$1 AND h.medicamento_id=$2 ORDER BY h.esquema_version DESC,h.id DESC`,
                [req.b2bUser.institucion_id, req.params.id]
            );
            res.json({ vigente: access.row, historial: history.rows });
        } catch (error) { sendP1Error(res, error, 'Error al obtener historial de esquema'); }
    });

    app.get('/api/b2b/pacientes/:id/timeline', authB2BMiddleware, async (req, res) => {
        try {
            await assertAccess(req, req.params.id);
            const iid = req.b2bUser.institucion_id;
            const pid = req.params.id;
            const family = req.b2bUser.rol === 'familiar';
            const can = section => !family || checkB2BFamiliarCanSee(req.b2bUser, section);
            const queries = [];
            const add = (enabled, source, sql) => { if (enabled) queries.push(pool.query(sql, [iid, pid]).then(result => ({ source, rows: result.rows }))); };
            add(can('evoluciones'), 'evolucion', `SELECT e.id,e.ocurrido_at,e.tipo,e.titulo,e.contenido,COALESCE(o.nombre,u.nombre,'No disponible') actor_nombre FROM evoluciones_b2b e LEFT JOIN usuarios_b2b u ON u.id=e.creado_por AND u.institucion_id=e.institucion_id LEFT JOIN operadores_b2b o ON o.id=e.operador_b2b_id AND o.institucion_id=e.institucion_id WHERE e.institucion_id=$1 AND e.paciente_id=$2 AND e.deleted_at IS NULL ORDER BY e.ocurrido_at DESC LIMIT 250`);
            add(can('sintomas'), 'sintoma', `SELECT id,fecha AT TIME ZONE 'America/Argentina/Buenos_Aires' ocurrido_at,'sintoma' tipo,'Síntoma' titulo,descripcion contenido,COALESCE(registrador_nombre,'No disponible') actor_nombre FROM sintomas_b2b WHERE institucion_id=$1 AND paciente_id=$2 AND deleted_at IS NULL ORDER BY fecha DESC LIMIT 250`);
            add(can('signos'), 'signo', `SELECT id,fecha AT TIME ZONE 'America/Argentina/Buenos_Aires' ocurrido_at,'signo_vital' tipo,tipo titulo,concat_ws(' ',valor,unidad,notas) contenido,COALESCE(registrador_nombre,'No disponible') actor_nombre FROM signos_vitales_b2b WHERE institucion_id=$1 AND paciente_id=$2 AND deleted_at IS NULL ORDER BY fecha DESC LIMIT 250`);
            add(can('notas'), 'nota', `SELECT id,created_at AT TIME ZONE 'America/Argentina/Buenos_Aires' ocurrido_at,'nota' tipo,titulo,contenido,COALESCE(autor_nombre,'No disponible') actor_nombre FROM notas_b2b WHERE institucion_id=$1 AND paciente_id=$2 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 250`);
            add(can('incidentes'), 'incidente', `SELECT i.id,i.ocurrido_at,'incidente' tipo,concat('Incidente: ',replace(i.categoria,'_',' ')) titulo,concat_ws(' · ',i.descripcion,i.accion_tomada) contenido,COALESCE(o.nombre,u.nombre,'No disponible') actor_nombre FROM incidentes_b2b i LEFT JOIN usuarios_b2b u ON u.id=i.creado_por AND u.institucion_id=i.institucion_id LEFT JOIN operadores_b2b o ON o.id=i.operador_b2b_id AND o.institucion_id=i.institucion_id WHERE i.institucion_id=$1 AND i.paciente_id=$2 AND i.deleted_at IS NULL ORDER BY i.ocurrido_at DESC LIMIT 250`);
            add(can('citas'), 'cita', `SELECT id,fecha AT TIME ZONE 'America/Argentina/Buenos_Aires' ocurrido_at,'cita' tipo,titulo,concat_ws(' · ',descripcion,medico,estado) contenido,'No disponible' actor_nombre FROM citas_b2b WHERE institucion_id=$1 AND paciente_id=$2 AND deleted_at IS NULL ORDER BY fecha DESC LIMIT 250`);
            add(can('medicamentos'), 'administracion', `SELECT id,fecha AT TIME ZONE 'America/Argentina/Buenos_Aires' ocurrido_at,concat('medicacion_',resultado) tipo,medicamento_nombre titulo,concat_ws(' · ',dosis,motivo_omision,notas) contenido,COALESCE(administrador_nombre,'No disponible') actor_nombre FROM historial_medicamentos_b2b WHERE institucion_id=$1 AND paciente_id=$2 ORDER BY fecha DESC LIMIT 250`);
            add(can('medicamentos'), 'esquema', `SELECT h.id,h.registrado_at ocurrido_at,'cambio_esquema' tipo,COALESCE(h.snapshot->>'nombre','Cambio de esquema') titulo,COALESCE(h.motivo,'Esquema registrado') contenido,COALESCE(o.nombre,u.nombre,'No disponible') actor_nombre FROM historial_esquemas_medicacion_b2b h LEFT JOIN usuarios_b2b u ON u.id=h.actor_usuario_id AND u.institucion_id=h.institucion_id LEFT JOIN operadores_b2b o ON o.id=h.operador_b2b_id AND o.institucion_id=h.institucion_id WHERE h.institucion_id=$1 AND h.paciente_id=$2 ORDER BY h.registrado_at DESC LIMIT 250`);
            add(can('estados'), 'estado', `SELECT e.id,e.iniciado_at ocurrido_at,'estado_temporal' tipo,replace(e.tipo,'_',' ') titulo,COALESCE(e.motivo,'Cambio de estado temporal') contenido,COALESCE(o.nombre,u.nombre,'No disponible') actor_nombre FROM estados_residente_b2b e LEFT JOIN usuarios_b2b u ON u.id=e.iniciado_por AND u.institucion_id=e.institucion_id LEFT JOIN operadores_b2b o ON o.id=e.iniciado_operador_b2b_id AND o.institucion_id=e.institucion_id WHERE e.institucion_id=$1 AND e.paciente_id=$2 ORDER BY e.iniciado_at DESC LIMIT 250`);
            add(can('estados'), 'estado_regreso', `SELECT e.id,e.finalizado_at ocurrido_at,'regreso' tipo,'Regreso' titulo,concat_ws(' · ',concat('Regreso de ',replace(e.tipo,'_',' ')),e.motivo) contenido,COALESCE(o.nombre,u.nombre,'No disponible') actor_nombre FROM estados_residente_b2b e LEFT JOIN usuarios_b2b u ON u.id=e.finalizado_por AND u.institucion_id=e.institucion_id LEFT JOIN operadores_b2b o ON o.id=e.finalizado_operador_b2b_id AND o.institucion_id=e.institucion_id WHERE e.institucion_id=$1 AND e.paciente_id=$2 AND e.finalizado_at IS NOT NULL ORDER BY e.finalizado_at DESC LIMIT 250`);
            add(can('documentos'), 'documento', `SELECT id,created_at AT TIME ZONE 'America/Argentina/Buenos_Aires' ocurrido_at,'documento' tipo,nombre_archivo titulo,COALESCE(descripcion,categoria,'Documento incorporado') contenido,COALESCE(subido_nombre,'No disponible') actor_nombre FROM documentos_b2b WHERE institucion_id=$1 AND paciente_id=$2 AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 250`);
            add(can('tareas'), 'tarea', `SELECT id,fecha AT TIME ZONE 'America/Argentina/Buenos_Aires' ocurrido_at,'tarea_completada' tipo,tarea_titulo titulo,COALESCE(notas,'Tarea completada') contenido,COALESCE(completador_nombre,'No disponible') actor_nombre FROM historial_tareas_b2b WHERE institucion_id=$1 AND paciente_id=$2 ORDER BY fecha DESC LIMIT 250`);
            const groups = await Promise.all(queries);
            let items = groups.flatMap(group => group.rows.map(row => ({
                id: `${group.source}:${row.id}`, source: group.source, source_id: row.id,
                tipo: row.tipo, ocurrido_at: row.ocurrido_at, titulo: row.titulo || 'Evento',
                detalle: row.contenido || null, actor_nombre: row.actor_nombre || 'No disponible',
            }))).filter(item => item.ocurrido_at).sort(timelineSort);
            const allowedTypes = String(req.query.tipos || '').split(',').map(v => v.trim()).filter(Boolean);
            if (allowedTypes.length) items = items.filter(item => allowedTypes.includes(item.tipo));
            const cursor = decodeCursor(req.query.cursor);
            if (cursor) {
                const marker = { ocurrido_at: cursor[0], tipo: cursor[1], id: cursor[2] };
                items = items.filter(item => timelineSort(item, marker) > 0);
            }
            const limit = Math.min(50, Math.max(1, Number(req.query.limit) || 25));
            const page = items.slice(0, limit);
            res.json({ items: page, next_cursor: items.length > limit && page.length ? encodeCursor(page[page.length - 1]) : null });
        } catch (error) { sendP1Error(res, error, 'Error al obtener línea de tiempo'); }
    });
}

module.exports = {
    LA2_MIGRATION,
    LA2_EVOLUTION_TYPES,
    LA2_ADMIN_RESULTS,
    medicationSchemeInput,
    medicationSchemeSnapshot,
    schemeChanged,
    insertSchemeSnapshot,
    registerLA2Routes,
};
