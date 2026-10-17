'use strict';

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { pipeline } = require('stream/promises');

const EXPORT_SCHEMA = 'cuidadiario-institutional-export/v1';
const EXPORTER_VERSION = 'p1-d2/1.0.0';
const DEFAULT_MAX_EXPORT_BYTES = 512 * 1024 * 1024;
const DEFAULT_MAX_ROWS = 250000;

const DATASETS = Object.freeze([
    {
        key: 'usuarios', file: 'data/usuarios.jsonl', table: 'usuarios_b2b',
        sql: `SELECT id,institucion_id,nombre,email,rol,turno,activo,email_verified,notif_prefs,
                     notif_last_seen_at,created_at,version
              FROM usuarios_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'pacientes', file: 'data/pacientes.jsonl', table: 'pacientes_b2b',
        sql: `SELECT id,institucion_id,nombre,apellido,fecha_nacimiento,dni,foto_url,habitacion,
                     obra_social,num_afiliado,contacto_familiar_nombre,contacto_familiar_tel,
                     diagnostico,alergias,medico_cabecera,antecedentes,notas_ingreso,
                     fecha_ingreso,fecha_egreso,motivo_egreso,activo,created_at,version
              FROM pacientes_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'asignaciones', file: 'data/asignaciones.jsonl', table: 'asignaciones_b2b',
        sql: `SELECT id,institucion_id,cuidador_id,paciente_id,activa,created_at,version
              FROM asignaciones_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'medicamentos', file: 'data/medicamentos.jsonl', table: 'medicamentos_b2b',
        sql: `SELECT id,institucion_id,paciente_id,catalogo_id,nombre,dosis,frecuencia,hora_inicio,
                     hora_fin,horarios_custom,instrucciones,stock,activo,created_at,version
              FROM medicamentos_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'historial_medicamentos', file: 'data/historial_medicamentos.jsonl', table: 'historial_medicamentos_b2b',
        sql: `SELECT id,institucion_id,paciente_id,medicamento_id,medicamento_nombre,dosis,
                     administrado_por,administrador_nombre,notas,fecha,cantidad
              FROM historial_medicamentos_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'catalogo_medicamentos', file: 'data/catalogo_medicamentos.jsonl', table: 'catalogo_medicamentos_b2b',
        sql: `SELECT id,institucion_id,paciente_id,nombre,principio_activo,presentacion,unidad,categoria,
                     stock_actual,stock_minimo,activo,created_at,updated_at,version
              FROM catalogo_medicamentos_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'historial_restock', file: 'data/historial_restock.jsonl', table: 'historial_restock_b2b',
        sql: `SELECT id,institucion_id,catalogo_id,paciente_id,nombre_item,stock_anterior,
                     cantidad_repuesta,stock_nuevo,notas,registrado_por,registrado_nombre,created_at
              FROM historial_restock_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'citas', file: 'data/citas.jsonl', table: 'citas_b2b',
        sql: `SELECT id,institucion_id,paciente_id,titulo,descripcion,fecha,medico,especialidad,lugar,
                     estado,created_by,created_at,updated_at,version,deleted_at,deleted_by,deletion_reason
              FROM citas_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'historial_citas', file: 'data/historial_citas.jsonl', table: 'historial_citas_b2b',
        sql: `SELECT id,institucion_id,cita_id,paciente_id,titulo,descripcion,fecha,medico,
                     especialidad,lugar,estado,archivado_en,archivado_por
              FROM historial_citas_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'tareas', file: 'data/tareas.jsonl', table: 'tareas_b2b',
        sql: `SELECT id,institucion_id,paciente_id,titulo,descripcion,categoria,frecuencia,hora,
                     activa,created_by,created_at,version
              FROM tareas_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'historial_tareas', file: 'data/historial_tareas.jsonl', table: 'historial_tareas_b2b',
        sql: `SELECT id,institucion_id,paciente_id,tarea_id,tarea_titulo,completado_por,
                     completador_nombre,notas,fecha
              FROM historial_tareas_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'sintomas', file: 'data/sintomas.jsonl', table: 'sintomas_b2b',
        sql: `SELECT id,institucion_id,paciente_id,descripcion,intensidad,registrado_por,
                     registrador_nombre,fecha,version,deleted_at,deleted_by,deletion_reason
              FROM sintomas_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'signos_vitales', file: 'data/signos_vitales.jsonl', table: 'signos_vitales_b2b',
        sql: `SELECT id,institucion_id,paciente_id,tipo,valor,unidad,notas,registrado_por,
                     registrador_nombre,fecha,version,deleted_at,deleted_by,deletion_reason
              FROM signos_vitales_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'contactos', file: 'data/contactos.jsonl', table: 'contactos_b2b',
        sql: `SELECT id,institucion_id,paciente_id,nombre,relacion,telefono,email,es_principal,
                     created_at,version,deleted_at,deleted_by,deletion_reason
              FROM contactos_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'notas', file: 'data/notas.jsonl', table: 'notas_b2b',
        sql: `SELECT id,institucion_id,paciente_id,titulo,contenido,urgente,autor_id,autor_nombre,
                     created_at,version,deleted_at,deleted_by,deletion_reason
              FROM notas_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'documentos', file: 'documents/index.jsonl', table: 'documentos_b2b',
        sql: `SELECT id,institucion_id,paciente_id,nombre_archivo,tipo_mime,tamanio_bytes,
                     subido_por,subido_nombre,created_at,version,deleted_at,deleted_by,deletion_reason
              FROM documentos_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
    {
        key: 'operadores', file: 'data/operadores.jsonl', table: 'operadores_b2b',
        sql: `SELECT id,institucion_id,nombre,rol,activo,created_by_usuario_id,created_at,updated_at,version
              FROM operadores_b2b WHERE institucion_id=$1 ORDER BY id`,
    },
]);

const AUDIT_QUERY = `SELECT id,institucion_id,paciente_id,actor_usuario_id,actor_tipo,
                            operador_usuario_id,operador_b2b_id,recurso_tipo,recurso_id,accion,
                            recurso_version,ocurrido_at,motivo,before_data,after_data,capture_mode,
                            metadata,request_id
                     FROM auditoria_eventos_b2b WHERE institucion_id=$1
                     ORDER BY ocurrido_at,id`;

function exportError(code, message, status = 409) {
    const error = new Error(message || code);
    error.code = code;
    error.status = status;
    return error;
}

function sha256(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

function parsePositiveId(value, label) {
    const text = String(value == null ? '' : value);
    if (!/^[1-9]\d*$/.test(text)) throw exportError('P1D2_INVALID_ID', `${label} inválido`, 400);
    const parsed = Number(text);
    if (!Number.isSafeInteger(parsed)) throw exportError('P1D2_INVALID_ID', `${label} inválido`, 400);
    return parsed;
}

function slugify(value, fallback) {
    const normalized = String(value || '').normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
        .toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 48);
    return normalized || fallback;
}

function compactUtc(date) {
    return date.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function assertZipPath(name) {
    if (typeof name !== 'string' || !name || name.length > 240 || name.includes('\\') || name.includes('\0')
        || name.startsWith('/') || /^[A-Za-z]:/.test(name)) {
        throw exportError('P1D2_UNSAFE_ZIP_PATH', 'Ruta ZIP insegura');
    }
    const segments = name.split('/');
    if (segments.some(segment => !segment || segment === '.' || segment === '..')) {
        throw exportError('P1D2_UNSAFE_ZIP_PATH', 'Ruta ZIP insegura');
    }
    return name;
}

const CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n += 1) {
        let c = n;
        for (let k = 0; k < 8; k += 1) c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
        table[n] = c >>> 0;
    }
    return table;
})();

function crc32(buffer) {
    let crc = 0xffffffff;
    for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
}

function dosDateTime(date) {
    const year = Math.max(1980, date.getUTCFullYear());
    const time = (date.getUTCHours() << 11) | (date.getUTCMinutes() << 5) | Math.floor(date.getUTCSeconds() / 2);
    const day = ((year - 1980) << 9) | ((date.getUTCMonth() + 1) << 5) | date.getUTCDate();
    return { time, date: day };
}

class ZipFileWriter {
    constructor(filePath, modifiedAt, maxBytes = DEFAULT_MAX_EXPORT_BYTES) {
        this.filePath = filePath;
        this.modifiedAt = modifiedAt;
        this.maxBytes = maxBytes;
        this.handle = null;
        this.offset = 0;
        this.entries = [];
        this.names = new Set();
    }

    async open() {
        this.handle = await fs.promises.open(this.filePath, 'wx', 0o600);
    }

    async write(buffer) {
        if (!this.handle) throw exportError('P1D2_ZIP_NOT_OPEN', 'ZIP no inicializado', 500);
        if (this.offset + buffer.length > this.maxBytes) {
            throw exportError('P1D2_EXPORT_TOO_LARGE', 'La exportación supera el límite configurado', 413);
        }
        await this.handle.write(buffer, 0, buffer.length, this.offset);
        this.offset += buffer.length;
    }

    async add(name, data) {
        const safeName = assertZipPath(name);
        if (this.names.has(safeName)) throw exportError('P1D2_ZIP_NAME_COLLISION', 'Nombre ZIP duplicado');
        this.names.add(safeName);
        const body = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
        if (body.length > 0xffffffff) throw exportError('P1D2_EXPORT_TOO_LARGE', 'Entrada ZIP demasiado grande', 413);
        const nameBytes = Buffer.from(safeName, 'utf8');
        const crc = crc32(body);
        const stamp = dosDateTime(this.modifiedAt);
        const localOffset = this.offset;
        const header = Buffer.alloc(30);
        header.writeUInt32LE(0x04034b50, 0);
        header.writeUInt16LE(20, 4);
        header.writeUInt16LE(0x0800, 6);
        header.writeUInt16LE(0, 8);
        header.writeUInt16LE(stamp.time, 10);
        header.writeUInt16LE(stamp.date, 12);
        header.writeUInt32LE(crc, 14);
        header.writeUInt32LE(body.length, 18);
        header.writeUInt32LE(body.length, 22);
        header.writeUInt16LE(nameBytes.length, 26);
        await this.write(header);
        await this.write(nameBytes);
        await this.write(body);
        const info = { name: safeName, bytes: body.length, sha256: sha256(body), crc32: crc, localOffset, stamp };
        this.entries.push(info);
        return info;
    }

    async close() {
        if (!this.handle) return;
        if (this.entries.length > 0xffff) throw exportError('P1D2_TOO_MANY_FILES', 'Demasiados archivos', 413);
        const centralOffset = this.offset;
        for (const entry of this.entries) {
            const nameBytes = Buffer.from(entry.name, 'utf8');
            const header = Buffer.alloc(46);
            header.writeUInt32LE(0x02014b50, 0);
            header.writeUInt16LE(20, 4);
            header.writeUInt16LE(20, 6);
            header.writeUInt16LE(0x0800, 8);
            header.writeUInt16LE(0, 10);
            header.writeUInt16LE(entry.stamp.time, 12);
            header.writeUInt16LE(entry.stamp.date, 14);
            header.writeUInt32LE(entry.crc32, 16);
            header.writeUInt32LE(entry.bytes, 20);
            header.writeUInt32LE(entry.bytes, 24);
            header.writeUInt16LE(nameBytes.length, 28);
            header.writeUInt32LE(entry.localOffset, 42);
            await this.write(header);
            await this.write(nameBytes);
        }
        const centralSize = this.offset - centralOffset;
        const end = Buffer.alloc(22);
        end.writeUInt32LE(0x06054b50, 0);
        end.writeUInt16LE(this.entries.length, 8);
        end.writeUInt16LE(this.entries.length, 10);
        end.writeUInt32LE(centralSize, 12);
        end.writeUInt32LE(centralOffset, 16);
        await this.write(end);
        await this.handle.sync();
        await this.handle.close();
        this.handle = null;
    }

    async abort() {
        if (this.handle) {
            try { await this.handle.close(); } catch {}
            this.handle = null;
        }
    }
}

function jsonLineBuffer(rows) {
    if (!rows.length) return Buffer.alloc(0);
    return Buffer.from(`${rows.map(row => JSON.stringify(row)).join('\n')}\n`, 'utf8');
}

function csvBuffer(rows, fields) {
    const quote = value => {
        if (value === null || value === undefined) return '';
        const stringValue = typeof value === 'object' ? JSON.stringify(value) : String(value);
        return /[",\r\n]/.test(stringValue) ? `"${stringValue.replace(/"/g, '""')}"` : stringValue;
    };
    const lines = [fields.join(','), ...rows.map(row => fields.map(field => quote(row[field])).join(','))];
    return Buffer.from(`\ufeff${lines.join('\r\n')}\r\n`, 'utf8');
}

function documentExtension(name) {
    const match = /\.([A-Za-z0-9]{1,10})$/.exec(String(name || '').trim());
    return match ? `.${match[1].toLowerCase()}` : '.bin';
}

function strictBase64Decode(value) {
    const normalized = String(value == null ? '' : value).replace(/\s+/g, '');
    if (!normalized || normalized.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
        throw exportError('P1D2_DOCUMENT_BASE64_INVALID', 'Documento con contenido base64 inválido');
    }
    const decoded = Buffer.from(normalized, 'base64');
    if (decoded.toString('base64').replace(/=+$/g, '') !== normalized.replace(/=+$/g, '')) {
        throw exportError('P1D2_DOCUMENT_BASE64_INVALID', 'Documento con contenido base64 inválido');
    }
    return decoded;
}

const FORBIDDEN_AUDIT_KEY = /(?:password|pass_hash|pin|token|jwt|secret|authorization|api[_-]?key|database.*url|credential|request_hash|\bclave\b|datos|base64)/i;
const SECRET_VALUE = /(?:postgres(?:ql)?:\/\/|\bBearer\s+\S+|-----BEGIN (?:RSA |EC )?PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|\bre_[A-Za-z0-9_-]{12,})/i;

function sanitizeAuditValue(value, stats) {
    if (Array.isArray(value)) return value.map(item => sanitizeAuditValue(item, stats));
    if (value && typeof value === 'object' && !(value instanceof Date)) {
        const output = {};
        for (const [key, nested] of Object.entries(value)) {
            if (FORBIDDEN_AUDIT_KEY.test(key)) {
                stats.redactedFields += 1;
                continue;
            }
            output[key] = sanitizeAuditValue(nested, stats);
        }
        return output;
    }
    if (typeof value === 'string' && SECRET_VALUE.test(value)) {
        stats.redactedValues += 1;
        return '[REDACTED]';
    }
    return value;
}

function rowIds(rows) {
    return new Set(rows.map(row => String(row.id)));
}

function requireReference(row, field, allowed, nullable, family) {
    const value = row[field];
    if (value === null || value === undefined) {
        if (nullable) return;
        throw exportError('P1D2_UNRESOLVED_TENANT_RELATION', `${family}.${field} sin relación`);
    }
    if (!allowed.has(String(value))) {
        throw exportError('P1D2_UNRESOLVED_TENANT_RELATION', `${family}.${field} fuera del tenant`);
    }
}

function validateTenantGraph(institutionId, data, auditRows) {
    for (const [family, rows] of Object.entries(data)) {
        for (const row of rows) {
            if (Number(row.institucion_id) !== institutionId) {
                throw exportError('P1D2_TENANT_MISMATCH', `${family} fuera del tenant`);
            }
        }
    }
    for (const row of auditRows) {
        if (Number(row.institucion_id) !== institutionId) throw exportError('P1D2_TENANT_MISMATCH', 'auditoría fuera del tenant');
    }

    const users = rowIds(data.usuarios);
    const patients = rowIds(data.pacientes);
    const catalog = rowIds(data.catalogo_medicamentos);
    const medicines = rowIds(data.medicamentos);
    const appointments = rowIds(data.citas);
    const tasks = rowIds(data.tareas);
    const operators = rowIds(data.operadores);

    data.asignaciones.forEach(row => {
        requireReference(row, 'cuidador_id', users, false, 'asignaciones');
        requireReference(row, 'paciente_id', patients, false, 'asignaciones');
    });
    data.medicamentos.forEach(row => {
        requireReference(row, 'paciente_id', patients, false, 'medicamentos');
        requireReference(row, 'catalogo_id', catalog, true, 'medicamentos');
    });
    data.historial_medicamentos.forEach(row => {
        requireReference(row, 'paciente_id', patients, false, 'historial_medicamentos');
        requireReference(row, 'medicamento_id', medicines, true, 'historial_medicamentos');
        requireReference(row, 'administrado_por', users, true, 'historial_medicamentos');
    });
    data.catalogo_medicamentos.forEach(row => requireReference(row, 'paciente_id', patients, true, 'catalogo_medicamentos'));
    data.historial_restock.forEach(row => {
        requireReference(row, 'catalogo_id', catalog, true, 'historial_restock');
        requireReference(row, 'paciente_id', patients, true, 'historial_restock');
        requireReference(row, 'registrado_por', users, true, 'historial_restock');
    });
    data.citas.forEach(row => {
        requireReference(row, 'paciente_id', patients, false, 'citas');
        requireReference(row, 'created_by', users, true, 'citas');
        requireReference(row, 'deleted_by', users, true, 'citas');
    });
    data.historial_citas.forEach(row => {
        requireReference(row, 'paciente_id', patients, false, 'historial_citas');
        requireReference(row, 'cita_id', appointments, true, 'historial_citas');
        requireReference(row, 'archivado_por', users, true, 'historial_citas');
    });
    data.tareas.forEach(row => {
        requireReference(row, 'paciente_id', patients, false, 'tareas');
        requireReference(row, 'created_by', users, true, 'tareas');
    });
    data.historial_tareas.forEach(row => {
        requireReference(row, 'paciente_id', patients, false, 'historial_tareas');
        requireReference(row, 'tarea_id', tasks, true, 'historial_tareas');
        requireReference(row, 'completado_por', users, true, 'historial_tareas');
    });
    for (const family of ['sintomas', 'signos_vitales']) {
        data[family].forEach(row => {
            requireReference(row, 'paciente_id', patients, false, family);
            requireReference(row, 'registrado_por', users, true, family);
            requireReference(row, 'deleted_by', users, true, family);
        });
    }
    data.contactos.forEach(row => {
        requireReference(row, 'paciente_id', patients, false, 'contactos');
        requireReference(row, 'deleted_by', users, true, 'contactos');
    });
    data.notas.forEach(row => {
        requireReference(row, 'paciente_id', patients, false, 'notas');
        requireReference(row, 'autor_id', users, true, 'notas');
        requireReference(row, 'deleted_by', users, true, 'notas');
    });
    data.documentos.forEach(row => {
        requireReference(row, 'paciente_id', patients, false, 'documentos');
        requireReference(row, 'subido_por', users, true, 'documentos');
        requireReference(row, 'deleted_by', users, true, 'documentos');
    });
    data.operadores.forEach(row => requireReference(row, 'created_by_usuario_id', users, true, 'operadores'));
    auditRows.forEach(row => {
        requireReference(row, 'paciente_id', patients, true, 'auditoria');
        requireReference(row, 'actor_usuario_id', users, true, 'auditoria');
        requireReference(row, 'operador_b2b_id', operators, true, 'auditoria');
    });
}

function setSensitiveDownloadHeaders(res) {
    res.setHeader('Cache-Control', 'private, no-store, no-cache, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('X-Content-Type-Options', 'nosniff');
}

async function revalidateAdministrativeContext(client, institutionId, principal, operator) {
    const institution = await client.query(
        `SELECT id,nombre,tipo,direccion,telefono,email,plan,activa,lifecycle_state,created_at,stock_modelo,
                permisos_equipo,onboarding_done,trial_started_at,shared_mode,mp_preapproval_id,
                discount_expires_at,plan_manual_expires_at,offboarding_started_at,offboarding_reason,
                offboarded_at,retention_review_at,retention_note,version
         FROM instituciones_b2b
         WHERE id=$1 AND activa=TRUE AND lifecycle_state IN ('active','offboarding_prepared')`,
        [institutionId]
    );
    if (institution.rowCount !== 1) throw exportError('P1D2_INSTITUTION_NOT_ACTIVE', 'Institución inválida o inactiva', 403);
    const principalResult = await client.query(
        `SELECT id FROM usuarios_b2b
         WHERE id=$1 AND institucion_id=$2 AND activo=TRUE AND email_verified=TRUE AND rol='admin_institucion'`,
        [principal.id, institutionId]
    );
    if (principalResult.rowCount !== 1) throw exportError('P1D2_ADMIN_REQUIRED', 'Se requiere administrador institucional', 403);
    if (operator) {
        const operatorResult = await client.query(
            `SELECT id FROM operadores_b2b
             WHERE id=$1 AND institucion_id=$2 AND activo=TRUE AND rol='admin_institucion'`,
            [operator.id, institutionId]
        );
        if (operatorResult.rowCount !== 1) throw exportError('P1D2_ADMIN_REQUIRED', 'Se requiere operador administrador vigente', 403);
    }
    return institution.rows[0];
}

async function createInstitutionalExport(options) {
    const {
        pool, institutionId: rawInstitutionId, principal, operator = null,
        tempRoot = os.tmpdir(), now = new Date(), maxExportBytes = DEFAULT_MAX_EXPORT_BYTES,
        maxRows = DEFAULT_MAX_ROWS, hooks = {}, failStage = null,
    } = options;
    if (!pool || !principal) throw exportError('P1D2_CONFIGURATION_INVALID', 'Configuración D2 inválida', 500);
    const institutionId = parsePositiveId(rawInstitutionId, 'institucion_id');
    if (Number(principal.institucion_id) !== institutionId) throw exportError('P1D2_TENANT_MISMATCH', 'Tenant inválido', 403);

    await fs.promises.mkdir(tempRoot, { recursive: true, mode: 0o700 });
    const tempDir = await fs.promises.mkdtemp(path.join(tempRoot, 'cuidadiario-p1d2-'));
    try { await fs.promises.chmod(tempDir, 0o700); } catch {}
    const zipPath = path.join(tempDir, 'institutional-export.zip');
    const zip = new ZipFileWriter(zipPath, now, maxExportBytes);
    const client = await pool.connect();
    let transactionOpen = false;
    let totalRows = 0;
    try {
        await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
        transactionOpen = true;
        await client.query("SET LOCAL statement_timeout = '120s'");
        const institution = await revalidateAdministrativeContext(client, institutionId, principal, operator);
        const isolation = (await client.query('SHOW transaction_isolation')).rows[0].transaction_isolation;
        const readOnly = (await client.query('SHOW transaction_read_only')).rows[0].transaction_read_only;
        if (isolation !== 'repeatable read' || readOnly !== 'on') throw exportError('P1D2_SNAPSHOT_INVALID', 'Snapshot no consistente', 500);
        if (hooks.afterSnapshotEstablished) await hooks.afterSnapshotEstablished({ client, institution });

        const data = {};
        for (const definition of DATASETS) {
            const result = await client.query(definition.sql, [institutionId]);
            data[definition.key] = result.rows;
            totalRows += result.rowCount;
            if (totalRows > maxRows) throw exportError('P1D2_TOO_MANY_ROWS', 'La exportación supera el límite de filas', 413);
        }
        const auditResult = await client.query(AUDIT_QUERY, [institutionId]);
        totalRows += auditResult.rowCount;
        if (totalRows > maxRows) throw exportError('P1D2_TOO_MANY_ROWS', 'La exportación supera el límite de filas', 413);
        validateTenantGraph(institutionId, data, auditResult.rows);
        if (hooks.afterStructuredRead) await hooks.afterStructuredRead({ client, data, auditRows: auditResult.rows });
        if (failStage === 'after-structured-data') throw exportError('P1D2_TEST_FAILURE', 'Fallo sintético D2', 500);

        const redactionStats = { redactedFields: 0, redactedValues: 0 };
        const auditRows = auditResult.rows.map(row => sanitizeAuditValue(row, redactionStats));
        const migrationRows = (await client.query(
            'SELECT version,checksum FROM schema_migrations_b2b ORDER BY version'
        )).rows;

        await zip.open();
        const inventory = [];
        const add = async (name, body, family = null) => {
            const info = await zip.add(name, body);
            inventory.push({ path: info.name, bytes: info.bytes, sha256: info.sha256, family });
            return info;
        };

        await add('data/institucion.json', Buffer.from(`${JSON.stringify(institution, null, 2)}\n`, 'utf8'), 'institucion');
        for (const definition of DATASETS) {
            if (definition.key === 'documentos') continue;
            await add(definition.file, jsonLineBuffer(data[definition.key]), definition.key);
        }
        await add('audit/eventos.jsonl', jsonLineBuffer(auditRows), 'auditoria_eventos');

        const documentIndex = [];
        const documentWarnings = [];
        let documentBytes = 0;
        for (const metadata of data.documentos) {
            const result = await client.query(
                'SELECT institucion_id,paciente_id,datos FROM documentos_b2b WHERE id=$1 AND institucion_id=$2',
                [metadata.id, institutionId]
            );
            if (result.rowCount !== 1 || Number(result.rows[0].institucion_id) !== institutionId
                || Number(result.rows[0].paciente_id) !== Number(metadata.paciente_id)) {
                throw exportError('P1D2_DOCUMENT_RELATION_INVALID', 'Documento fuera del tenant');
            }
            const bytes = strictBase64Decode(result.rows[0].datos);
            const internalPath = `documents/${metadata.id}/original${documentExtension(metadata.nombre_archivo)}`;
            const fileInfo = await add(internalPath, bytes, 'documentos_binarios');
            documentBytes += bytes.length;
            const declared = metadata.tamanio_bytes == null ? null : Number(metadata.tamanio_bytes);
            const sizeMatches = declared === null ? null : declared === bytes.length;
            if (sizeMatches === false) documentWarnings.push({ document_id: metadata.id, code: 'DECLARED_SIZE_MISMATCH' });
            documentIndex.push({
                ...metadata,
                package_path: internalPath,
                original_bytes: bytes.length,
                original_sha256: fileInfo.sha256,
                declared_size_matches: sizeMatches,
            });
            bytes.fill(0);
        }
        await add('documents/index.jsonl', jsonLineBuffer(documentIndex), 'documentos');

        await add('views/residentes.csv', csvBuffer(data.pacientes,
            ['id','nombre','apellido','dni','habitacion','fecha_ingreso','fecha_egreso','motivo_egreso','activo','version']), 'vista_residentes');
        await add('views/staff.csv', csvBuffer(data.usuarios,
            ['id','nombre','email','rol','turno','activo','email_verified','created_at','version']), 'vista_staff');
        await add('views/documentos.csv', csvBuffer(documentIndex,
            ['id','paciente_id','nombre_archivo','tipo_mime','tamanio_bytes','original_bytes','original_sha256','package_path','deleted_at']), 'vista_documentos');
        await add('audit/eventos.csv', csvBuffer(auditRows,
            ['id','paciente_id','actor_usuario_id','operador_b2b_id','actor_tipo','recurso_tipo','recurso_id','accion','recurso_version','ocurrido_at','motivo','capture_mode','request_id']), 'auditoria_eventos');

        const counts = Object.fromEntries(DATASETS.map(definition => [definition.key, data[definition.key].length]));
        counts.auditoria_eventos = auditRows.length;
        const readme = [
            'CuidaDiario PRO — Exportación institucional',
            '',
            `Formato: ${EXPORT_SCHEMA}`,
            `Generado en UTC: ${now.toISOString()}`,
            `Institución ID: ${institutionId}`,
            '',
            'Los archivos JSON/JSONL UTF-8 son la representación canónica. Los CSV son vistas de conveniencia.',
            'Para una lectura rápida, abra primero este README y luego la carpeta views, que contiene listados CSV de residentes, personal, documentos y auditoría.',
            'La carpeta data conserva las demás familias operativas en JSONL: cada línea es un registro independiente.',
            'Los documentos originales están bajo documents/<id>/ y su nombre original permanece en documents/index.jsonl.',
            '',
            'Resumen de registros incluidos:',
            ...Object.entries(counts).map(([family, count]) => `- ${family}: ${count}`),
            `- documentos originales: ${documentIndex.length}`,
            '',
            'Verifique manifest.sha256, manifest.json y checksums.sha256 antes de usar el paquete.',
            'Este paquete excluye credenciales, sesiones, idempotencia y secretos técnicos.',
            'La auditoría es prospectiva: no se fabricó historia anterior a P1-A.',
            '',
        ].join('\r\n');
        await add('README.txt', Buffer.from(readme, 'utf8'), 'documentacion');

        const checksumText = inventory.map(file => `${file.sha256}  ${file.path}`).join('\n') + '\n';
        const checksumInfo = await add('checksums.sha256', Buffer.from(checksumText, 'utf8'), 'integridad');
        const manifest = {
            schema: EXPORT_SCHEMA,
            exporter_version: EXPORTER_VERSION,
            generated_at_utc: now.toISOString(),
            institution: { id: institution.id, nombre: institution.nombre },
            consistency: { transaction_isolation: isolation, transaction_read_only: readOnly, single_snapshot: true },
            inclusion: {
                historical: 'Incluye activos, inactivos, egresados y soft-deleted/archivados del tenant.',
                audit: 'Ledger prospectivo disponible; no se fabrica historia anterior a P1-A.',
                documents: 'Incluye metadatos y bytes originales activos y archivados.',
            },
            exclusions: [
                'password_hash', 'reset_token', 'email_verification_token', 'pin_hash',
                'operador_sesiones_b2b', 'operaciones_idempotentes_b2b',
                'institucion_exportaciones_b2b', '_migrations',
                'JWT/cookies/variables de entorno/secretos de proveedores/material criptográfico',
            ],
            schema_migrations_b2b: migrationRows,
            families: ['institucion', ...DATASETS.map(definition => definition.key), 'auditoria_eventos'],
            counts,
            documents: { count: documentIndex.length, original_bytes: documentBytes },
            audit_redactions: redactionStats,
            warnings: documentWarnings,
            resource_limits: { maximum_zip_bytes: maxExportBytes, maximum_rows: maxRows },
            files: inventory.map(file => ({ path: file.path, bytes: file.bytes, sha256: file.sha256, family: file.family })),
            integrity: {
                payload_checksums_file: checksumInfo.name,
                manifest_digest_file: 'manifest.sha256',
                manifest_self_hash_excluded_to_avoid_recursion: true,
            },
        };
        const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
        const manifestInfo = await zip.add('manifest.json', manifestBytes);
        await zip.add('manifest.sha256', Buffer.from(`${manifestInfo.sha256}  manifest.json\n`, 'utf8'));
        await zip.close();
        await client.query('COMMIT');
        transactionOpen = false;

        const stat = await fs.promises.stat(zipPath);
        const fileName = `cuidadiario-export-${slugify(institution.nombre, `institucion-${institutionId}`)}-${compactUtc(now)}.zip`;
        return { tempDir, zipPath, fileName, bytes: stat.size, sha256: await fileSha256(zipPath), manifest };
    } catch (error) {
        if (transactionOpen) {
            try { await client.query('ROLLBACK'); } catch {}
        }
        await zip.abort();
        await fs.promises.rm(tempDir, { recursive: true, force: true });
        throw error;
    } finally {
        client.release();
    }
}

async function fileSha256(filePath) {
    const hash = crypto.createHash('sha256');
    await pipeline(fs.createReadStream(filePath), hash);
    return hash.digest('hex');
}

async function cleanupExport(result) {
    if (result && result.tempDir) await fs.promises.rm(result.tempDir, { recursive: true, force: true });
}

function registerInstitutionalExportRoutes(app, dependencies) {
    const { pool, authB2BMiddleware, requireB2BRole, recordExportReceipt, tempRoot, testMode = false } = dependencies;
    app.use('/api/b2b/institutional-export', (req, res, next) => {
        setSensitiveDownloadHeaders(res);
        next();
    });
    app.get('/api/b2b/institutional-export', authB2BMiddleware, requireB2BRole('admin_institucion'), async (req, res) => {
        let result = null;
        try {
            const failStage = testMode ? req.get('x-p1d2-fail-stage') : null;
            result = await createInstitutionalExport({
                pool,
                institutionId: req.b2bUser.institucion_id,
                principal: req.b2bPrincipal || req.b2bUser,
                operator: req.b2bOperator || null,
                tempRoot,
                failStage,
            });
            if (typeof recordExportReceipt !== 'function') {
                throw exportError('P1D3_EXPORT_RECEIPT_UNAVAILABLE', 'No se pudo registrar la evidencia de exportación', 500);
            }
            const receipt = await recordExportReceipt(pool, {
                institutionId: req.b2bUser.institucion_id,
                actorUserId: (req.b2bPrincipal || req.b2bUser).id,
                schema: EXPORT_SCHEMA,
                sha256: result.sha256,
                bytes: result.bytes,
            });
            res.status(200);
            res.setHeader('Content-Type', 'application/zip');
            res.setHeader('Content-Length', String(result.bytes));
            res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(result.fileName)}`);
            res.setHeader('X-B2B-Export-Receipt', receipt);
            res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition, X-B2B-Export-Receipt');
            await pipeline(fs.createReadStream(result.zipPath), res);
        } catch (error) {
            const code = error && /^P1D2_[A-Z0-9_]+$/.test(error.code || '') ? error.code : 'P1D2_EXPORT_FAILED';
            console.error('GET /api/b2b/institutional-export:', code);
            if (!res.headersSent) {
                res.status(error.status || 500).json({ error: 'No se pudo generar la exportación institucional', code });
            } else if (!res.destroyed) {
                res.destroy(error);
            }
        } finally {
            try {
                await cleanupExport(result);
            } catch {
                console.error('GET /api/b2b/institutional-export: P1D2_TEMP_CLEANUP_FAILED');
            }
        }
    });
}

module.exports = {
    EXPORT_SCHEMA,
    EXPORTER_VERSION,
    DATASETS,
    ZipFileWriter,
    assertZipPath,
    sanitizeAuditValue,
    validateTenantGraph,
    createInstitutionalExport,
    cleanupExport,
    registerInstitutionalExportRoutes,
};
