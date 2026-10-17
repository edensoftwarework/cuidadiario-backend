'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const PDFDocument = require('pdfkit');
const PDF_FONTS = Object.freeze({
    regular: require.resolve('dejavu-fonts-ttf/ttf/DejaVuSans.ttf'),
    bold: require.resolve('dejavu-fonts-ttf/ttf/DejaVuSans-Bold.ttf'),
});

const ACCEPTANCE_STATEMENT = 'Acepto los Términos del servicio, la Política de privacidad y el Anexo de tratamiento de datos en representación de esta institución';
const CURRENT_BUNDLE_VERSION = '2026-10-12-candidate.6';
const ACTIVE_BUNDLE_ENV = 'B2B_CONTRACT_ACTIVE_VERSION';
const CONTRACT_TYPES = Object.freeze(['terms', 'privacy', 'dpa']);
const CONTRACT_FILES = Object.freeze({
    terms: 'terms-2026-10-12-candidate.6.md',
    privacy: 'privacy-2026-10-12-candidate.6.md',
    dpa: 'dpa-2026-10-12-candidate.6.md',
});

function clientReadyCandidate(source) {
    return String(source)
        .replace(/^\*\*Versión candidata:\*\*[^\n]*\n/m, '**Última actualización:** 12 de octubre de 2026  \n')
        .replace(/^\*\*Estado:\*\*[^\n]*\n/m, '');
}

function publicDocumentVersion(version) {
    const match = String(version || '').match(/(20\d{2})-(\d{2})-(\d{2})/);
    return match ? { display: `${match[3]}/${match[2]}/${match[1]}`, slug: match[0] } : { display: 'actual', slug: 'vigente' };
}

const STAGE_A_CONTRACT_MIGRATION = Object.freeze({
    version: 'stagea_001_contract_acceptance',
    sql: `
CREATE TABLE IF NOT EXISTS contrato_aceptaciones_b2b (
    id UUID PRIMARY KEY,
    institucion_id INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE RESTRICT,
    usuario_b2b_id INTEGER NOT NULL REFERENCES usuarios_b2b(id) ON DELETE RESTRICT,
    bundle_version VARCHAR(80) NOT NULL,
    bundle_sha256 CHAR(64) NOT NULL CHECK (bundle_sha256 ~ '^[0-9a-f]{64}$'),
    terms_version VARCHAR(80) NOT NULL,
    terms_sha256 CHAR(64) NOT NULL CHECK (terms_sha256 ~ '^[0-9a-f]{64}$'),
    terms_content TEXT NOT NULL,
    privacy_version VARCHAR(80) NOT NULL,
    privacy_sha256 CHAR(64) NOT NULL CHECK (privacy_sha256 ~ '^[0-9a-f]{64}$'),
    privacy_content TEXT NOT NULL,
    dpa_version VARCHAR(80) NOT NULL,
    dpa_sha256 CHAR(64) NOT NULL CHECK (dpa_sha256 ~ '^[0-9a-f]{64}$'),
    dpa_content TEXT NOT NULL,
    representante_nombre TEXT NOT NULL CHECK (char_length(btrim(representante_nombre)) BETWEEN 2 AND 160),
    representante_email TEXT NOT NULL CHECK (char_length(btrim(representante_email)) BETWEEN 3 AND 254),
    representante_caracter TEXT NOT NULL CHECK (char_length(btrim(representante_caracter)) BETWEEN 2 AND 160),
    declaracion_facultades BOOLEAN NOT NULL CHECK (declaracion_facultades = TRUE),
    acceptance_statement TEXT NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    request_id UUID NOT NULL,
    user_agent_sha256 CHAR(64) NOT NULL CHECK (user_agent_sha256 ~ '^[0-9a-f]{64}$'),
    evidence_source VARCHAR(30) NOT NULL CHECK (evidence_source IN ('web_authenticated','controlled_test')),
    UNIQUE (institucion_id, bundle_version)
);
CREATE INDEX IF NOT EXISTS contrato_aceptaciones_b2b_tenant_fecha_idx
    ON contrato_aceptaciones_b2b (institucion_id, accepted_at DESC, id);

CREATE OR REPLACE FUNCTION prevent_contrato_aceptacion_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'contrato_aceptaciones_b2b es append-only'
        USING ERRCODE = '55000';
END;
$$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname = 'contrato_aceptaciones_b2b_append_only'
          AND tgrelid = 'contrato_aceptaciones_b2b'::regclass
    ) THEN
        CREATE TRIGGER contrato_aceptaciones_b2b_append_only
        BEFORE UPDATE OR DELETE ON contrato_aceptaciones_b2b
        FOR EACH ROW EXECUTE FUNCTION prevent_contrato_aceptacion_mutation();
    END IF;
END;
$$;
`,
});

const STAGE_A_COMMERCIAL_MIGRATION = Object.freeze({
    version: 'stagea_002_commercial_offers',
    sql: `
CREATE TABLE IF NOT EXISTS contrato_ofertas_b2b (
    id UUID PRIMARY KEY,
    institucion_id INTEGER NOT NULL REFERENCES instituciones_b2b(id) ON DELETE RESTRICT,
    oferta_version VARCHAR(80) NOT NULL,
    importe NUMERIC(14,2) NOT NULL CHECK (importe > 0),
    moneda CHAR(3) NOT NULL CHECK (moneda ~ '^[A-Z]{3}$'),
    periodicidad VARCHAR(20) NOT NULL CHECK (periodicidad = 'monthly'),
    regla_vencimiento TEXT NOT NULL CHECK (char_length(btrim(regla_vencimiento)) BETWEEN 3 AND 300),
    medio_pago TEXT NOT NULL CHECK (char_length(btrim(medio_pago)) BETWEEN 2 AND 200),
    vigente_desde TIMESTAMPTZ NOT NULL,
    vigente_hasta TIMESTAMPTZ NULL,
    reemplaza_oferta_id UUID NULL,
    oferta_sha256 CHAR(64) NOT NULL CHECK (oferta_sha256 ~ '^[0-9a-f]{64}$'),
    estado_origen VARCHAR(20) NOT NULL DEFAULT 'proposed' CHECK (estado_origen = 'proposed'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    evidence_source VARCHAR(30) NOT NULL CHECK (evidence_source IN ('local_admin','controlled_test')),
    CONSTRAINT contrato_ofertas_b2b_vigencia_check CHECK (vigente_hasta IS NULL OR vigente_hasta > vigente_desde),
    CONSTRAINT contrato_ofertas_b2b_tenant_version_key UNIQUE (institucion_id,oferta_version),
    CONSTRAINT contrato_ofertas_b2b_tenant_id_key UNIQUE (institucion_id,id),
    CONSTRAINT contrato_ofertas_b2b_reemplazo_fk FOREIGN KEY (institucion_id,reemplaza_oferta_id)
        REFERENCES contrato_ofertas_b2b(institucion_id,id) ON DELETE RESTRICT
);
CREATE INDEX IF NOT EXISTS contrato_ofertas_b2b_tenant_fecha_idx
    ON contrato_ofertas_b2b (institucion_id,created_at DESC,id DESC);

ALTER TABLE contrato_aceptaciones_b2b
    ADD COLUMN IF NOT EXISTS oferta_id UUID NULL,
    ADD COLUMN IF NOT EXISTS oferta_version VARCHAR(80) NULL,
    ADD COLUMN IF NOT EXISTS oferta_sha256 CHAR(64) NULL,
    ADD COLUMN IF NOT EXISTS importe NUMERIC(14,2) NULL,
    ADD COLUMN IF NOT EXISTS moneda CHAR(3) NULL,
    ADD COLUMN IF NOT EXISTS periodicidad VARCHAR(20) NULL,
    ADD COLUMN IF NOT EXISTS regla_vencimiento TEXT NULL,
    ADD COLUMN IF NOT EXISTS medio_pago TEXT NULL,
    ADD COLUMN IF NOT EXISTS oferta_vigente_desde TIMESTAMPTZ NULL,
    ADD COLUMN IF NOT EXISTS oferta_vigente_hasta TIMESTAMPTZ NULL;

ALTER TABLE contrato_aceptaciones_b2b
    DROP CONSTRAINT IF EXISTS contrato_aceptaciones_b2b_institucion_id_bundle_version_key;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='contrato_aceptaciones_b2b_oferta_fields_check') THEN
        ALTER TABLE contrato_aceptaciones_b2b ADD CONSTRAINT contrato_aceptaciones_b2b_oferta_fields_check CHECK (
            (oferta_id IS NULL AND oferta_version IS NULL AND oferta_sha256 IS NULL AND importe IS NULL
                AND moneda IS NULL AND periodicidad IS NULL AND regla_vencimiento IS NULL AND medio_pago IS NULL
                AND oferta_vigente_desde IS NULL AND oferta_vigente_hasta IS NULL)
            OR
            (oferta_id IS NOT NULL AND oferta_version IS NOT NULL AND oferta_sha256 ~ '^[0-9a-f]{64}$'
                AND importe > 0 AND moneda ~ '^[A-Z]{3}$' AND periodicidad='monthly'
                AND regla_vencimiento IS NOT NULL AND medio_pago IS NOT NULL AND oferta_vigente_desde IS NOT NULL)
        );
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='contrato_aceptaciones_b2b_oferta_fk') THEN
        ALTER TABLE contrato_aceptaciones_b2b ADD CONSTRAINT contrato_aceptaciones_b2b_oferta_fk
            FOREIGN KEY (institucion_id,oferta_id) REFERENCES contrato_ofertas_b2b(institucion_id,id) ON DELETE RESTRICT;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname='contrato_aceptaciones_b2b_oferta_bundle_key') THEN
        ALTER TABLE contrato_aceptaciones_b2b ADD CONSTRAINT contrato_aceptaciones_b2b_oferta_bundle_key
            UNIQUE (institucion_id,oferta_id,bundle_version);
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION prevent_contrato_oferta_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'contrato_ofertas_b2b es append-only'
        USING ERRCODE = '55000';
END;
$$;
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger
        WHERE tgname='contrato_ofertas_b2b_append_only'
          AND tgrelid='contrato_ofertas_b2b'::regclass
    ) THEN
        CREATE TRIGGER contrato_ofertas_b2b_append_only
        BEFORE UPDATE OR DELETE ON contrato_ofertas_b2b
        FOR EACH ROW EXECUTE FUNCTION prevent_contrato_oferta_mutation();
    END IF;
END;
$$;
`,
});

const STAGE_A_DOCUMENT_ONLY_MIGRATION = Object.freeze({
    version: 'stagea_003_document_only_acceptance',
    sql: `
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='contrato_aceptaciones_b2b' AND column_name='oferta_id'
    ) THEN
        EXECUTE 'CREATE UNIQUE INDEX IF NOT EXISTS contrato_aceptaciones_b2b_document_bundle_key
                 ON contrato_aceptaciones_b2b (institucion_id,bundle_version)
                 WHERE oferta_id IS NULL';
    END IF;
END;
$$;
`,
});

const STAGE_A_CONTRACT_MIGRATIONS = Object.freeze([
    STAGE_A_CONTRACT_MIGRATION,
    STAGE_A_DOCUMENT_ONLY_MIGRATION,
]);

function normalizeDocumentContent(value) {
    return String(value).replace(/\r\n/g, '\n').replace(/\r/g, '\n').trimEnd() + '\n';
}

function sha256(value) {
    return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function parsePositiveId(value) {
    const text = String(value ?? '');
    if (!/^[1-9]\d*$/.test(text)) return null;
    const parsed = Number(text);
    return Number.isSafeInteger(parsed) ? parsed : null;
}

function normalizeCommercialOffer(input) {
    const institutionId = parsePositiveId(input.institution_id ?? input.institucion_id);
    const version = String(input.offer_version ?? input.oferta_version ?? '').trim();
    const amountText = String(input.amount ?? input.importe ?? '').trim();
    const currency = String(input.currency ?? input.moneda ?? '').trim().toUpperCase();
    const dueRule = String(input.due_rule ?? input.regla_vencimiento ?? '').trim();
    const paymentMethod = String(input.payment_method ?? input.medio_pago ?? '').trim();
    const validFromDate = new Date(input.valid_from ?? input.vigente_desde ?? '');
    const validUntilRaw = input.valid_until ?? input.vigente_hasta ?? null;
    const validUntilDate = validUntilRaw === null || validUntilRaw === '' ? null : new Date(validUntilRaw);
    if (!institutionId) throw contractError(400, 'COMMERCIAL_INSTITUTION_INVALID', 'Institución comercial inválida');
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$/.test(version)) {
        throw contractError(400, 'COMMERCIAL_VERSION_INVALID', 'Versión comercial inválida');
    }
    if (!/^\d{1,12}(?:\.\d{1,2})?$/.test(amountText) || Number(amountText) <= 0) {
        throw contractError(400, 'COMMERCIAL_AMOUNT_INVALID', 'Importe comercial inválido');
    }
    if (!/^[A-Z]{3}$/.test(currency)) throw contractError(400, 'COMMERCIAL_CURRENCY_INVALID', 'Moneda inválida');
    if (dueRule.length < 3 || dueRule.length > 300) throw contractError(400, 'COMMERCIAL_DUE_RULE_INVALID', 'Regla de vencimiento inválida');
    if (paymentMethod.length < 2 || paymentMethod.length > 200) throw contractError(400, 'COMMERCIAL_PAYMENT_METHOD_INVALID', 'Medio de pago inválido');
    if (Number.isNaN(validFromDate.getTime())) throw contractError(400, 'COMMERCIAL_VALID_FROM_INVALID', 'Inicio de vigencia inválido');
    if (validUntilDate && (Number.isNaN(validUntilDate.getTime()) || validUntilDate <= validFromDate)) {
        throw contractError(400, 'COMMERCIAL_VALID_UNTIL_INVALID', 'Fin de vigencia inválido');
    }
    const amount = Number(amountText).toFixed(2);
    const normalized = {
        institution_id: institutionId,
        offer_version: version,
        amount,
        currency,
        billing_period: 'monthly',
        due_rule: dueRule,
        payment_method: paymentMethod,
        valid_from: validFromDate.toISOString(),
        valid_until: validUntilDate ? validUntilDate.toISOString() : null,
    };
    normalized.offer_sha256 = sha256(JSON.stringify(normalized));
    return Object.freeze(normalized);
}

function commercialOfferEvidence(row, derivedStatus = 'proposed') {
    if (!row) return null;
    return {
        offer_id: row.id,
        institution_id: Number(row.institucion_id),
        offer_version: row.oferta_version,
        amount: String(row.importe),
        currency: row.moneda,
        billing_period: row.periodicidad,
        due_rule: row.regla_vencimiento,
        payment_method: row.medio_pago,
        valid_from: row.vigente_desde,
        valid_until: row.vigente_hasta,
        offer_sha256: row.oferta_sha256,
        status: derivedStatus,
        created_at: row.created_at,
        supersedes_offer_id: row.reemplaza_oferta_id,
    };
}

async function createCommercialOffer(pool, input, options = {}) {
    const offer = normalizeCommercialOffer(input);
    const evidenceSource = options.evidenceSource || 'local_admin';
    if (!['local_admin', 'controlled_test'].includes(evidenceSource)) {
        throw contractError(400, 'COMMERCIAL_SOURCE_INVALID', 'Fuente administrativa inválida');
    }
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query("SELECT pg_advisory_xact_lock(hashtext('cuidadiario-stage-a-commercial'),$1)", [offer.institution_id]);
        const institution = await client.query(
            `SELECT id FROM instituciones_b2b WHERE id=$1 AND activa=TRUE AND COALESCE(lifecycle_state,'active') <> 'retained' FOR UPDATE`,
            [offer.institution_id]
        );
        if (institution.rowCount !== 1) throw contractError(409, 'COMMERCIAL_INSTITUTION_INACTIVE', 'La institución no está activa');
        const previous = await client.query(
            `SELECT id FROM contrato_ofertas_b2b WHERE institucion_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1`,
            [offer.institution_id]
        );
        const id = crypto.randomUUID();
        const inserted = await client.query(
            `INSERT INTO contrato_ofertas_b2b
             (id,institucion_id,oferta_version,importe,moneda,periodicidad,regla_vencimiento,medio_pago,
              vigente_desde,vigente_hasta,reemplaza_oferta_id,oferta_sha256,evidence_source)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
            [id, offer.institution_id, offer.offer_version, offer.amount, offer.currency, offer.billing_period,
                offer.due_rule, offer.payment_method, offer.valid_from, offer.valid_until,
                previous.rows[0]?.id || null, offer.offer_sha256, evidenceSource]
        );
        await client.query('COMMIT');
        return commercialOfferEvidence(inserted.rows[0]);
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        if (error.code === '23505') throw contractError(409, 'COMMERCIAL_VERSION_DUPLICATE', 'La versión comercial ya existe');
        throw error;
    } finally {
        client.release();
    }
}

function createContractBundle({ version, status, documents: sourceDocuments, requiresAcceptance = true }) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,79}$/.test(String(version || ''))) {
        throw new Error('Versión de bundle contractual inválida');
    }
    if (!['draft', 'active'].includes(status)) throw new Error('Estado de bundle contractual inválido');
    const documents = {};
    for (const type of CONTRACT_TYPES) {
        const content = normalizeDocumentContent(sourceDocuments[type]);
        documents[type] = Object.freeze({
            type,
            version,
            sha256: sha256(content),
            content,
        });
    }
    const bundleMaterial = JSON.stringify(CONTRACT_TYPES.map(type => ({
        type,
        version: documents[type].version,
        sha256: documents[type].sha256,
    })));
    return Object.freeze({
        version,
        status,
        requires_acceptance: !!requiresAcceptance,
        sha256: sha256(bundleMaterial),
        documents: Object.freeze(documents),
    });
}

function configuredContractStatus(version, environment = process.env) {
    const requestedVersion = String(environment?.[ACTIVE_BUNDLE_ENV] || '').trim();
    if (!requestedVersion) return 'draft';
    if (requestedVersion !== version) {
        throw new Error(`${ACTIVE_BUNDLE_ENV} no coincide con el bundle contractual incorporado`);
    }
    return 'active';
}

function loadCurrentContractBundle(options = {}) {
    const directory = options.directory || path.join(__dirname, 'contracts');
    const sourceDocuments = {};
    for (const type of CONTRACT_TYPES) {
        sourceDocuments[type] = clientReadyCandidate(fs.readFileSync(path.join(directory, CONTRACT_FILES[type]), 'utf8'));
    }
    return createContractBundle({
        version: CURRENT_BUNDLE_VERSION,
        status: options.status || configuredContractStatus(CURRENT_BUNDLE_VERSION, options.environment),
        documents: sourceDocuments,
    });
}

function loadIntegratedDemoContractBundle() {
    const allowedHosts = new Set(['127.0.0.1', 'localhost', '::1']);
    const database = String(process.env.PGDATABASE || '');
    if (process.env.P1_TEST_MODE !== '1' || process.env.NODE_ENV !== 'test'
        || !allowedHosts.has(process.env.PGHOST)
        || !/^cuidadiario_p1_test(?:_|$)/.test(database)) {
        throw new Error('El bundle contractual de demostración sólo puede activarse en P1_TEST_MODE, loopback y base allowlisted');
    }
    const directory = path.join(__dirname, 'contracts');
    const sourceDocuments = {};
    for (const type of CONTRACT_TYPES) {
        sourceDocuments[type] = clientReadyCandidate(fs.readFileSync(path.join(directory, CONTRACT_FILES[type]), 'utf8'));
    }
    return createContractBundle({
        version: 'local-demo-2026-10-12-candidate.6',
        status: 'active',
        documents: sourceDocuments,
    });
}

const CURRENT_CONTRACT_BUNDLE = process.env.CUIDADIARIO_INTEGRATED_DEMO === '1'
    ? loadIntegratedDemoContractBundle()
    : loadCurrentContractBundle();

function contractError(status, code, message) {
    const error = new Error(message);
    error.status = status;
    error.code = code;
    return error;
}

function requestUuid(req) {
    const candidate = String(req.get?.('X-Request-ID') || '').trim().toLowerCase();
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(candidate)
        ? candidate
        : crypto.randomUUID();
}

function publicBundle(bundle) {
    return {
        version: bundle.version,
        status: bundle.status,
        requires_acceptance: bundle.requires_acceptance,
        sha256: bundle.sha256,
        documents: CONTRACT_TYPES.map(type => ({
            type,
            version: bundle.documents[type].version,
            sha256: bundle.documents[type].sha256,
            url: `/api/b2b/contracts/documents/${type}?bundle_version=${encodeURIComponent(bundle.version)}`,
            pdf_url: `/api/b2b/contracts/documents/${type}.pdf?bundle_version=${encodeURIComponent(bundle.version)}`,
        })),
        pdf_url: `/api/b2b/contracts/documents.pdf?bundle_version=${encodeURIComponent(bundle.version)}`,
    };
}

function pdfText(value) {
    return String(value || '').replace(/\*\*([^*]+)\*\*/g, '$1').replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1 ($2)');
}

function writeMarkdownToPdf(doc, source, startOnNewPage = false) {
    if (startOnNewPage) doc.addPage();
    const lines = String(source || '').replace(/\r/g, '').split('\n');
    for (const raw of lines) {
        const heading = raw.match(/^(#{1,4})\s+(.+)$/);
        const bullet = raw.match(/^[-*]\s+(.+)$/);
        const numbered = raw.match(/^(\d+)\.\s+(.+)$/);
        if (heading) {
            const sizes = [20, 16, 13, 11];
            doc.moveDown(heading[1].length === 1 ? 0.25 : 0.45)
                .font('CuidaDiario-Bold').fontSize(sizes[heading[1].length - 1]).fillColor('#17324D')
                .text(pdfText(heading[2]), { paragraphGap: 5, keepTogether: true });
        } else if (bullet) {
            doc.font('CuidaDiario-Regular').fontSize(9.5).fillColor('#27364A').text(`•  ${pdfText(bullet[1])}`, { indent: 10, paragraphGap: 3 });
        } else if (numbered) {
            doc.font('CuidaDiario-Regular').fontSize(9.5).fillColor('#27364A').text(`${numbered[1]}.  ${pdfText(numbered[2])}`, { indent: 10, paragraphGap: 3 });
        } else if (raw.trim()) {
            doc.font('CuidaDiario-Regular').fontSize(9.5).fillColor('#27364A').text(pdfText(raw), { align: 'justify', lineGap: 1.5, paragraphGap: 5 });
        } else {
            doc.moveDown(0.35);
        }
    }
}

function sendContractPdf(res, bundle, selectedTypes) {
    const labels = { terms: 'Términos del servicio', privacy: 'Política de privacidad', dpa: 'Acuerdo de tratamiento de datos' };
    const filenames = { terms: 'terminos', privacy: 'privacidad', dpa: 'tratamiento-de-datos' };
    const publicVersion = publicDocumentVersion(bundle.version);
    const combined = selectedTypes.length > 1;
    const filename = combined ? `cuidadiario-documentacion-${publicVersion.slug}.pdf` : `cuidadiario-${filenames[selectedTypes[0]]}-${publicVersion.slug}.pdf`;
    const doc = new PDFDocument({ size: 'A4', bufferPages: true, margins: { top: 48, right: 48, bottom: 54, left: 48 }, info: {
        Title: combined ? 'Documentación institucional de CuidaDiario PRO' : labels[selectedTypes[0]],
        Author: 'EDEN SoftWork', Subject: `Versión documental ${publicVersion.display}`,
    }});
    doc.registerFont('CuidaDiario-Regular', PDF_FONTS.regular);
    doc.registerFont('CuidaDiario-Bold', PDF_FONTS.bold);
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    doc.on('pageAdded', () => {
        const range = doc.bufferedPageRange();
        void range;
    });
    doc.pipe(res);
    selectedTypes.forEach((type, index) => {
        if (combined) {
            if (index > 0) doc.addPage();
            doc.font('CuidaDiario-Bold').fontSize(10).fillColor('#557086').text(`CuidaDiario PRO · ${labels[type]}`);
            doc.font('CuidaDiario-Regular').fontSize(8.5).fillColor('#6A7D90').text(`Versión documental ${publicVersion.display} · SHA-256 ${bundle.documents[type].sha256}`);
            doc.moveDown(0.7);
        }
        writeMarkdownToPdf(doc, bundle.documents[type].content, false);
    });
    const range = doc.bufferedPageRange();
    for (let pageIndex = range.start; pageIndex < range.start + range.count; pageIndex += 1) {
        doc.switchToPage(pageIndex);
        const bottomMargin = doc.page.margins.bottom;
        doc.page.margins.bottom = 0;
        doc.font('CuidaDiario-Regular').fontSize(8).fillColor('#718096')
            .text(`CuidaDiario PRO · ${publicVersion.display} · Página ${pageIndex + 1} de ${range.count}`, 48, doc.page.height - 34, { width: 499, align: 'center', lineBreak: false });
        doc.page.margins.bottom = bottomMargin;
    }
    doc.end();
}

const ACCEPTANCE_DOCUMENT_LABELS = Object.freeze({
    terms: 'Términos del servicio',
    privacy: 'Política de privacidad',
    dpa: 'Anexo de tratamiento de datos',
});

function formatAcceptanceDate(value) {
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return 'Fecha no disponible';
    return new Intl.DateTimeFormat('es-AR', {
        timeZone: 'America/Argentina/Buenos_Aires',
        day: '2-digit', month: 'long', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        timeZoneName: 'longOffset', hour12: false,
    }).format(date).replace('GMT', 'UTC');
}

function writeCertificateField(doc, label, value, options = {}) {
    doc.font('CuidaDiario-Bold').fontSize(8.5).fillColor('#557086').text(label.toUpperCase(), { characterSpacing: 0.45 });
    doc.moveDown(0.2);
    doc.font(options.monospace ? 'Courier' : 'CuidaDiario-Regular')
        .fontSize(options.small ? 8.2 : 10.2).fillColor('#1D3448')
        .text(value == null || value === '' ? 'No disponible' : String(value), { lineGap: 2 });
    doc.moveDown(0.7);
}

function sendAcceptanceCertificatePdf(res, rows, institutionName, institutionId) {
    if (!rows.length) {
        throw contractError(404, 'CONTRACT_ACCEPTANCE_NOT_FOUND', 'La institución todavía no registra una aceptación contractual');
    }
    const doc = new PDFDocument({
        size: 'A4', bufferPages: true,
        margins: { top: 52, right: 52, bottom: 58, left: 52 },
        info: {
            Title: 'Constancia de aceptación de documentación institucional',
            Author: 'CuidaDiario PRO',
            Subject: 'Constancia informativa basada en el registro de aceptación',
        },
    });
    doc.registerFont('CuidaDiario-Regular', PDF_FONTS.regular);
    doc.registerFont('CuidaDiario-Bold', PDF_FONTS.bold);
    res.setHeader('Cache-Control', 'no-store, max-age=0, private');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="cuidadiario-constancia-aceptacion-${institutionId}.pdf"`);
    res.setHeader('Access-Control-Expose-Headers', 'Content-Disposition');
    doc.on('error', error => res.destroy(error));
    doc.pipe(res);

    rows.forEach((row, rowIndex) => {
        if (rowIndex > 0) doc.addPage();
        const evidence = acceptanceEvidence(row, null, false);
        doc.rect(0, 0, doc.page.width, 11).fill('#2B6F73');
        doc.font('CuidaDiario-Bold').fontSize(22).fillColor('#19364A')
            .text('Constancia de aceptación', { align: 'left' });
        doc.font('CuidaDiario-Regular').fontSize(11).fillColor('#557086')
            .text('Documentación institucional de CuidaDiario PRO');
        if (rows.length > 1) {
            doc.fontSize(8.5).fillColor('#718096').text(`Registro ${rowIndex + 1} de ${rows.length}`, 52, 55, { align: 'right', width: 491 });
        }
        doc.moveDown(1.2);
        doc.roundedRect(52, doc.y, 491, 64, 7).fill('#F1F7F7');
        const noticeY = doc.y + 13;
        doc.font('CuidaDiario-Bold').fontSize(9.5).fillColor('#2B6F73').text('NATURALEZA DE ESTA CONSTANCIA', 68, noticeY, { width: 459 });
        doc.font('CuidaDiario-Regular').fontSize(8.8).fillColor('#334E60')
            .text('Reproduce la aceptación registrada por el sistema. No constituye firma digital, certificación notarial ni validación independiente de facultades o identidad.', 68, noticeY + 18, { width: 459, lineGap: 2 });
        doc.y = noticeY + 68;

        doc.font('CuidaDiario-Bold').fontSize(13).fillColor('#19364A').text('Datos de la aceptación');
        doc.moveDown(0.65);
        writeCertificateField(doc, 'Institución', institutionName);
        writeCertificateField(doc, 'Aceptante', `${evidence.representative.name} · ${evidence.representative.email}`);
        writeCertificateField(doc, 'Carácter declarado', evidence.representative.capacity);
        writeCertificateField(doc, 'Fecha y hora', `${formatAcceptanceDate(evidence.accepted_at)} · America/Argentina/Buenos_Aires`);
        writeCertificateField(doc, 'Identificador de la constancia', evidence.acceptance_event_id, { monospace: true, small: true });
        writeCertificateField(doc, 'Versión conjunta', evidence.bundle_version);
        writeCertificateField(doc, 'Hash conjunto SHA-256', evidence.bundle_sha256, { monospace: true, small: true });

        doc.font('CuidaDiario-Bold').fontSize(13).fillColor('#19364A').text('Documentos aceptados');
        doc.moveDown(0.55);
        for (const type of CONTRACT_TYPES) {
            const document = evidence.documents[type];
            doc.font('CuidaDiario-Bold').fontSize(9.4).fillColor('#2B6F73').text(ACCEPTANCE_DOCUMENT_LABELS[type]);
            doc.font('CuidaDiario-Regular').fontSize(8.5).fillColor('#334E60')
                .text(`Versión: ${document.version}`, { lineGap: 1 });
            doc.font('Courier').fontSize(7.6).fillColor('#526777').text(`SHA-256: ${document.sha256}`, { lineGap: 1 });
            doc.moveDown(0.5);
        }

        doc.moveDown(0.3);
        doc.font('CuidaDiario-Bold').fontSize(13).fillColor('#19364A').text('Declaración registrada');
        doc.moveDown(0.5);
        doc.roundedRect(52, doc.y, 491, 62, 6).lineWidth(0.8).strokeColor('#B8CCCF').stroke();
        const statementY = doc.y + 12;
        doc.font('CuidaDiario-Regular').fontSize(9.3).fillColor('#1D3448')
            .text(`“${evidence.acceptance_statement}”`, 67, statementY, { width: 461, lineGap: 3 });
        doc.y = statementY + 67;
        doc.font('CuidaDiario-Regular').fontSize(8.2).fillColor('#718096')
            .text('La evidencia técnica íntegra permanece conservada por CuidaDiario PRO para verificación administrativa autorizada.', { align: 'left' });
    });

    const range = doc.bufferedPageRange();
    for (let pageIndex = 0; pageIndex < range.count; pageIndex += 1) {
        doc.switchToPage(range.start + pageIndex);
        const bottomMargin = doc.page.margins.bottom;
        doc.page.margins.bottom = 0;
        doc.font('CuidaDiario-Regular').fontSize(7.8).fillColor('#718096')
            .text(`CuidaDiario PRO · Constancia de aceptación · Página ${pageIndex + 1} de ${range.count}`,
                52, doc.page.height - 35, { width: 491, align: 'center', lineBreak: false });
        doc.page.margins.bottom = bottomMargin;
    }
    doc.end();
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

async function runB2BStageAContractMigrations(pool) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query("SELECT pg_advisory_xact_lock(hashtext('cuidadiario-b2b-stage-a-contract-migrations'))");
        await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations_b2b (
            version TEXT PRIMARY KEY,
            checksum CHAR(64) NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        )`);
        for (const migration of STAGE_A_CONTRACT_MIGRATIONS) {
            const checksum = sha256(migration.sql);
            const previous = await client.query(
                'SELECT checksum FROM schema_migrations_b2b WHERE version=$1 FOR UPDATE',
                [migration.version]
            );
            if (previous.rowCount > 0) {
                if (previous.rows[0].checksum !== checksum) {
                    throw new Error(`Checksum inválido para migración B2B ${migration.version}`);
                }
            } else {
                await client.query(migration.sql);
                await client.query('INSERT INTO schema_migrations_b2b (version,checksum) VALUES ($1,$2)',
                    [migration.version, checksum]);
            }
        }
        await client.query('COMMIT');
    } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw new Error(`Migraciones B2B Stage A fallaron: ${error.message}`);
    } finally {
        client.release();
    }
}

function acceptanceEvidence(row, bundle, includeContent = true) {
    const documents = {};
    for (const type of CONTRACT_TYPES) {
        const versionColumn = `${type}_version`;
        const hashColumn = `${type}_sha256`;
        const contentColumn = `${type}_content`;
        const storedContent = typeof row[contentColumn] === 'string'
            ? normalizeDocumentContent(row[contentColumn])
            : null;
        const storedContentIsExact = storedContent !== null && sha256(storedContent) === row[hashColumn];
        const document = bundle && bundle.documents[type];
        const currentContentIsExact = document && document.version === row[versionColumn]
            && document.sha256 === row[hashColumn];
        const exactContent = storedContentIsExact ? storedContent : (currentContentIsExact ? document.content : null);
        documents[type] = {
            version: row[versionColumn],
            sha256: row[hashColumn],
            content_available: exactContent !== null,
            content: includeContent ? exactContent : undefined,
        };
    }
    return {
        acceptance_event_id: row.id,
        institution_id: Number(row.institucion_id),
        authenticated_user_id: Number(row.usuario_b2b_id),
        bundle_version: row.bundle_version,
        bundle_sha256: row.bundle_sha256,
        accepted_at: row.accepted_at,
        representative: {
            name: row.representante_nombre,
            email: row.representante_email,
            capacity: row.representante_caracter,
            authority_confirmed: row.declaracion_facultades,
        },
        acceptance_statement: row.acceptance_statement,
        request_id: row.request_id,
        user_agent_sha256: row.user_agent_sha256,
        evidence_source: row.evidence_source,
        commercial_terms: row.oferta_id ? {
            offer_id: row.oferta_id,
            offer_version: row.oferta_version,
            offer_sha256: row.oferta_sha256,
            amount: String(row.importe),
            currency: row.moneda,
            billing_period: row.periodicidad,
            due_rule: row.regla_vencimiento,
            payment_method: row.medio_pago,
            valid_from: row.oferta_vigente_desde,
            valid_until: row.oferta_vigente_hasta,
        } : null,
        documents,
    };
}

function registerContractRoutes(app, dependencies) {
    const {
        pool,
        authB2BMiddleware,
        b2bP1BridgeMiddleware = (_req, _res, next) => next(),
        bundle = CURRENT_CONTRACT_BUNDLE,
        evidenceSource = 'web_authenticated',
    } = dependencies;

    app.get('/api/b2b/contracts/documents.pdf', (req, res) => {
        if (req.query.bundle_version !== bundle.version) return res.status(404).type('text/plain').send('Documentación contractual no encontrada');
        sendContractPdf(res, bundle, CONTRACT_TYPES);
    });

    app.get('/api/b2b/contracts/documents/:type.pdf', (req, res) => {
        const type = String(req.params.type || '');
        if (!CONTRACT_TYPES.includes(type) || req.query.bundle_version !== bundle.version) {
            return res.status(404).type('text/plain').send('Documento contractual no encontrado');
        }
        sendContractPdf(res, bundle, [type]);
    });

    app.get('/api/b2b/contracts/documents/:type', (req, res) => {
        const type = String(req.params.type || '');
        if (!CONTRACT_TYPES.includes(type) || req.query.bundle_version !== bundle.version) {
            return res.status(404).type('text/plain').send('Documento contractual no encontrado');
        }
        const document = bundle.documents[type];
        res.setHeader('Cache-Control', 'no-store, max-age=0');
        res.setHeader('X-Contract-Version', document.version);
        res.setHeader('X-Contract-SHA256', document.sha256);
        res.type('text/markdown; charset=utf-8').send(document.content);
    });

    app.get('/api/b2b/contracts/status', authB2BMiddleware, requirePrincipalInstitutionAdmin, async (req, res) => {
        try {
            const institutionId = req.b2bPrincipal.institucion_id;
            const acceptedResult = await pool.query(
                `SELECT * FROM contrato_aceptaciones_b2b
                 WHERE institucion_id=$1 AND bundle_version=$2
                 ORDER BY accepted_at DESC,id DESC LIMIT 1`,
                [institutionId, bundle.version]
            );
            const acceptance = acceptedResult.rows[0] || null;
            res.setHeader('Cache-Control', 'no-store, max-age=0, private');
            res.json({
                current_bundle: publicBundle(bundle),
                accepted: !!acceptance,
                acceptance: acceptance ? acceptanceEvidence(acceptance, bundle, false) : null,
                can_accept: bundle.status === 'active' && !acceptance,
                non_blocking_transition: true,
            });
        } catch (error) {
            console.error('GET /api/b2b/contracts/status:', error.code || error.message);
            res.status(500).json({ error: 'No se pudo consultar el estado contractual', code: 'CONTRACT_STATUS_FAILED' });
        }
    });

    app.post('/api/b2b/contracts/accept', b2bP1BridgeMiddleware, authB2BMiddleware, requirePrincipalInstitutionAdmin, async (req, res) => {
        try {
            if (bundle.status !== 'active') {
                throw contractError(409, 'CONTRACT_BUNDLE_NOT_ACTIVE', 'La versión contractual todavía no está habilitada para aceptación');
            }
            if (req.body?.bundle_version !== bundle.version) {
                throw contractError(409, 'CONTRACT_VERSION_STALE', 'La versión documental cambió; revisá los documentos vigentes');
            }
            if (req.body?.representation_confirmed !== true || req.body?.acceptance_statement !== ACCEPTANCE_STATEMENT) {
                throw contractError(400, 'REPRESENTATION_CONFIRMATION_REQUIRED', 'Debés confirmar expresamente la representación y la aceptación');
            }
            const capacity = String(req.body?.representative_capacity || '').trim();
            if (capacity.length < 2 || capacity.length > 160) {
                throw contractError(400, 'REPRESENTATIVE_CAPACITY_INVALID', 'Indicá el carácter con el que representás a la institución');
            }
            const principal = req.b2bPrincipal;
            const id = crypto.randomUUID();
            const requestId = requestUuid(req);
            const userAgentHash = sha256(String(req.get?.('User-Agent') || 'not-provided').slice(0, 1000));
            const client = await pool.connect();
            try {
                await client.query('BEGIN');
                await client.query("SELECT pg_advisory_xact_lock(hashtext('cuidadiario-stage-a-contract'),$1)",
                    [principal.institucion_id]);
                const current = await client.query(
                    `SELECT u.id,u.institucion_id,u.nombre,u.email,u.rol,u.activo,u.email_verified,i.activa,i.lifecycle_state
                     FROM usuarios_b2b u JOIN instituciones_b2b i ON i.id=u.institucion_id
                     WHERE u.id=$1 AND u.institucion_id=$2 FOR UPDATE OF u,i`,
                    [principal.id, principal.institucion_id]
                );
                const user = current.rows[0];
                if (!user || !user.activo || !user.email_verified || !user.activa || user.lifecycle_state === 'retained'
                    || user.rol !== 'admin_institucion') {
                    throw contractError(403, 'PRINCIPAL_ADMIN_REQUIRED', 'La cuenta principal administradora ya no está vigente');
                }
                const duplicate = await client.query(
                    `SELECT id FROM contrato_aceptaciones_b2b
                     WHERE institucion_id=$1 AND bundle_version=$2 FOR UPDATE`,
                    [principal.institucion_id, bundle.version]
                );
                if (duplicate.rowCount > 0) {
                    throw contractError(409, 'CONTRACT_ALREADY_ACCEPTED', 'Esta versión ya fue aceptada por la institución');
                }
                const inserted = await client.query(
                    `INSERT INTO contrato_aceptaciones_b2b
                     (id,institucion_id,usuario_b2b_id,bundle_version,bundle_sha256,
                      terms_version,terms_sha256,terms_content,
                      privacy_version,privacy_sha256,privacy_content,
                      dpa_version,dpa_sha256,dpa_content,
                      representante_nombre,representante_email,representante_caracter,declaracion_facultades,
                      acceptance_statement,request_id,user_agent_sha256,evidence_source)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,
                             $15,$16,$17,TRUE,$18,$19,$20,$21)
                     RETURNING *`,
                    [id, principal.institucion_id, principal.id, bundle.version, bundle.sha256,
                        bundle.documents.terms.version, bundle.documents.terms.sha256, bundle.documents.terms.content,
                        bundle.documents.privacy.version, bundle.documents.privacy.sha256, bundle.documents.privacy.content,
                        bundle.documents.dpa.version, bundle.documents.dpa.sha256, bundle.documents.dpa.content,
                        user.nombre, user.email, capacity, ACCEPTANCE_STATEMENT, requestId, userAgentHash, evidenceSource]
                );
                await client.query('COMMIT');
                res.status(201).json(acceptanceEvidence(inserted.rows[0], bundle, false));
            } catch (error) {
                await client.query('ROLLBACK').catch(() => {});
                throw error;
            } finally {
                client.release();
            }
        } catch (error) {
            if (error.code === '23505') {
                return res.status(409).json({ error: 'Esta versión ya fue aceptada por la institución', code: 'CONTRACT_ALREADY_ACCEPTED' });
            }
            res.status(error.status || 500).json({
                error: error.status ? error.message : 'No se pudo registrar la aceptación contractual',
                code: error.code || 'CONTRACT_ACCEPTANCE_FAILED',
            });
        }
    });

    async function sendEvidence(req, res, asPdf) {
        try {
            const result = await pool.query(
                `SELECT ca.*, i.nombre AS institution_name
                 FROM contrato_aceptaciones_b2b ca
                 JOIN instituciones_b2b i ON i.id=ca.institucion_id
                 WHERE ca.institucion_id=$1 ORDER BY ca.accepted_at,ca.id`,
                [req.b2bPrincipal.institucion_id]
            );
            if (asPdf) {
                return sendAcceptanceCertificatePdf(res, result.rows,
                    result.rows[0]?.institution_name, req.b2bPrincipal.institucion_id);
            }
            const payload = {
                schema: 'cuidadiario-contract-evidence/v1',
                institution_id: req.b2bPrincipal.institucion_id,
                generated_at: new Date().toISOString(),
                acceptance_count: result.rowCount,
                acceptances: result.rows.map(row => acceptanceEvidence(row,
                    row.bundle_version === bundle.version ? bundle : null)),
            };
            res.setHeader('Cache-Control', 'no-store, max-age=0, private');
            res.status(200).json(payload);
        } catch (error) {
            console.error('GET /api/b2b/contracts/evidence:', error.code || error.message);
            if (res.headersSent) return res.destroy(error);
            if (error.status) return res.status(error.status).json({ error: error.message, code: error.code });
            res.status(500).json({ error: 'No se pudo exportar la evidencia contractual', code: 'CONTRACT_EVIDENCE_FAILED' });
        }
    }

    app.get('/api/b2b/contracts/evidence', authB2BMiddleware, requirePrincipalInstitutionAdmin,
        (req, res) => sendEvidence(req, res, false));
    app.get('/api/b2b/contracts/evidence/export', authB2BMiddleware, requirePrincipalInstitutionAdmin,
        (req, res) => sendEvidence(req, res, true));

}

module.exports = {
    ACCEPTANCE_STATEMENT,
    CURRENT_BUNDLE_VERSION,
    CONTRACT_TYPES,
    STAGE_A_CONTRACT_MIGRATION,
    STAGE_A_COMMERCIAL_MIGRATION,
    STAGE_A_DOCUMENT_ONLY_MIGRATION,
    STAGE_A_CONTRACT_MIGRATIONS,
    CURRENT_CONTRACT_BUNDLE,
    ACTIVE_BUNDLE_ENV,
    normalizeDocumentContent,
    createContractBundle,
    configuredContractStatus,
    normalizeCommercialOffer,
    commercialOfferEvidence,
    createCommercialOffer,
    sha256,
    loadCurrentContractBundle,
    loadIntegratedDemoContractBundle,
    runB2BStageAContractMigrations,
    registerContractRoutes,
};
