'use strict';

const LA4_ALERT_TYPES = Object.freeze([
    'anticoagulacion',
    'diabetes',
    'medicacion',
    'alergias',
    'alimentacion_hidratacion',
    'movilidad_caidas',
    'seguimiento_clinico',
    'cuidados_especiales',
    'personalizada',
    'otra',
]);

const LA4_MIGRATION = Object.freeze({
    version: 'la_004_alert_categories',
    sql: `
DO $$
DECLARE
    current_definition TEXT;
BEGIN
    SELECT pg_get_constraintdef(c.oid)
      INTO current_definition
      FROM pg_constraint c
      JOIN pg_class t ON t.oid=c.conrelid
      JOIN pg_namespace n ON n.oid=t.relnamespace
     WHERE n.nspname='public'
       AND t.relname='alertas_residente_b2b'
       AND c.conname='alertas_residente_b2b_tipo_check'
       AND c.contype='c';

    IF current_definition IS NULL THEN
        RAISE EXCEPTION 'LA4_ALERT_TYPE_CONSTRAINT_MISSING';
    END IF;

    IF current_definition LIKE '%alimentacion_hidratacion%'
       AND current_definition LIKE '%cuidados_especiales%'
       AND current_definition LIKE '%seguimiento_clinico%' THEN
        RETURN;
    END IF;

    IF current_definition NOT LIKE '%anticoagulacion%'
       OR current_definition NOT LIKE '%diabetes%'
       OR current_definition NOT LIKE '%personalizada%'
       OR current_definition NOT LIKE '%otra%' THEN
        RAISE EXCEPTION 'LA4_ALERT_TYPE_CONSTRAINT_DRIFT';
    END IF;

    IF EXISTS (
        SELECT 1 FROM alertas_residente_b2b
         WHERE tipo NOT IN (
            'anticoagulacion','diabetes','medicacion','alergias',
            'alimentacion_hidratacion','movilidad_caidas','seguimiento_clinico',
            'cuidados_especiales','personalizada','otra'
         )
    ) THEN
        RAISE EXCEPTION 'LA4_ALERT_TYPE_DATA_INCOMPATIBLE';
    END IF;

    ALTER TABLE alertas_residente_b2b
        DROP CONSTRAINT alertas_residente_b2b_tipo_check;
    ALTER TABLE alertas_residente_b2b
        ADD CONSTRAINT alertas_residente_b2b_tipo_check CHECK (tipo IN (
            'anticoagulacion','diabetes','medicacion','alergias',
            'alimentacion_hidratacion','movilidad_caidas','seguimiento_clinico',
            'cuidados_especiales','personalizada','otra'
        ));
END;
$$;
`,
});

module.exports = { LA4_ALERT_TYPES, LA4_MIGRATION };
