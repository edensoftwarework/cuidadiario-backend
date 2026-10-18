'use strict';

const DEFAULT_TIMEZONE = 'America/Argentina/Buenos_Aires';

const LA3_MIGRATION = Object.freeze({
    version: 'la_003_operational_reporting',
    sql: `
ALTER TABLE instituciones_b2b
    ADD COLUMN IF NOT EXISTS timezone TEXT NULL;

CREATE INDEX IF NOT EXISTS incidentes_b2b_open_dashboard_idx
    ON incidentes_b2b (institucion_id, ocurrido_at, paciente_id)
    WHERE deleted_at IS NULL AND estado IN ('abierto','en_seguimiento');
CREATE INDEX IF NOT EXISTS estados_residente_b2b_current_dashboard_idx
    ON estados_residente_b2b (institucion_id, paciente_id, iniciado_at)
    WHERE finalizado_at IS NULL;
CREATE INDEX IF NOT EXISTS historial_medicamentos_b2b_reporting_idx
    ON historial_medicamentos_b2b (institucion_id, fecha, paciente_id, resultado);
`,
});

function validTimezone(value) {
    try { new Intl.DateTimeFormat('es-AR', { timeZone:value }).format(); return value; }
    catch { return DEFAULT_TIMEZONE; }
}

function scopeSql(assignedIds, alias = 'p') {
    return assignedIds ? ` AND ${alias}.id = ANY($2)` : '';
}

async function buildOperationalAttention(pool, { institutionId, assignedIds = null, role, familyCanSee = () => false }) {
    if (role === 'familiar') return [];
    const params = assignedIds ? [institutionId, assignedIds] : [institutionId];
    const patientScope = scopeSql(assignedIds);
    const timezoneRow = await pool.query('SELECT timezone FROM instituciones_b2b WHERE id=$1', [institutionId]);
    const timezone = validTimezone(timezoneRow.rows[0]?.timezone || DEFAULT_TIMEZONE);
    const [incidents, omissions, tasks, states, stock, medications] = await Promise.all([
        pool.query(`SELECT i.id,i.paciente_id,p.nombre,p.apellido,i.categoria,i.severidad,i.ocurrido_at
            FROM incidentes_b2b i JOIN pacientes_b2b p ON p.id=i.paciente_id AND p.institucion_id=i.institucion_id
            WHERE i.institucion_id=$1 AND i.deleted_at IS NULL AND i.estado IN ('abierto','en_seguimiento')
              AND p.activo=TRUE AND p.fecha_egreso IS NULL${patientScope}
            ORDER BY i.ocurrido_at ASC LIMIT 50`, params),
        pool.query(`SELECT h.id,h.paciente_id,p.nombre,p.apellido,h.medicamento_nombre,
                   h.fecha AT TIME ZONE $${assignedIds ? 3 : 2} AS fecha,h.motivo_omision
            FROM historial_medicamentos_b2b h JOIN pacientes_b2b p ON p.id=h.paciente_id AND p.institucion_id=h.institucion_id
            WHERE h.institucion_id=$1 AND h.resultado='omitida'
              AND h.fecha >= ((now() AT TIME ZONE $${assignedIds ? 3 : 2})::date AT TIME ZONE $${assignedIds ? 3 : 2})${patientScope}
            ORDER BY h.fecha ASC LIMIT 50`, [...params, timezone]),
        pool.query(`SELECT t.id,t.paciente_id,p.nombre,p.apellido,t.titulo,
                   ((now() AT TIME ZONE $${assignedIds ? 3 : 2})::date + t.hora) AT TIME ZONE $${assignedIds ? 3 : 2} AS due_at
            FROM tareas_b2b t JOIN pacientes_b2b p ON p.id=t.paciente_id AND p.institucion_id=t.institucion_id
            WHERE t.institucion_id=$1 AND t.activa=TRUE AND t.hora IS NOT NULL
              AND p.activo=TRUE AND p.fecha_egreso IS NULL${patientScope}
              AND t.hora < (now() AT TIME ZONE $${assignedIds ? 3 : 2})::time
              AND NOT EXISTS (SELECT 1 FROM historial_tareas_b2b h WHERE h.institucion_id=t.institucion_id
                  AND h.tarea_id=t.id AND (h.fecha AT TIME ZONE $${assignedIds ? 3 : 2})::date=(now() AT TIME ZONE $${assignedIds ? 3 : 2})::date)
            ORDER BY due_at ASC LIMIT 50`, [...params, timezone]),
        pool.query(`SELECT e.id,e.paciente_id,p.nombre,p.apellido,e.tipo,e.iniciado_at,e.motivo
            FROM estados_residente_b2b e JOIN pacientes_b2b p ON p.id=e.paciente_id AND p.institucion_id=e.institucion_id
            WHERE e.institucion_id=$1 AND e.finalizado_at IS NULL AND e.tipo IN ('internado','salida_medica','salida_familiar','otro')
              AND p.activo=TRUE AND p.fecha_egreso IS NULL${patientScope}
            ORDER BY e.iniciado_at ASC LIMIT 50`, params),
        pool.query(`SELECT x.* FROM (
            SELECT m.id,m.paciente_id,p.nombre AS paciente_nombre,p.apellido AS paciente_apellido,m.nombre,m.stock,NULL::integer AS minimo,'individual'::text AS tipo
              FROM medicamentos_b2b m JOIN pacientes_b2b p ON p.id=m.paciente_id AND p.institucion_id=m.institucion_id
             WHERE m.institucion_id=$1 AND m.activo=TRUE AND m.catalogo_id IS NULL AND m.stock IS NOT NULL AND m.stock<10${patientScope}
            UNION ALL
            SELECT c.id,c.paciente_id,p.nombre,p.apellido,c.nombre,c.stock_actual,c.stock_minimo,
                   CASE WHEN c.paciente_id IS NULL THEN 'institucional' ELSE 'catalogo_paciente' END
              FROM catalogo_medicamentos_b2b c LEFT JOIN pacientes_b2b p ON p.id=c.paciente_id AND p.institucion_id=c.institucion_id
             WHERE c.institucion_id=$1 AND c.stock_actual IS NOT NULL AND c.stock_actual<=COALESCE(c.stock_minimo,5)
               ${assignedIds ? 'AND (c.paciente_id IS NULL OR p.id=ANY($2))' : ''}
            ) x ORDER BY stock ASC LIMIT 50`, params),
        pool.query(`SELECT m.id,m.paciente_id,p.nombre,p.apellido,m.nombre AS medicamento_nombre,s.hora,
                   (((now() AT TIME ZONE $${assignedIds ? 3 : 2})::date + s.hora::time) AT TIME ZONE $${assignedIds ? 3 : 2}) AS due_at
            FROM medicamentos_b2b m JOIN pacientes_b2b p ON p.id=m.paciente_id AND p.institucion_id=m.institucion_id
            CROSS JOIN LATERAL jsonb_array_elements_text(m.horarios_programados) s(hora)
            WHERE m.institucion_id=$1 AND m.activo=TRUE AND p.activo=TRUE AND p.fecha_egreso IS NULL${patientScope}
              AND jsonb_typeof(m.horarios_programados)='array' AND s.hora ~ '^(?:[01][0-9]|2[0-3]):[0-5][0-9]$'
              AND (m.vigente_desde IS NULL OR m.vigente_desde<=now()) AND (m.vigente_hasta IS NULL OR m.vigente_hasta>=now())
              AND (((now() AT TIME ZONE $${assignedIds ? 3 : 2})::date + s.hora::time) AT TIME ZONE $${assignedIds ? 3 : 2}) <= now()
              AND NOT EXISTS (SELECT 1 FROM historial_medicamentos_b2b h WHERE h.institucion_id=m.institucion_id
                 AND h.medicamento_id=m.id AND h.programada_para IS NOT NULL
                 AND date_trunc('minute',h.programada_para)=date_trunc('minute',(((now() AT TIME ZONE $${assignedIds ? 3 : 2})::date+s.hora::time) AT TIME ZONE $${assignedIds ? 3 : 2})))
            ORDER BY due_at ASC LIMIT 50`, [...params, timezone]),
    ]);

    const patient = row => ({ paciente_id:Number(row.paciente_id), paciente_nombre:`${row.nombre || row.paciente_nombre || ''} ${row.apellido || row.paciente_apellido || ''}`.trim() });
    const items = [
        ...incidents.rows.map(r => ({ tipo:'incidente_abierto', prioridad:r.severidad==='critica'?'critica':'alta', ocurrido_at:r.ocurrido_at, titulo:`Incidente: ${r.categoria}`, detalle:`Estado abierto · severidad ${r.severidad}`, source:'registrado', ...patient(r) })),
        ...omissions.rows.map(r => ({ tipo:'omision_medicacion', prioridad:'alta', ocurrido_at:r.fecha, titulo:`Omisión: ${r.medicamento_nombre || 'medicación'}`, detalle:r.motivo_omision || 'Motivo registrado', source:'registrado', ...patient(r) })),
        ...tasks.rows.map(r => ({ tipo:'tarea_vencida', prioridad:'media', ocurrido_at:r.due_at, titulo:`Tarea vencida: ${r.titulo}`, detalle:'Vencimiento calculado para hoy; sin finalización registrada.', source:'calculado', ...patient(r) })),
        ...states.rows.map(r => ({ tipo:'estado_temporal', prioridad:r.tipo==='internado'?'alta':'media', ocurrido_at:r.iniciado_at, titulo:r.tipo==='internado'?'Residente internado':'Residente temporalmente ausente', detalle:r.motivo || r.tipo.replaceAll('_',' '), source:'registrado', ...patient(r) })),
        ...stock.rows.map(r => ({ tipo:'stock_critico', prioridad:Number(r.stock)<=0?'critica':'alta', ocurrido_at:null, titulo:`Stock crítico: ${r.nombre}`, detalle:`Stock ${r.stock}${r.minimo!=null?` · mínimo ${r.minimo}`:''}`, source:'estado_actual', ...(r.paciente_id ? patient(r) : { paciente_id:null,paciente_nombre:null }) })),
        ...medications.rows.map(r => ({ tipo:'medicacion_vencida', prioridad:'alta', ocurrido_at:r.due_at, titulo:`Medicación vencida: ${r.medicamento_nombre}`, detalle:'Vencimiento calculado desde esquema vigente, horario y zona horaria; no equivale a una omisión registrada.', source:'calculado', ...patient(r) })),
    ];
    const rank = { critica:0, alta:1, media:2, baja:3 };
    return items.sort((a,b) => (rank[a.prioridad]-rank[b.prioridad]) || (new Date(a.ocurrido_at||0)-new Date(b.ocurrido_at||0))).slice(0,100);
}

function registerLA3Routes(app, { pool, authB2BMiddleware, checkB2BCanDo }) {
    app.get('/api/b2b/dashboard/direccion', authB2BMiddleware, async (req,res) => {
        try {
            if (!checkB2BCanDo(req.b2bUser,'ver_dashboard_direccion')) return res.status(403).json({ error:'Sin permiso para ver el dashboard de Dirección',code:'FORBIDDEN' });
            const granularidad = req.query.granularidad || 'mes';
            if (!['semana','mes'].includes(granularidad)) return res.status(400).json({ error:'granularidad inválida',code:'INVALID_GRANULARITY' });
            const hasta = req.query.hasta ? new Date(req.query.hasta) : new Date();
            const desde = req.query.desde ? new Date(req.query.desde) : new Date(hasta.getTime()-90*86400000);
            if (!Number.isFinite(desde.getTime()) || !Number.isFinite(hasta.getTime()) || desde>=hasta) return res.status(400).json({ error:'Período inválido',code:'INVALID_PERIOD' });
            const iid=req.b2bUser.institucion_id;
            const tzRow=await pool.query('SELECT timezone FROM instituciones_b2b WHERE id=$1',[iid]);
            const timezone=validTimezone(tzRow.rows[0]?.timezone||DEFAULT_TIMEZONE);
            const p=[iid,desde.toISOString(),hasta.toISOString(),timezone];
            const periodParams=p.slice(0,3);
            const [occupancy,movements,incidents,states,omissions,currentTasks,currentStock]=await Promise.all([
                pool.query(`SELECT COUNT(*) FILTER (WHERE activo=TRUE AND fecha_egreso IS NULL)::int AS ocupados FROM pacientes_b2b WHERE institucion_id=$1`,[iid]),
                pool.query(`SELECT COUNT(*) FILTER (WHERE fecha_ingreso >= ($2::timestamptz AT TIME ZONE $4)::date AND fecha_ingreso < ($3::timestamptz AT TIME ZONE $4)::date)::int ingresos,
                    COUNT(*) FILTER (WHERE fecha_egreso >= ($2::timestamptz AT TIME ZONE $4)::date AND fecha_egreso < ($3::timestamptz AT TIME ZONE $4)::date)::int egresos FROM pacientes_b2b WHERE institucion_id=$1`,p),
                pool.query(`SELECT categoria,COUNT(*)::int total FROM incidentes_b2b WHERE institucion_id=$1 AND deleted_at IS NULL AND ocurrido_at >= $2 AND ocurrido_at < $3 GROUP BY categoria ORDER BY categoria`,periodParams),
                pool.query(`SELECT tipo,COUNT(*)::int total FROM estados_residente_b2b WHERE institucion_id=$1 AND iniciado_at >= $2 AND iniciado_at < $3 AND tipo IN ('internado','salida_medica') GROUP BY tipo`,periodParams),
                pool.query(`SELECT COUNT(*)::int total FROM historial_medicamentos_b2b WHERE institucion_id=$1 AND resultado='omitida' AND fecha >= $2 AND fecha < $3`,periodParams),
                pool.query(`SELECT COUNT(*)::int total FROM tareas_b2b t JOIN pacientes_b2b p ON p.id=t.paciente_id AND p.institucion_id=t.institucion_id WHERE t.institucion_id=$1 AND t.activa=TRUE AND t.hora IS NOT NULL AND p.activo=TRUE AND p.fecha_egreso IS NULL AND t.hora<(now() AT TIME ZONE $2)::time AND NOT EXISTS (SELECT 1 FROM historial_tareas_b2b h WHERE h.institucion_id=t.institucion_id AND h.tarea_id=t.id AND (h.fecha AT TIME ZONE $2)::date=(now() AT TIME ZONE $2)::date)`,[iid,timezone]),
                pool.query(`SELECT COUNT(*)::int total FROM (SELECT id FROM medicamentos_b2b WHERE institucion_id=$1 AND activo=TRUE AND catalogo_id IS NULL AND stock IS NOT NULL AND stock<10 UNION ALL SELECT id FROM catalogo_medicamentos_b2b WHERE institucion_id=$1 AND stock_actual IS NOT NULL AND stock_actual<=COALESCE(stock_minimo,5)) s`,[iid]),
            ]);
            const category=Object.fromEntries(incidents.rows.map(r=>[r.categoria,Number(r.total)]));
            const state=Object.fromEntries(states.rows.map(r=>[r.tipo,Number(r.total)]));
            res.json({ actualizado_en:new Date().toISOString(),periodo:{desde:desde.toISOString(),hasta:hasta.toISOString(),granularidad,timezone},
                estado_actual:{ocupacion:{valor:Number(occupancy.rows[0].ocupados),unidad:'residentes',porcentaje:null,estado:'parcial',explicacion:'La base conserva residentes ocupando plaza, pero no una capacidad institucional canónica; el porcentaje no está disponible.'},tareas_vencidas:{valor:Number(currentTasks.rows[0].total),unidad:'tareas',referencia:'ahora',estado:'disponible'},stock_critico:{valor:Number(currentStock.rows[0].total),unidad:'ítems',referencia:'ahora',estado:'disponible'}},
                historicos:{ingresos:{valor:Number(movements.rows[0].ingresos),unidad:'residentes'},egresos:{valor:Number(movements.rows[0].egresos),unidad:'residentes'},incidentes_por_categoria:category,caidas:{valor:category.caida||0,unidad:'incidentes'},internaciones:{valor:state.internado||0,unidad:'eventos'},derivaciones:{valor:category.derivacion||0,unidad:'incidentes'},omisiones_medicacion:{valor:Number(omissions.rows[0].total),unidad:'registros'},tareas_vencidas:{valor:null,estado:'no_disponible',explicacion:'No existe una ocurrencia programada histórica por tarea; no se reconstruyen incumplimientos pasados.'},stock_critico:{valor:null,estado:'no_disponible',explicacion:'El modelo conserva stock actual, no snapshots históricos.'}},
                definiciones:{limites:'desde inclusivo; hasta exclusivo',ocupacion:'Residentes activos sin fecha de egreso al momento de consulta.',ingresos_egresos:'Fechas de ingreso/egreso dentro del período civil institucional.',incidentes:'Incidentes no archivados por ocurrido_at.',omisiones:'Registros explícitos con resultado omitida; nunca se infieren por ausencia de toma.'}});
        } catch(error) { console.error('GET /api/b2b/dashboard/direccion:',error.message); res.status(500).json({error:'Error al obtener dashboard de Dirección'}); }
    });
}

module.exports={LA3_MIGRATION,DEFAULT_TIMEZONE,buildOperationalAttention,registerLA3Routes,validTimezone};
