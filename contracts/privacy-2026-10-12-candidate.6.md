# Política de privacidad de CuidaDiario PRO

**Versión candidata:** 2026-10-12-candidate.6  
**Estado:** CANDIDATO PENDIENTE DE APROBACIÓN HUMANA — NO ACTIVO NI ACEPTABLE  
**Proveedor:** **Matías Hernán Ramos**, persona humana, nombre comercial **EDEN SoftWork**, CUIT **20-39443725-6**, domicilio contractual **Zapiola 1874, Bahía Blanca, Buenos Aires, Argentina**  
**Contacto de privacidad e incidentes:** **edensoftwarework@gmail.com**

## 1. Alcance

Esta Política describe el tratamiento de datos personales asociado al servicio institucional CuidaDiario PRO. No alcanza otros productos del Proveedor. La aplicación es una herramienta operativa y de registro; no se presenta por sí sola como historia clínica electrónica oficial ni sustituye las decisiones asistenciales y documentales de cada Institución.

## 2. Datos tratados

Según las funciones utilizadas, pueden tratarse:

- datos de la Institución y sus contactos;
- identidad, contacto, rol, permisos, credenciales protegidas y sesiones de usuarios y operadores;
- identificación, contacto, relaciones, cobertura y datos administrativos de residentes, familiares y representantes;
- datos sensibles de salud, como antecedentes, diagnósticos, alergias, medicación y administraciones, síntomas, signos vitales, incidentes, notas, evoluciones y documentos;
- tareas, citas, inventario, reportes y exportaciones;
- metadatos de seguridad, auditoría, soporte, continuidad, idempotencia y aceptación contractual.

Las contraseñas se almacenan mediante hash; no se conservan en texto plano. La evidencia contractual contiene Institución, administrador autenticado, fecha, versiones, huellas SHA-256, declaración y textos aceptados, pero no datos clínicos de residentes.

## 3. Roles y finalidades

La Institución determina finalidades, autorizaciones, accesos y conservación respecto de su dominio y actúa como responsable. El Proveedor trata esos datos para prestar, mantener, asegurar, respaldar y alojar el servicio conforme a instrucciones y actúa como encargado. Cada parte puede ser responsable separado de tratamientos cuyos fines determine por sí misma, como datos de cuenta, contacto, seguridad o soporte.

Los datos se procesan para operar funciones habilitadas; autenticar y autorizar; generar reportes y exportaciones solicitadas; enviar comunicaciones transaccionales configuradas; preservar integridad y continuidad; registrar operaciones; brindar soporte e investigar incidentes; administrar la relación contractual; y cumplir obligaciones aplicables. El Proveedor no utiliza datos de residentes para publicidad, venta o finalidades comerciales propias ajenas al servicio.

## 4. Responsabilidades de la Institución

La Institución debe determinar las bases habilitantes aplicables, informar a residentes o representantes, administrar permisos, mantener datos pertinentes y actualizados, atender derechos y decidir conservación o supresión. El consentimiento no es necesariamente la única base posible y debe evaluarse según el tratamiento y las obligaciones institucionales.

## 5. Infraestructura y servicios técnicos

- **Railway Corporation:** alojamiento efectivo de la aplicación del servidor y PostgreSQL en Virginia, Estados Unidos. Procesa técnicamente la información institucional alojada, incluidos datos personales y de salud cuando la Institución los incorpora.
- **GitHub Pages:** publicación de la interfaz web. No contiene la base institucional, pero puede procesar solicitudes y metadatos de red necesarios para entregar el sitio.
- **Resend:** integración condicional de correo transaccional. Cuando está configurada puede recibir correo, nombre o Institución incluidos en el mensaje y enlaces con tokens temporales. No se envía intencionalmente contenido clínico.
- **Mercado Pago:** integración disponible en el software, actualmente no habilitada como medio de pago institucional estándar. Sólo intervendrá si el flujo se activa y se informa expresamente.

La participación efectiva depende de la configuración y las funciones utilizadas. No se atribuyen a terceros ubicaciones, garantías o plazos distintos de los documentados.

## 6. Tratamiento internacional

Railway aloja la aplicación del servidor y PostgreSQL en Virginia, Estados Unidos. Por ello, los datos necesarios para prestar CuidaDiario PRO, incluidos datos relativos a la salud, se almacenan y procesan en ese país. Estados Unidos no figura en la lista general de destinos adecuados publicada por la autoridad argentina.

La Institución determina las finalidades y bases aplicables a los datos de su dominio. El Proveedor mantiene informada la arquitectura, limita el tratamiento a la prestación y coopera con la documentación razonablemente disponible. Las partes deben atender las reglas de transferencia que correspondan a sus respectivos roles. La aceptación institucional de estos documentos no sustituye por sí sola un consentimiento individual ni cualquier otro instrumento exigible.

Railway ofrece un anexo estándar de tratamiento sujeto a firma mediante su procedimiento previsto. Ese anexo no ha sido firmado para CuidaDiario PRO y no contiene términos específicos para datos relativos a la salud ni un instrumento adicional propio para transferencias desde Argentina. Esta descripción informa el marco contractual actualmente disponible sin formular una conclusión sobre la licitud de la operación. El detalle de subencargados y cooperación se desarrolla en el Anexo de tratamiento de datos.

## 7. Seguridad

Los controles propios vigentes incluyen conexión cifrada en los accesos públicos observados, autenticación, sesiones con expiración, contraseñas protegidas mediante hash, permisos por rol e Institución, separación lógica, registro de las operaciones alcanzadas, ausencia de caché de respuestas institucionales en el navegador, protección frente a envíos repetidos donde está implementada, exportación controlada y proceso de finalización institucional.

El Proveedor conserva respaldos lógicos cifrados fuera de Railway mediante un procedimiento automatizado local con manifiesto e integridad, y verificó una restauración aislada. El respaldo incluye la base compartida y los adjuntos almacenados en ella. No existe actualmente una réplica física adicional en una segunda computadora. Las medidas publicadas por Railway son propias de ese proveedor y no se presentan como controles operados directamente por EDEN SoftWork.

Ningún sistema garantiza seguridad o disponibilidad absolutas. La Institución debe administrar usuarios, dispositivos, credenciales y archivos descargados.

## 8. Conservación por categoría

La conservación se determina de forma diferenciada:

- **Datos clínicos y operativos de residentes:** durante el servicio y, al finalizar, en acceso bloqueado mientras la Institución define una instrucción compatible con sus obligaciones de conservación. No se aplica una purga automática indiscriminada.
- **Usuarios, roles y sesiones:** durante la relación y el tiempo necesario para seguridad, cierre de accesos y trazabilidad. Las sesiones pueden expirar o revocarse antes.
- **Auditoría e idempotencia:** según su finalidad de integridad, seguridad y reconstrucción; la auditoría alcanzada es append-only y no se utiliza para reactivar datos archivados.
- **Adjuntos:** siguen el ciclo del registro institucional al que pertenecen y se incluyen cuando están disponibles en exportaciones y respaldos.
- **Exportaciones:** se generan a pedido y no se conservan como archivo descargable permanente en el servidor; la copia descargada queda bajo custodia de la Institución.
- **Respaldos:** siguen la rotación técnica configurada en generaciones diarias, semanales y mensuales. No se editan para borrar una fila individual; se restringen a recuperación y vencen por rotación.
- **Soporte:** se conserva sólo el tiempo necesario para atender y documentar la consulta, evitando incorporar contenido clínico cuando no sea necesario.
- **Evidencia contractual:** se conserva con los textos, versiones y huellas aceptados para demostrar la relación y no se elimina mediante operaciones ordinarias.

## 9. Exportación, finalización y eliminación

Un administrador autorizado puede generar una exportación institucional comprimida con formatos estructurados, vistas tabulares, documentos disponibles, registro de operaciones y manifiesto con huellas de integridad. No es una migración automática ni un respaldo completo de PostgreSQL.

El proceso de finalización puede bloquear el acceso y mantener los datos en retención. Durante treinta días corridos puede solicitarse la exportación disponible. Vencida esa ventana, los datos operativos continúan protegidos y sin uso ordinario hasta documentar la disposición de cada categoría.

La eliminación requiere una instrucción institucional válida o un criterio aplicable documentado, verificación de alcance y una operación controlada; no se activa por silencio ni se ejecuta automáticamente. Cuando una categoría deba conservarse, se limita su acceso. Cuando proceda eliminarla, los respaldos preexistentes permanecen restringidos hasta vencer por su rotación y cualquier restauración debe reaplicar el estado de eliminación. Este procedimiento evita tanto una eliminación clínica arbitraria como una retención indefinida sin finalidad documentada.

## 10. Derechos

Los titulares pueden ejercer los derechos reconocidos por la normativa aplicable, incluidos acceso, rectificación, actualización y supresión cuando corresponda. Las solicitudes sobre datos administrados por una Institución deben dirigirse primero a su contacto. El Proveedor canalizará las que reciba y asistirá razonablemente. La supresión puede limitarse o diferirse por conservación aplicable, derechos de terceros u otra excepción válida.

## 11. Navegador y dispositivos

La interfaz usa almacenamiento del navegador para sesión y preferencias. Las respuestas de consulta institucional no se escriben ni recuperan desde almacenamiento local ni desde la caché de respuestas del navegador. Las descargas pueden permanecer en dispositivos o servicios de sincronización bajo control de la Institución o usuario. No se utilizan cookies de publicidad comportamental.

## 12. Incidentes de seguridad

Un incidente notificable es un acceso, divulgación, alteración, pérdida o indisponibilidad no autorizada confirmada que afecte datos institucionales y pueda generar un riesgo relevante. No es lo mismo que un incidente asistencial registrado en la ficha de un residente.

El canal principal es **edensoftwarework@gmail.com**; el canal cotidiano informado puede utilizarse como respaldo para alertar sobre la comunicación. El Proveedor informará sin demora injustificada y procurará un aviso inicial dentro de las cuarenta y ocho horas desde que cuente con conocimiento suficiente para confirmar el incidente. El aviso puede ser preliminar e incluir naturaleza, categorías afectadas, alcance conocido, medidas iniciales y contacto; se actualizará a medida que avance la investigación. La Institución decide y realiza las notificaciones que le correspondan como responsable.

## 13. Cambios

Los cambios materiales se comunicarán con antelación razonable y podrán requerir una nueva aceptación institucional. La continuidad de uso no sustituye una formalidad exigible ni crea aceptación retroactiva. Las versiones y evidencias anteriores permanecen conservadas.
