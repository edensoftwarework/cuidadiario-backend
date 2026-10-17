# Anexo de tratamiento de datos — CuidaDiario PRO

**Versión candidata:** 2026-10-12-candidate.6  
**Estado:** CANDIDATO PENDIENTE DE APROBACIÓN HUMANA — NO ACTIVO NI ACEPTABLE

Este Anexo integra los Términos y la Política de privacidad de la misma versión. Se celebra entre **Matías Hernán Ramos**, persona humana que opera como **EDEN SoftWork**, CUIT **20-39443725-6**, domicilio contractual **Zapiola 1874, Bahía Blanca, Buenos Aires, Argentina**, contacto **edensoftwarework@gmail.com** (el **“Proveedor”**), y la institución identificada en su cuenta (la **“Institución”**).

## 1. Roles

La Institución actúa como responsable respecto de los datos que decide cargar y tratar para su gestión. El Proveedor actúa como encargado respecto de ese dominio. Un tercero que realiza parte de ese tratamiento actúa como subencargado según su función. Cada parte puede ser responsable separado de tratamientos cuyos fines determine por sí misma, como cuenta, contacto, seguridad o soporte; ello no habilita a reutilizar datos de residentes para finalidades incompatibles.

## 2. Objeto, duración y finalidades

El tratamiento tiene por objeto alojar, operar, mantener, asegurar, respaldar, recuperar, exportar y dar soporte a CuidaDiario PRO durante el servicio y la conservación que resulte aplicable. Sus finalidades son prestar funciones habilitadas, autenticar y autorizar, mantener integridad y continuidad, producir reportes y exportaciones, enviar comunicaciones transaccionales configuradas, asistir en soporte e incidentes y cumplir obligaciones aplicables.

## 3. Titulares, categorías y operaciones

Los titulares pueden incluir residentes, familiares, contactos, representantes, personal, profesionales, usuarios, operadores y contactos institucionales. Los datos pueden incluir identificación, contacto, relaciones, cobertura; datos sensibles de salud; tareas, citas, incidentes y registros operativos; identidades, roles, credenciales protegidas y sesiones; auditoría, idempotencia, exportación, aceptación contractual y metadatos técnicos.

Las operaciones comprenden recepción, almacenamiento, organización, consulta, transmisión dentro de la arquitectura informada, modificación por usuarios autorizados, respaldo, recuperación, exportación, bloqueo y eliminación controlada cuando exista una instrucción válida. La evidencia contractual no debe incorporar contenido clínico.

## 4. Instrucciones

La Institución instruye al Proveedor a tratar los datos para prestar el servicio conforme a estos documentos y a las acciones de usuarios autorizados. Las instrucciones posteriores deben provenir de un contacto autorizado y quedar documentadas. El Proveedor informará si una instrucción no puede ejecutarse de forma segura, excede las funciones disponibles o, en su criterio razonable, contradice obligaciones aplicables.

El Proveedor no aplicará los datos a fines incompatibles, no los venderá ni los cederá a terceros ajenos a la prestación salvo obligación legal. No se fabricarán instrucciones, consentimientos o aceptaciones retroactivas.

## 5. Obligaciones de la Institución

La Institución debe asegurar licitud, calidad, pertinencia y transparencia; determinar bases habilitantes; administrar usuarios y dispositivos; atender derechos; decidir conservación y supresión; determinar el carácter de sus registros clínicos; custodiar exportaciones; y comunicar cambios o incidentes relevantes. También debe evaluar la transferencia internacional y documentar el instrumento que corresponda a su rol y operación.

## 6. Obligaciones del Proveedor

El Proveedor debe seguir instrucciones documentadas; limitar accesos y exigir confidencialidad; aplicar medidas proporcionales; mantener aislamiento lógico; asistir razonablemente en derechos, incidentes, evaluaciones, exportación y finalización; informar los subencargados relevantes; y poner a disposición evidencia razonable sin exponer datos de terceros o secretos de seguridad.

El Proveedor mantendrá documentación operativa, material de recuperación separado y procedimientos de continuidad proporcionados a una operación individual. No promete personal sustituto, disponibilidad permanente ni recuperación dentro de un plazo no acordado.

## 7. Seguridad y confidencialidad

Los controles propios comprobados incluyen autenticación, contraseñas protegidas mediante hash, sesiones con expiración, permisos por rol e Institución, separación lógica, identificación de operadores secundarios, registro de las operaciones alcanzadas, protección frente a envíos repetidos donde está implementada, prevención de caché de respuestas institucionales, exportación controlada y ciclo de vida institucional.

El respaldo independiente consiste en un dump lógico completo de PostgreSQL, validado y cifrado mediante CMS/PKCS#7 antes de persistir, con manifiesto y SHA-256. Incluye adjuntos almacenados en la base. La restauración aislada local fue verificada. Se conservan generaciones diarias, semanales y mensuales según la configuración operativa. La clave de recuperación se custodia separadamente. No existe actualmente una réplica física adicional en una segunda computadora.

Las conexiones públicas observadas utilizan cifrado en tránsito. No se afirma una configuración de cifrado en reposo más allá de lo publicado por el proveedor de infraestructura o de los respaldos independientes verificados. Ningún control garantiza seguridad o disponibilidad absolutas.

## 8. Subencargados y servicios técnicos

1. **Railway Corporation.** Aloja la aplicación del servidor y PostgreSQL en Virginia, Estados Unidos. Recibe y procesa los datos alojados, incluidos datos personales y relativos a la salud, para prestar infraestructura, almacenamiento, redes, soporte y seguridad.
2. **GitHub Pages.** Entrega la interfaz web y procesa solicitudes y metadatos de red necesarios para esa función; no aloja la base institucional.
3. **Resend.** Integración condicional de correo transaccional. Si está configurada recibe los datos mínimos del mensaje, como correo, nombre o Institución y enlaces con tokens temporales. No se envía intencionalmente contenido clínico.
4. **Mercado Pago.** Integración disponible pero no operativa como medio estándar de la Institución. Sólo será subencargado efectivo si se habilita e informa su flujo.

El Proveedor informará cambios materiales cuando resulte razonablemente posible y evaluará las objeciones fundadas de la Institución. Si un servicio resulta esencial y no existe alternativa compatible inmediata, las partes coordinarán una migración o finalización ordenada.

Railway ofrece un Data Processing Addendum estándar, disponible para sus distintos planes y sujeto a firma mediante su procedimiento DocuSign. Railway informó que no modifica ni complementa ese texto y que no ofrece un instrumento adicional específico para transferencias desde Argentina. El documento no ha sido firmado para CuidaDiario PRO. Su Exhibit A declara “Sensitive Data or Special Categories of Data: None” y Railway confirmó que el acuerdo no contiene términos contractuales específicos para datos personales relativos a la salud. Las cláusulas sobre Unión Europea y Reino Unido atienden esos regímenes y no se presentan como un instrumento argentino.

Estas condiciones describen la documentación contractual disponible con el proveedor de infraestructura. No establecen por sí solas una prohibición técnica del tratamiento ni una conclusión sobre su adecuación jurídica para esta operación. Las medidas publicadas por Railway corresponden a ese proveedor; los controles gestionados directamente por EDEN SoftWork son los enumerados en la sección 7.

## 9. Transferencia internacional

El alojamiento en Estados Unidos implica una transferencia y tratamiento internacional. Estados Unidos no integra la lista publicada por la autoridad argentina de países con nivel adecuado general. La normativa argentina contempla excepciones y mecanismos adicionales, incluidas cláusulas contractuales modelo para relaciones responsable–encargado y responsable–responsable, normas corporativas vinculantes y aprobación de contratos alternativos cuando corresponda.

La Institución determina las finalidades, bases e instrucciones aplicables a su dominio. El Proveedor informa la arquitectura, limita el tratamiento a la prestación, conserva la documentación disponible y coopera razonablemente en la evaluación o instrumentación que corresponda. Cada parte cumple las obligaciones propias de su rol.

La aceptación de este Anexo no constituye una autorización universal para cualquier transferencia, no reemplaza el consentimiento cuando éste resulte exigible y no declara por sí sola satisfechos todos los requisitos aplicables. Tampoco implica una conclusión de ilicitud: el mecanismo pertinente debe evaluarse atendiendo a la operación concreta y a las alternativas previstas por la normativa.

## 10. Incidentes de seguridad

Un incidente notificable es un acceso, divulgación, alteración, pérdida o indisponibilidad no autorizada confirmada que afecte datos institucionales y pueda generar un riesgo relevante. No comprende por sí solo un incidente asistencial de un residente.

El Proveedor registrará el evento, preservará evidencia razonable, contendrá el riesgo bajo su control y notificará sin demora injustificada. Como objetivo operativo procurará emitir un aviso inicial dentro de las cuarenta y ocho horas desde que cuente con conocimiento suficiente para confirmar el incidente. El aviso podrá ser preliminar e incluir naturaleza, categorías y volumen aproximado cuando se conozcan, consecuencias posibles, medidas adoptadas y punto de contacto. Se enviarán actualizaciones proporcionadas.

El canal principal es **edensoftwarework@gmail.com** y el canal cotidiano informado puede utilizarse como respaldo. La Institución decide las notificaciones a titulares o autoridades que le correspondan; el Proveedor brindará la información disponible y cooperación razonable. La notificación no constituye por sí sola reconocimiento de responsabilidad.

## 11. Derechos y cooperación

El Proveedor canalizará a la Institución las solicitudes de titulares que reciba respecto de su dominio, salvo prohibición legal, y no responderá sustantivamente por cuenta de ella sin instrucción. Asistirá mediante consultas, correcciones, exportación y operaciones técnicas existentes, considerando naturaleza del tratamiento y seguridad de terceros.

## 12. Conservación, devolución y eliminación

Durante el servicio, los datos se conservan para las finalidades documentadas. En la finalización, el acceso puede bloquearse y la Institución dispone de treinta días corridos para solicitar la exportación disponible. La exportación no elimina datos ni es un respaldo completo.

Después de esa ventana, los datos operativos permanecen en retención restringida mientras se documenta la disposición por categoría. Los datos clínicos no se eliminan por un plazo arbitrario si la Institución debe conservarlos, pero tampoco se retienen sin una finalidad o criterio documentado. La Institución debe impartir una instrucción y señalar cualquier obligación de conservación. El Proveedor debe registrar el alcance, verificar dependencias y ejecutar sólo operaciones controladas compatibles con las capacidades vigentes.

Los usuarios y sesiones se conservan según seguridad y trazabilidad; la auditoría y evidencia contractual según integridad y defensa de derechos; los adjuntos según su registro principal; los datos de soporte sólo mientras sean necesarios; y las exportaciones no se almacenan permanentemente en el servidor. Los respaldos preexistentes se restringen a recuperación y vencen por la rotación configurada. Si se restaura uno, deben reaplicarse los estados de retención y eliminación vigentes.

## 13. Auditoría y evidencia

La Institución puede solicitar información razonable sobre medidas, subencargados, exportaciones y eventos vinculados con su dominio. La asistencia no obliga a revelar secretos de seguridad, datos de otras instituciones o material de terceros sujeto a confidencialidad. Las auditorías extraordinarias, costos y modalidad se coordinarán de buena fe y de forma proporcionada.

La aceptación registra Institución, administrador autenticado, fecha y hora del servidor, versiones, hashes SHA-256, declaración de representación, evento UUID y datos técnicos mínimos. La evidencia es append-only y exportable por administradores de la misma Institución. No prueba por sí sola la suficiencia de las facultades declaradas y no constituye firma digital certificada.

## 14. Condiciones económicas y prevalencia

La aceptación comprende exclusivamente Términos, Política de privacidad y este Anexo. No incorpora oferta, precio ni condiciones particulares. El acuerdo comercial independiente prevalece sólo respecto de sus condiciones económicas; este Anexo prevalece frente a términos generales incompatibles en materia de tratamiento por cuenta de la Institución.

## 15. Vigencia

Este Anexo rige desde una aceptación válida de una versión activa o desde otra fecha particular documentada. Mientras permanezca candidato no produce aceptación ni vigencia. Confidencialidad, conservación, evidencia y cooperación subsisten cuando por su naturaleza corresponda.
