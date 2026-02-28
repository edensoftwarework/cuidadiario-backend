#!/usr/bin/env node
/**
 * setup-vapid.js — Genera las claves VAPID necesarias para las notificaciones push
 * by EDEN SoftWork
 *
 * Las claves VAPID son el "permiso" que el navegador necesita para confiar en
 * los pushes del servidor. Sin ellas, las notificaciones NO llegan con la app cerrada.
 *
 * ── USO ──────────────────────────────────────────────────────────────────────
 *
 *   1. Abrí una terminal en la carpeta del BACKEND (donde está index-COMPLETE.js)
 *   2. Asegurate de tener web-push instalado:
 *        npm install web-push
 *   3. Ejecutá este script:
 *        node setup-vapid.js
 *   4. Copiá las 3 variables que aparecen en pantalla
 *   5. Pegálas en Railway → Tu proyecto → Variables (Environment Variables)
 *   6. Re-deploiá el backend en Railway (lo hace automático al guardar)
 *   7. En el celular: abrí la app, andá a Configuración (⚙) → Notificaciones push
 *      → Desactivar y volver a Activar (para re-crear la suscripción con las nuevas claves)
 *
 * ── IMPORTANTE ───────────────────────────────────────────────────────────────
 *   • Generá las claves UNA sola vez. Si las cambiás, todos los dispositivos
 *     suscritos necesitarán re-activar las notificaciones manualmente.
 *   • La VAPID_PRIVATE_KEY es secreta — no la compartas ni la subas a GitHub.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 */

try {
    const webPush = require('web-push');
    const keys = webPush.generateVAPIDKeys();

    console.log('\n✅  VAPID Keys generadas exitosamente\n');
    console.log('━'.repeat(60));
    console.log('Copiá estas 3 líneas en Railway → Variables de entorno:\n');
    console.log(`VAPID_PUBLIC_KEY=${keys.publicKey}`);
    console.log(`VAPID_PRIVATE_KEY=${keys.privateKey}`);
    console.log(`VAPID_EMAIL=mailto:edensoftwarework@gmail.com`);
    console.log('━'.repeat(60));
    console.log('\n⚠️  Guardá VAPID_PRIVATE_KEY de forma segura (no la subas a GitHub).');
    console.log('   Después de configurar Railway, re-activá notificaciones en cada dispositivo.\n');
} catch (e) {
    if (e.code === 'MODULE_NOT_FOUND') {
        console.error('\n❌  web-push no está instalado.');
        console.error('   Ejecutá primero:  npm install web-push');
        console.error('   (desde la carpeta del backend)\n');
    } else {
        console.error('Error inesperado:', e.message);
    }
    process.exit(1);
}
