#!/usr/bin/env node
// PIN gate builder for the Vietnam 2026 itinerary.
//
//   Encrypt:   node build.mjs --pin "YOUR-SECRET"
//              reads trip.html (plaintext, git-ignored) -> writes index.html
//              (PIN lock + AES-256-GCM ciphertext), safe to publish.
//
//   Decode:    node build.mjs --decode --pin "YOUR-SECRET"
//              reads index.html -> writes trip.html (recover the source).
//
//   The PIN never appears in any published file. Content is unreadable
//   without it. Strength equals the PIN's entropy: use 12+ characters;
//   a 6-digit numeric PIN can be brute-forced offline in hours.

import { webcrypto } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const ITERATIONS = 250_000;

const args = process.argv.slice(2);
const decode = args.includes("--decode");
const pinIndex = args.indexOf("--pin");
const pin = pinIndex !== -1 ? args[pinIndex + 1] : undefined;
if (!pin) {
  console.error('Usage: node build.mjs --pin "YOUR-SECRET" [--decode]');
  process.exit(1);
}

const subtle = webcrypto.subtle;
const keyMaterial = await subtle.importKey("raw", new TextEncoder().encode(pin), "PBKDF2", false, ["deriveKey"]);
const derive = (salt) => subtle.deriveKey(
  { name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" },
  keyMaterial,
  { name: "AES-GCM", length: 256 },
  false,
  decode ? ["decrypt"] : ["encrypt"]
);

const b64 = (buf) => Buffer.from(buf).toString("base64");
const unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));

if (decode) {
  const html = readFileSync("index.html", "utf8");
  const blob = JSON.parse(html.match(/id="trip-data"[^>]*>([^<]+)<\/script>/)[1]);
  const key = await derive(unb64(blob.salt));
  const plain = await subtle.decrypt({ name: "AES-GCM", iv: unb64(blob.iv) }, key, unb64(blob.ct));
  writeFileSync("trip.html", Buffer.from(plain));
  console.log(`Decrypted index.html -> trip.html (${new Blob([plain]).size} bytes)`);
} else {
  const trip = readFileSync("trip.html", "utf8");
  const salt = webcrypto.getRandomValues(new Uint8Array(16));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const key = await derive(salt);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(trip));
  const gate = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Vietnam 2026</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20100%20100'%3E%3Ctext%20y='.9em'%20font-size='90'%3E%F0%9F%94%92%3C/text%3E%3C/svg%3E">
<style>
body { margin:0; min-height:100vh; display:grid; place-items:center; background:#f4f1ea; color:#173043; font:15px/1.5 Inter, ui-sans-serif, system-ui, -apple-system, sans-serif; }
.gate { background:#fffdf8; border:1px solid #d8c7ad; border-radius:18px; padding:34px 32px; width:min(360px, 90vw); box-shadow:0 16px 40px #15263b14; text-align:center; }
.gate h1 { font-family:Georgia, serif; font-size:26px; margin:10px 0 4px; }
.gate p { color:#63716f; margin:0 0 20px; font-size:13px; }
.gate input { width:100%; box-sizing:border-box; padding:12px 14px; border:1px solid #c8bfa4; border-radius:10px; font-size:18px; letter-spacing:.08em; text-align:center; background:#fff; color:#173043; outline:none; }
.gate input:focus { border-color:#0b665e; box-shadow:0 0 0 3px #9cc5c855; }
.gate button { margin-top:12px; width:100%; padding:12px; border:0; border-radius:10px; background:#0b665e; color:#fff; font:inherit; font-weight:800; cursor:pointer; }
.gate button:hover { filter:brightness(.94); }
.gate .error { color:#9f493d; font-size:13px; min-height:18px; margin-top:10px; }
.gate small { display:block; margin-top:16px; color:#a09884; font-size:11px; }
.shake { animation:shake .3s; }
@keyframes shake { 25% { transform:translateX(-6px); } 75% { transform:translateX(6px); } }
</style>
</head>
<body>
<div class="gate">
  <div style="font-size:34px">🔒</div>
  <h1>Vietnam 2026</h1>
  <p>Private itinerary — enter the trip secret to unlock.</p>
  <input id="pin" type="password" autocomplete="off" autofocus placeholder="Trip secret" aria-label="Trip secret">
  <button id="unlock" type="button">Unlock</button>
  <div class="error" id="err" role="alert"></div>
  <small>Content is encrypted; the secret is not stored on this site.</small>
</div>
<script id="trip-data" type="application/json">{"v":1,"iter":${ITERATIONS},"salt":"${b64(salt)}","iv":"${b64(iv)}","ct":"${b64(ct)}"}</script>
<script>
(() => {
  const blob = JSON.parse(document.getElementById('trip-data').textContent);
  const unb64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const unlock = async () => {
    const pin = document.getElementById('pin').value;
    if (!pin) return;
    try {
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']);
      const key = await crypto.subtle.deriveKey({ name:'PBKDF2', salt:unb64(blob.salt), iterations:blob.iter, hash:'SHA-256' }, material, { name:'AES-GCM', length:256 }, false, ['decrypt']);
      const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv:unb64(blob.iv) }, key, unb64(blob.ct));
      try { sessionStorage.setItem('trip-pin', pin); } catch (_) {}
      const html = new TextDecoder().decode(plain);
      document.open();
      document.write(html);
      document.close();
    } catch (_) {
      const err = document.getElementById('err');
      err.textContent = 'Wrong secret — try again.';
      const gate = document.querySelector('.gate');
      gate.classList.remove('shake');
      void gate.offsetWidth;
      gate.classList.add('shake');
    }
  };
  document.getElementById('unlock').addEventListener('click', unlock);
  document.getElementById('pin').addEventListener('keydown', (e) => { if (e.key === 'Enter') unlock(); });
  (async () => {
    let saved = null;
    try { saved = sessionStorage.getItem('trip-pin'); } catch (_) {}
    if (saved) { document.getElementById('pin').value = saved; unlock(); }
  })();
})();
</script>
</body>
</html>`;
  writeFileSync("index.html", gate);
  const kb = (Buffer.byteLength(gate) / 1024).toFixed(1);
  console.log(`Encrypted trip.html (${(trip.length / 1024).toFixed(1)} KB) -> index.html (${kb} KB incl. ciphertext). PIN is not stored anywhere.`);
}
