// Verschlüsselt src/index.html mit einem Passwort und schreibt das Ergebnis nach index.html.
// Aufruf:  node tools/encrypt.mjs "PASSWORT"
// Das Passwort wird nirgends gespeichert; src/ ist per .gitignore vom Repo ausgeschlossen.
import { readFileSync, writeFileSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const password = process.argv[2];
if (!password) {
    console.error('Bitte Passwort angeben: node tools/encrypt.mjs "PASSWORT"');
    process.exit(1);
}

const ITERATIONS = 600000;
const plaintext = readFileSync(join(root, 'src/index.html'), 'utf8');
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const baseKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
);
const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext)));

const b64 = (u8) => Buffer.from(u8).toString('base64');
const payload = JSON.stringify({ s: b64(salt), i: b64(iv), c: b64(cipher), n: ITERATIONS });

const template = readFileSync(join(root, 'tools/gate.html'), 'utf8');
writeFileSync(join(root, 'index.html'), template.replace('__PAYLOAD__', () => payload));
console.log('index.html geschrieben (' + Math.round(cipher.length / 1024) + ' KB verschlüsselt).');
