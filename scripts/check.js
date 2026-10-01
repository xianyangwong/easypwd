import { readFile, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const extension = new URL('../extension/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('manifest.json', extension), 'utf8'));
if (manifest.manifest_version !== 3 ||
    JSON.stringify(manifest.permissions) !== JSON.stringify(['storage', 'clipboardWrite']) ||
    manifest.host_permissions || manifest.content_scripts ||
    !manifest.content_security_policy.extension_pages.includes("connect-src 'none'")) {
  throw new Error('Unexpected extension permissions or network policy.');
}
const html = await readFile(new URL('vault.html', extension), 'utf8');
const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
if (new Set(ids).size !== ids.length) throw new Error('Duplicate HTML IDs.');
const app = await readFile(new URL('app.js', extension), 'utf8');
for (const [, id] of app.matchAll(/\$\('([^']+)'\)/g)) {
  if (!ids.includes(id)) throw new Error(`Missing HTML element: ${id}`);
}
for (const file of await readdir(extension)) {
  if (file.endsWith('.js')) {
    execFileSync(process.execPath, ['--check', fileURLToPath(new URL(file, extension))], { stdio: 'inherit' });
  }
}
if (/\b(?:fetch|XMLHttpRequest|eval)\s*\(|innerHTML\s*=/.test(app)) {
  throw new Error('Unexpected network, dynamic execution, or HTML injection API.');
}
if (await readFile(new URL('crypto.js', extension), 'utf8') !==
    await readFile(new URL('../docs/crypto.js', import.meta.url), 'utf8')) {
  throw new Error('docs/crypto.js is out of date. Run npm run build.');
}
console.log('Extension syntax, DOM references, permissions, and network policy checked.');
