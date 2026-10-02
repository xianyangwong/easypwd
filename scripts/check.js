import { readFile, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const extension = new URL('../extension/', import.meta.url);
const manifest = JSON.parse(await readFile(new URL('manifest.json', extension), 'utf8'));
if (manifest.manifest_version !== 3 ||
    JSON.stringify(manifest.permissions) !== JSON.stringify(['storage', 'clipboardWrite', 'activeTab', 'scripting']) ||
    manifest.host_permissions || manifest.content_scripts ||
    !manifest.content_security_policy.extension_pages.includes("connect-src 'none'")) {
  throw new Error('Unexpected extension permissions or network policy.');
}
for (const [page, script] of [['vault.html', 'app.js'], ['popup.html', 'popup.js']]) {
  const html = await readFile(new URL(page, extension), 'utf8');
  const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]);
  if (new Set(ids).size !== ids.length) throw new Error(`Duplicate HTML IDs in ${page}.`);
  const code = await readFile(new URL(script, extension), 'utf8');
  for (const [, id] of code.matchAll(/\$\('([^']+)'\)/g)) {
    if (!ids.includes(id)) throw new Error(`Missing HTML element in ${page}: ${id}`);
  }
}
for (const file of await readdir(extension)) {
  if (file.endsWith('.js')) {
    execFileSync(process.execPath, ['--check', fileURLToPath(new URL(file, extension))], { stdio: 'inherit' });
  }
}
for (const file of ['app.js', 'popup.js', 'lookup.js']) {
  if (/\b(?:fetch|XMLHttpRequest|eval)\s*\(|innerHTML\s*=/.test(await readFile(new URL(file, extension), 'utf8'))) {
    throw new Error(`Unexpected network, dynamic execution, or HTML injection API in ${file}.`);
  }
}
if (await readFile(new URL('crypto.js', extension), 'utf8') !==
    await readFile(new URL('../docs/crypto.js', import.meta.url), 'utf8')) {
  throw new Error('docs/crypto.js is out of date. Run npm run build.');
}
console.log('Extension syntax, DOM references, permissions, and network policy checked.');
