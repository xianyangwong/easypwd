// Uploads a zip to the Chrome Web Store and submits it for review (API v2).
// Usage: node scripts/publish-cws.js dist/easypwd-X.Y.Z.zip [--upload-only]
// Auth: CWS_SERVICE_ACCOUNT_KEY (JSON key), or CWS_CLIENT_ID + CWS_CLIENT_SECRET + CWS_REFRESH_TOKEN.
import { readFile } from 'node:fs/promises';
import { createSign } from 'node:crypto';

const [zipPath, flag] = process.argv.slice(2);
const env = process.env;
const itemId = env.CWS_EXTENSION_ID || 'dlabnhmimmbohgmbclbdagfkbibkimoa';
const scope = 'https://www.googleapis.com/auth/chromewebstore';

function fail(message) {
  console.error(`::error::${message}`);
  process.exit(1);
}

if (!zipPath) fail('Pass the zip path.');
if (!env.CWS_PUBLISHER_ID) fail('Missing CWS_PUBLISHER_ID secret.');

async function token() {
  let body;
  if (env.CWS_SERVICE_ACCOUNT_KEY) {
    const key = JSON.parse(env.CWS_SERVICE_ACCOUNT_KEY);
    const now = Math.floor(Date.now() / 1000);
    const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const unsigned = `${b64({ alg: 'RS256', typ: 'JWT' })}.${b64({
      iss: key.client_email, scope, aud: 'https://oauth2.googleapis.com/token', iat: now, exp: now + 600,
    })}`;
    const signature = createSign('RSA-SHA256').update(unsigned).sign(key.private_key, 'base64url');
    body = { grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer', assertion: `${unsigned}.${signature}` };
  } else if (env.CWS_CLIENT_ID && env.CWS_CLIENT_SECRET && env.CWS_REFRESH_TOKEN) {
    body = {
      grant_type: 'refresh_token', client_id: env.CWS_CLIENT_ID,
      client_secret: env.CWS_CLIENT_SECRET, refresh_token: env.CWS_REFRESH_TOKEN,
    };
  } else {
    fail('Set CWS_SERVICE_ACCOUNT_KEY, or CWS_CLIENT_ID, CWS_CLIENT_SECRET and CWS_REFRESH_TOKEN.');
  }
  const json = await call('https://oauth2.googleapis.com/token', { method: 'POST', body: new URLSearchParams(body) });
  return json.access_token;
}

async function call(url, options) {
  const response = await fetch(url, options);
  const text = await response.text();
  if (!response.ok) fail(`${options.method} ${url} -> ${response.status}: ${text}`);
  return text ? JSON.parse(text) : {};
}

const headers = { Authorization: `Bearer ${await token()}` };
const item = `publishers/${env.CWS_PUBLISHER_ID}/items/${itemId}`;
const api = 'https://chromewebstore.googleapis.com';

let upload = await call(`${api}/upload/v2/${item}:upload`, {
  method: 'POST', headers: { ...headers, 'Content-Type': 'application/zip' }, body: await readFile(zipPath),
});
let state = upload.uploadState;
for (let i = 0; state === 'IN_PROGRESS' && i < 30; i++) {
  await new Promise((resolve) => setTimeout(resolve, 5000));
  state = (await call(`${api}/v2/${item}:fetchStatus`, { method: 'GET', headers })).lastAsyncUploadState;
}
if (state !== 'SUCCEEDED') fail(`Upload state: ${state}. ${JSON.stringify(upload)}`);
console.log(`Uploaded ${upload.crxVersion ?? zipPath} to ${itemId}.`);

if (flag === '--upload-only') {
  console.log('Left as a draft in the Developer Dashboard.');
} else {
  const published = await call(`${api}/v2/${item}:publish`, { method: 'POST', headers });
  console.log(`Submitted for review: ${published.state}`);
}
