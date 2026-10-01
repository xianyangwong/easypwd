import { validateEntries } from './crypto.js';

export const MAX_IMPORT_BYTES = 5_000_000;

// RFC 4180 CSV: quoted fields may contain commas, quotes ("") and newlines.
export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < text.length; i += 1) {
    const character = text[i];
    if (quoted) {
      if (character !== '"') field += character;
      else if (text[i + 1] === '"') { field += '"'; i += 1; } else quoted = false;
    } else if (character === '"' && field === '') {
      quoted = true;
    } else if (character === ',') {
      row.push(field);
      field = '';
    } else if (character === '\n' || character === '\r') {
      if (character === '\r' && text[i + 1] === '\n') i += 1;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else {
      field += character;
    }
  }
  if (quoted) throw new Error('The CSV file is malformed (unclosed quote).');
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((cells) => cells.some((cell) => cell !== ''));
}

function httpUrl(value) {
  try {
    const url = new URL(value);
    return ['http:', 'https:'].includes(url.protocol) && !url.username && !url.password ? url : null;
  } catch {
    return null;
  }
}

// Google Password Manager export: name,url,username,password[,note]
export function entriesFromChromeCsv(text, now = Date.now()) {
  if (text.length > MAX_IMPORT_BYTES) throw new Error('The CSV file is larger than 5 MB.');
  const [header = [], ...rows] = parseCsv(text.replace(/^\uFEFF/, ''));
  const columns = header.map((name) => name.trim().toLowerCase());
  const index = (name) => columns.indexOf(name);
  if (['name', 'url', 'username', 'password'].some((name) => index(name) < 0)) {
    throw new Error('This isn’t a Chrome password export. Expected columns: name, url, username, password.');
  }
  const entries = [];
  let skipped = 0;
  for (const row of rows) {
    const cell = (name) => (index(name) < 0 ? '' : row[index(name)] ?? '');
    const url = httpUrl(cell('url').trim());
    const entry = {
      id: crypto.randomUUID(),
      name: cell('name').trim() || url?.hostname || cell('username') || 'Imported login',
      url: url ? url.href : '',
      username: cell('username'),
      password: cell('password'),
      notes: cell('note'),
      updatedAt: now,
    };
    try {
      validateEntries([entry]);
      entries.push(entry);
    } catch {
      skipped += 1;
    }
  }
  return { entries, skipped };
}
