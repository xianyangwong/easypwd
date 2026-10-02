import { DEFAULT_RULES, derivePassword, normalizeSite, totp } from './crypto.js';

// The site a login belongs to: its generated-password site, or its website's host.
export function entrySite(entry) {
  if (entry.derive) return entry.derive.site;
  try { return normalizeSite(new URL(entry.url).hostname); } catch { return ''; }
}

// "accounts.google.com" matches a login for "google.com", and the other way round.
export function siteMatches(site, host) {
  if (!site || !host || !site.includes('.')) return false;
  return site === host || host.endsWith(`.${site}`) || site.endsWith(`.${host}`);
}

// A best guess at the site name to generate for, without a public-suffix list:
// "accounts.google.com" → "google.com", "www.bbc.co.uk" → "bbc.co.uk".
export function guessSite(host) {
  const labels = host.split('.');
  if (labels.length <= 2 || /^\d+$/.test(labels.at(-1))) return host;
  const secondLevel = labels.at(-1).length === 2 && /^(?:co|com|net|org|gov|edu|ac|or|ne|go)$/.test(labels.at(-2));
  return labels.slice(secondLevel ? -3 : -2).join('.');
}

export async function lookup({ entries, siteKey }, { host, site }) {
  const matches = await Promise.all(entries
    .filter((entry) => siteMatches(entrySite(entry), host))
    .sort((a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' }))
    .slice(0, 20)
    .map(async (entry) => ({
      id: entry.id,
      name: entry.name,
      username: entry.username,
      generated: !!entry.derive,
      password: entry.derive ? await derivePassword(siteKey, entry.derive) : entry.password,
      otp: entry.otp ? await totp(entry.otp) : null,
    })));
  const suggestSite = normalizeSite(site || guessSite(host));
  const suggestion = suggestSite ?
    { site: suggestSite, password: await derivePassword(siteKey, { site: suggestSite, counter: 1, ...DEFAULT_RULES }) } :
    null;
  return { matches, suggestion };
}
