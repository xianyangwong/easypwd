import { DEFAULT_RULES, derivePassword, normalizeSite, totp, validRules } from './crypto.js';

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

// Characters and pairs phishing domains swap in for others ("paypa1", "rnicrosoft").
const SKELETON = [[/rn/g, 'm'], [/vv/g, 'w'], [/cl/g, 'd'], [/[0]/g, 'o'], [/[1il|]/g, 'l'], [/5/g, 's'], [/3/g, 'e'], [/-/g, '']];
const skeleton = (label) => SKELETON.reduce((text, [from, to]) => text.replace(from, to), label);

function editDistance(a, b) {
  if (Math.abs(a.length - b.length) > 2) return 3;
  let row = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    const next = [i];
    for (let j = 1; j <= b.length; j += 1) {
      next[j] = Math.min(row[j] + 1, next[j - 1] + 1, row[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    row = next;
  }
  return row[b.length];
}

// A saved site this host imitates, e.g. "paypa1.com", "paypal-login.com", or "paypal.com.evil.net"
// for a login saved for "paypal.com". Offline and heuristic: a hint, never a guarantee.
export function lookalikeOf(host, sites) {
  if (!host.includes('.') || sites.some((site) => siteMatches(site, host))) return null;
  const hostSite = guessSite(host);
  const hostBrand = hostSite.split('.')[0];
  const hostTokens = host.split(/[.-]/);
  // "xn--pypal-4ve" (pаypal with a Cyrillic "а") keeps its plain letters, "pypal", before the last hyphen.
  const plain = hostBrand.startsWith('xn--') && hostBrand.lastIndexOf('-') > 3 ? hostBrand.slice(4, hostBrand.lastIndexOf('-')) : '';
  const within = (part, whole) => { let index = 0; for (const char of whole) if (char === part[index]) index += 1; return index === part.length; };
  for (const site of new Set(sites)) {
    if (!site.includes('.')) continue;
    const brand = guessSite(site).split('.')[0];
    if (brand.length < 4 || guessSite(site) === hostSite) continue;
    if (hostBrand === brand || hostTokens.includes(brand) || skeleton(hostBrand) === skeleton(brand) ||
        (brand.length >= 5 && editDistance(hostBrand, brand) <= (brand.length >= 9 ? 2 : 1)) ||
        (plain.length >= 3 && brand.length - plain.length <= 2 && within(plain, brand))) return site;
  }
  return null;
}

export async function lookup({ entries, siteKey }, { host, site, rules }) {
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
  const { length, groups } = validRules(rules?.length, rules?.groups) ? rules : DEFAULT_RULES;
  const suggestion = suggestSite ?
    { site: suggestSite, length, groups, password: await derivePassword(siteKey, { site: suggestSite, counter: 1, length, groups }) } :
    null;
  const lookalike = matches.length ? null : lookalikeOf(host, entries.map(entrySite));
  return { matches, suggestion, lookalike };
}
