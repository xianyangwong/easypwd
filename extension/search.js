// Plain-language vault search: "weak passwords", "logins with 2FA", "gmail without username".
// Only the query is ever given to the on-device model, never vault data.
import { promptJson } from './ai.js';

export { aiAvailability } from './ai.js';

const FILTERS = [
  ['noOtp', /\b(?:no|without|missing|lacking)\s+(?:an?\s+|any\s+)?(?:2fa|two[- ]factor|totp|otp|authenticator|2-step)(?:\s+codes?)?/gi],
  ['otp', /\b(?:with|has|have|having|using)?\s*(?:2fa|two[- ]factor|totp|otp|authenticator|2-step)(?:\s+codes?)?/gi],
  ['noUsername', /\b(?:no|without|missing|empty)\s+(?:an?\s+|any\s+)?(?:usernames?|user names?|emails?|logins? names?)/gi],
  ['notes', /\b(?:with|has|have)\s+notes?\b/gi],
  ['weak', /\bweak(?:est)?\b/gi],
  ['reused', /\b(?:reused|re-used|duplicated?|same)\b/gi],
  ['old', /\b(?:old|stale|outdated|over a year(?: old)?|not (?:changed|updated)(?: in)?(?: over)?(?: a year)?)\b/gi],
  ['attention', /\b(?:need(?:s)? attention|unhealthy|at risk|issues?|problems?|unsafe|insecure)\b/gi],
  ['generated', /\bgenerated\b/gi],
  ['saved', /\b(?:saved|stored|manual|typed)\b(?=\s+(?:passwords?|logins?)\b)/gi],
];
const STOP = new Set(('a all an and any are account accounts by can code codes do entries entry find for from get give has have i in ' +
  'is it list login logins me my of on or password passwords please show site sites that the their them these those to ' +
  'use used what where which with without').split(' '));

const LABELS = {
  otp: 'with 2FA', noOtp: 'without 2FA', noUsername: 'without a username', notes: 'with notes', weak: 'weak',
  reused: 'reused', old: 'over a year old', attention: 'need attention', generated: 'generated', saved: 'saved',
};

// { terms, filters } from a query. Plain text with no keywords is just terms.
export function parseQuery(query) {
  let text = ` ${query.toLowerCase()} `;
  const filters = {};
  for (const [name, pattern] of FILTERS) {
    text = text.replace(pattern, () => {
      filters[name] = true;
      return ' ';
    });
  }
  if (filters.noOtp) delete filters.otp;
  const terms = text.split(/[\s,?!]+/).map((term) => term.replace(/^['"]+|['"]+$/g, '')).filter((term) => term && !STOP.has(term));
  return { terms, filters };
}

export function describeQuery({ terms, filters }) {
  const parts = Object.keys(filters).map((name) => LABELS[name]);
  if (terms.length) parts.push(`matching “${terms.join(' ')}”`);
  return parts.join(' · ');
}

// fields: searchable text of the entry. issues: health labels for the entry, e.g. ["Weak", "Reused"].
export function matchesQuery(entry, fields, issues, { terms, filters }) {
  const labels = issues.map((issue) => issue.label);
  const checks = {
    otp: () => !!entry.otp,
    noOtp: () => !entry.otp,
    noUsername: () => !entry.username,
    notes: () => !!entry.notes,
    weak: () => labels.includes('Weak') || labels.includes('Short'),
    reused: () => labels.includes('Reused'),
    old: () => labels.includes('Over a year old'),
    attention: () => labels.length > 0,
    generated: () => !!entry.derive,
    saved: () => !entry.derive,
  };
  const text = fields.join(' ').toLowerCase();
  return Object.keys(filters).every((name) => checks[name]()) && terms.every((term) => text.includes(term));
}

const SCHEMA = {
  type: 'object',
  properties: {
    words: { type: 'array', items: { type: 'string' }, maxItems: 5 },
    filters: { type: 'array', items: { enum: Object.keys(LABELS) }, maxItems: 5 },
  },
  required: ['words', 'filters'],
  additionalProperties: false,
};

// The on-device model's reading of a longer question, validated into the same shape as parseQuery.
export async function aiQuery(query, options) {
  const answer = await promptJson(
    'You turn a question about a password manager into a search. words are the website, app, company, or username ' +
      'words to look for, lowercase, without filler words such as "password" or "login"; use the company\'s name, ' +
      'for example "gmail" for "my Google mail". filters are the conditions the question asks for: ' +
      `${Object.entries(LABELS).map(([name, label]) => `${name} = ${label}`).join(', ')}. Use empty arrays when nothing applies.`,
    query.slice(0, 500), SCHEMA, options);
  const filters = {};
  for (const name of Array.isArray(answer.filters) ? answer.filters : []) if (name in LABELS) filters[name] = true;
  if (filters.noOtp) delete filters.otp;
  const terms = (Array.isArray(answer.words) ? answer.words : [])
    .filter((word) => typeof word === 'string')
    .flatMap((word) => word.toLowerCase().split(/\s+/))
    .filter((word) => word && word.length <= 64 && !STOP.has(word))
    .slice(0, 5);
  return { terms, filters };
}
