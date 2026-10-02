// Reads a website's password requirements and turns them into generation rules.
// The on-device model (Chrome's built-in Gemini Nano) is used when available;
// a small rule-based parser covers everything else. Nothing leaves the device.
import { DEFAULT_RULES, GROUP_ORDER, validRules } from './crypto.js';
import { promptJson } from './ai.js';

export { aiAvailability, startAiDownload } from './ai.js';

const MAX_TEXT = 4_000;

// Runs inside the web page. Collects password-related text and the password fields' limits.
// Returns no field values.
export function collectRuleText() {
  const visible = (node) => node.getClientRects().length > 0 && getComputedStyle(node).visibility !== 'hidden';
  const fields = [...document.querySelectorAll('input[type=password]')].filter(visible);
  const lines = new Set();
  const add = (text) => {
    for (const line of (text ?? '').split('\n')) {
      const trimmed = line.trim().replace(/\s+/g, ' ');
      if (trimmed && trimmed.length < 300) lines.add(trimmed);
    }
  };
  for (const field of fields) {
    for (const id of (field.getAttribute('aria-describedby') ?? '').split(/\s+/).filter(Boolean)) {
      add(document.getElementById(id)?.textContent);
    }
    add(field.title);
    add(field.placeholder);
  }
  const keywords = /password|passcode|\bpin\b|character|symbol|special|letter|digit|number|upper|lower|alphanumeric|密码|字符/i;
  for (const line of (document.body?.innerText ?? '').split('\n')) {
    if (keywords.test(line)) add(line);
  }
  const numbers = (name) => fields.map((field) => Number(field.getAttribute(name))).filter((value) => value > 0);
  return {
    text: [...lines].join('\n').slice(0, 4_000),
    minLength: Math.max(0, ...numbers('minlength')) || null,
    maxLength: Math.min(Infinity, ...numbers('maxlength')) === Infinity ? null : Math.min(...numbers('maxlength')),
    hasPasswordField: fields.length > 0,
  };
}

const NONE = Object.freeze({ minLength: null, maxLength: null, lowercase: true, uppercase: true, digits: true, symbols: true });

// Rule-based reading of common English phrasings.
export function parseRules(text) {
  const found = { ...NONE };
  let any = false;
  const num = '(\\d{1,3})';
  const chars = '(?:characters?|chars?|letters?(?: and (?:numbers|digits))?|digits)';
  const range = new RegExp(`(?:between\\s+)?${num}\\s*(?:-|–|—|to|and)\\s*${num}\\s*${chars}`, 'i').exec(text);
  if (range) {
    found.minLength = Number(range[1]);
    found.maxLength = Number(range[2]);
    any = true;
  }
  const min = new RegExp(`(?:at least|minimum(?: of)?|min\\.?|no (?:fewer|less) than|must be)\\s+${num}\\s*(?:or more\\s+)?${chars}|${num}\\s*(?:or more|\\+)\\s*${chars}`, 'i').exec(text);
  if (min && !range) {
    found.minLength = Number(min[1] ?? min[2]);
    any = true;
  }
  const max = new RegExp(`(?:at most|maximum(?: of)?|max\\.?|no (?:more|longer) than|up to|cannot exceed|not exceed)\\s+${num}\\s*${chars}`, 'i').exec(text);
  if (max && !range) {
    found.maxLength = Number(max[1]);
    any = true;
  }
  if (/\b(?:no|not|cannot|can't|can ?not|don't|do not|must not|without|isn't|aren't)\b[^.\n]{0,40}\b(?:special characters?|symbols?|punctuation)/i.test(text) ||
      /\b(?:special characters?|symbols?|punctuation)\b[^.\n]{0,20}\b(?:(?:are|is) not|aren't|isn't|not)\s+(?:allowed|permitted|accepted|supported)/i.test(text) ||
      /\b(?:letters and (?:numbers|digits) only|only (?:contain )?letters and (?:numbers|digits)|alphanumeric(?: characters)? only|only alphanumeric|must be alphanumeric)/i.test(text) ||
      /(?:only|following|allowed|permitted|valid|accepted)[^.\n]{0,40}(?:special characters?|symbols?)[^.\n]{0,20}?[:(]\s*[^\w\s]{1,}/i.test(text)) {
    found.symbols = false;
    any = true;
  }
  if (/\b(?:\d+[- ]digit (?:pin|passcode|password)|(?:digits|numbers) only|only (?:digits|numbers)|numeric only|must be numeric)\b/i.test(text)) {
    Object.assign(found, { lowercase: false, uppercase: false, symbols: false, digits: true });
    any = true;
  }
  return any ? found : null;
}

const SCHEMA = {
  type: 'object',
  properties: {
    found: { type: 'boolean' },
    minLength: { type: ['integer', 'null'] },
    maxLength: { type: ['integer', 'null'] },
    lowercaseAllowed: { type: 'boolean' },
    uppercaseAllowed: { type: 'boolean' },
    digitsAllowed: { type: 'boolean' },
    anySymbolAllowed: { type: 'boolean' },
  },
  required: ['found', 'minLength', 'maxLength', 'lowercaseAllowed', 'uppercaseAllowed', 'digitsAllowed', 'anySymbolAllowed'],
  additionalProperties: false,
};

export async function aiRules(text, options) {
  const answer = await promptJson(
    'You read password requirements from a website sign-up or change-password page and report them exactly. ' +
      'Only report limits the text states. Unstated limits are null, and unmentioned character types are allowed. ' +
      'anySymbolAllowed is false if symbols are forbidden or only some specific symbols are allowed. ' +
      'found is false if the text states no password requirements.',
    `Page text:\n"""\n${text.slice(0, MAX_TEXT)}\n"""`, SCHEMA, options);
  if (!answer.found) return null;
  const length = (value) => (Number.isInteger(value) && value > 0 && value <= 1_000 ? value : null);
  return {
    minLength: length(answer.minLength),
    maxLength: length(answer.maxLength),
    lowercase: answer.lowercaseAllowed !== false,
    uppercase: answer.uppercaseAllowed !== false,
    digits: answer.digitsAllowed !== false,
    symbols: answer.anySymbolAllowed !== false,
  };
}

// The strongest EasyPwd rules that satisfy the requirements, or null if none can.
// HTML minlength/maxlength attributes are enforced by the page, so they always win.
export function rulesFor(found, page = {}) {
  const limits = { ...NONE, ...found };
  const min = Math.max(8, limits.minLength ?? 0, page.minLength ?? 0);
  const max = Math.min(64, limits.maxLength ?? 64, page.maxLength ?? 64);
  if (min > max) return null;
  const length = Math.min(max, Math.max(min, DEFAULT_RULES.length));
  const groups = GROUP_ORDER.filter((group) => limits[group] !== false);
  if (!groups.length || !validRules(length, groups)) return null;
  return { length, groups };
}

export function describeRules({ length, groups }) {
  const labels = { lowercase: 'a–z', uppercase: 'A–Z', digits: '0–9', symbols: 'symbols' };
  return `${length} characters · ${groups.map((group) => labels[group]).join(' ')}`;
}
