// Offline password health checks. No breach data: "old" is the closest offline signal.
export const STALE_AFTER_MS = 365 * 24 * 60 * 60 * 1000;

const CLASSES = [[/[a-z]/, 26], [/[A-Z]/, 26], [/[0-9]/, 10], [/[^a-zA-Z0-9]/, 33]];

export function isWeak(password) {
  const pool = CLASSES.reduce((size, [pattern, count]) => size + (pattern.test(password) ? count : 0), 0);
  return password.length < 12 || [...password].length * Math.log2(pool) < 60 || new Set(password).size < 5;
}

// Returns Map(entry id -> [{ label, text }]) for entries with at least one issue.
export function passwordIssues(entries, now = Date.now()) {
  const uses = new Map();
  for (const entry of entries) {
    if (!entry.derive && entry.password) uses.set(entry.password, (uses.get(entry.password) ?? 0) + 1);
  }
  const issues = new Map();
  for (const entry of entries) {
    const found = [];
    if (entry.derive) {
      if (entry.derive.length < 12) {
        found.push({ label: 'Short', text: `This generated password has only ${entry.derive.length} characters. Edit it to make it longer if the site allows.` });
      }
    } else if (entry.password) {
      const others = uses.get(entry.password) - 1;
      if (others) found.push({ label: 'Reused', text: `This password is also used for ${others} other login${others === 1 ? '' : 's'}.` });
      if (isWeak(entry.password)) found.push({ label: 'Weak', text: 'This password is weak. Consider switching this login to a generated password.' });
    }
    if (Number.isSafeInteger(entry.updatedAt) && now - entry.updatedAt > STALE_AFTER_MS) {
      found.push({
        label: 'Over a year old',
        text: entry.derive ?
          'Not changed in over a year. If this site had a breach, edit it and raise the Version to get a new password.' :
          'Not changed in over a year. If this site had a breach, change it there and here.',
      });
    }
    if (found.length) issues.set(entry.id, found);
  }
  return issues;
}
