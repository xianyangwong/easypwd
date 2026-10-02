// Chrome's built-in, on-device language model (Prompt API, Gemini Nano).
// Optional: every caller has a non-AI fallback. The model runs locally; Chrome downloads it.
const LANGUAGES = Object.freeze({
  expectedInputs: [{ type: 'text', languages: ['en'] }],
  expectedOutputs: [{ type: 'text', languages: ['en'] }],
});

export function withTimeout(promise, ms) {
  let timer;
  const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Timed out.')), ms); });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// "available", "downloadable", "downloading", or "unavailable".
export async function aiAvailability(model = globalThis.LanguageModel, ms = 3_000) {
  if (!model?.availability) return 'unavailable';
  try { return await withTimeout(model.availability(LANGUAGES), ms); } catch { return 'unavailable'; }
}

// Starts the one-time model download (needs a click). Chrome finishes it in the background.
export function startAiDownload(model = globalThis.LanguageModel) {
  model?.create?.(LANGUAGES).then((session) => session.destroy(), () => {});
}

// One prompt, answered as JSON matching `schema`. The answer is untrusted; callers validate it.
export async function promptJson(system, text, schema, { model = globalThis.LanguageModel, ms = 30_000 } = {}) {
  const session = await withTimeout(model.create({ ...LANGUAGES, initialPrompts: [{ role: 'system', content: system }] }), ms);
  try {
    return JSON.parse(await withTimeout(session.prompt(text, { responseConstraint: schema }), ms));
  } finally {
    session.destroy();
  }
}
