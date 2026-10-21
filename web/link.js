// Permalinks: what makes a run (the example or the typed source, the spend path, the
// step) lives in the URL fragment, so a link opens the same view. Older links may
// carry m=script, from when the page had modes: it is ignored.
// The fragment never reaches the server. Everything read from it is untrusted: only
// known names, digits and bounded text get through, the rest is dropped.

export const MAX_TEXT = 4096; // as the backend: longer is refused there anyway
const KINDS = ['policy', 'miniscript', 'descriptor', 'script'];
const WRAPS = ['bare', 'pkh', 'sh', 'wpkh', 'wsh'];

// path and step: up to 4 digits; the page bounds them by the run it gets
const index = (v) => (/^\d{1,4}$/.test(v ?? '') ? Number(v) : 0);
const oneOf = (v, list) => (list.includes(v) ? v : null);

// `{example | source, path, step}` -> '#...'. Defaults are left out.
export function writeLink({ example, source, path = 0, step = 0 }) {
  const q = new URLSearchParams();
  if (example) q.set('ex', example);
  else {
    q.set('k', source.kind);
    q.set('t', source.text);
    // a descriptor names its own output and a script is always wsh
    if (source.wrap && (source.kind === 'policy' || source.kind === 'miniscript')) q.set('w', source.wrap);
  }
  if (path) q.set('p', path);
  if (step) q.set('s', step);
  return `#${q}`;
}

// '#...' -> `{example: index into names, ...}` or `{source: {kind, text, wrap}, ...}`,
// or null when the fragment is not a link of ours.
export function readLink(hash, names) {
  const q = new URLSearchParams(hash.replace(/^#/, ''));
  const rest = { path: index(q.get('p')), step: index(q.get('s')) };
  if (q.has('ex')) {
    const example = names.indexOf(q.get('ex'));
    return example < 0 ? null : { example, ...rest };
  }
  const kind = oneOf(q.get('k'), KINDS);
  const text = q.get('t') ?? '';
  if (!kind || !text || text.length > MAX_TEXT) return null;
  return { source: { kind, text, wrap: oneOf(q.get('w'), WRAPS) }, ...rest };
}
