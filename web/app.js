import { renderCost } from './cost.js';
import { $, copyText, esc } from './dom.js';
import { readLink, writeLink } from './link.js';
import { describe, opText } from './opinfo.js';
import { initTheme, loadPref, savePref } from './prefs.js';
import { groups, scenarios } from './scenarios.js';

const state = {
  scenario: 0,
  path: 0,
  step: 0,
  mode: loadPref('mode', 'miniscript'),
  source: 'policy', // which field the user typed into last: policy, miniscript or descriptor
  wrap: 'wsh', // output type policy / miniscript are built for (API.md); an example sets it
  drafts: {}, // text that failed to compile, kept per field until fixed or an example is picked
  alt: loadPref('alt', 'off') === 'on',
  scriptView: loadPref('scriptView', 'grouped'), // desktop listing: 'grouped' by leaf fragment or 'ops', one per line
  testKeys: loadPref('testKeys', 'off') === 'on', // opt-in: named keys are not a real descriptor
  blocked: null, // why the script is refused: 'alt' | 'keys' | null
  live: null, // scenario from the backend (API.md); null = nothing compiled yet
  origin: null, // the typed source `live` was compiled from ({kind, text, wrap}); null for an example
};
let reqSeq = 0; // the latest backend request wins
let trace;
let drawn = -1; // last drawn stack: animate only a single step forward

// drawn until the backend answered (or when it is not running): nothing to run
const EMPTY = {
  policy: null,
  miniscript: null,
  descriptor: '',
  spk: '',
  about: null,
  tree: null,
  script: [],
  paths: [],
  traces: [{ steps: [{ pc: -1, stack: [], alt: [], popped: [], pushed: [], executed: true, note: '' }], result: { ok: false, message: 'nothing compiled' } }],
};
const scenario = () => state.live ?? EMPTY;
// backend items are JSON, so object identity means nothing: compare by id
const key = (x) => x.id;
const last = () => trace.steps.length - 1;

// phones have no room for a third column: no alt stack there at all
const PHONE = matchMedia('(max-width: 860px)');
const altOn = () => state.alt && !PHONE.matches;
const usesAlt = (sc) => sc.script.some((ins) => ins.op === 'OP_TOALTSTACK' || ins.op === 'OP_FROMALTSTACK');
// key items (pk, sig, hash160 of a key) carry the key's name: A, B…
const usesTestKeys = (sc) =>
  [...sc.script.map((ins) => ins.item), ...sc.traces.flatMap((t) => t.steps[0].stack)].some((x) => x?.name !== undefined);

// what the step card says when a script is refused instead of run
const BLOCKED = {
  alt: {
    title: 'alt stack is off',
    html: 'This script uses OP_TOALTSTACK / OP_FROMALTSTACK. <button id="alt-on">turn on alt stack <kbd>A</kbd></button>',
  },
  altPhone: {
    title: 'needs the alt stack',
    html: 'This script uses OP_TOALTSTACK / OP_FROMALTSTACK. The alt stack is shown on wider screens only.',
  },
  keys: {
    title: 'test keys are off',
    // real keys in the input are built as test keys too: say which, not "A, B…"
    html: (sc) =>
      (sc.keys?.length
        ? `We can't sign for real keys, so ${sc.keys.map((k) => `${esc(shortKey(k.key))} runs as test key ${esc(k.name)}`).join(', ')}: the script bytes and signatures are not the real ones.`
        : 'This example uses named test keys (A, B…) instead of real public keys, and its signatures are symbolic: not a real descriptor.') +
      ' <button id="keys-on">turn on test keys <kbd>K</kbd></button>',
  },
};
const blockedHtml = (why, sc) => (typeof BLOCKED[why].html === 'function' ? BLOCKED[why].html(sc) : BLOCKED[why].html);
// 02e5b88fdb…3bba12f: a real key is too long to read in full (the title has it)
const shortKey = (k) => (k.length <= 24 ? k : `${k.slice(0, 12)}…${k.slice(-8)}`);

// A run of ops in a branch not taken is one step: the stack does not change on them.
// OP_ELSE / OP_ENDIF run even there (they flip the branch), so they end the run.
// Every step gets `pcs`, the script lines it covers (one, but for such a run).
function collapseSkips(t) {
  const steps = [];
  for (const s of t.steps) {
    const prev = steps.at(-1);
    if (!s.executed && !s.error && prev && !prev.executed && !prev.error) prev.pcs.push(s.pc);
    else steps.push({ ...s, pcs: [s.pc] });
  }
  return { ...t, steps };
}

function load() {
  stopPlay();
  const sc = scenario();
  // scripts that need something turned off are refused, not run
  state.blocked = usesAlt(sc) && !altOn() ? (PHONE.matches ? 'altPhone' : 'alt') : usesTestKeys(sc) && !state.testKeys ? 'keys' : null;
  trace = collapseSkips(
    state.blocked
      ? { steps: [{ pc: -1, stack: [], alt: [], popped: [], pushed: [], executed: true }], result: { ok: false, message: BLOCKED[state.blocked].title } }
      : (sc.traces[state.path] ?? EMPTY.traces[0]),
  );
  document.body.classList.toggle('alt-on', altOn());
  document.body.classList.toggle('blocked', Boolean(state.blocked));
  state.step = 0;
  drawn = -1;
  renderStatic();
  renderCost(sc, state.blocked ? -1 : state.path);
  render();
}

// --- static parts (change only with scenario / path) ---

const FLOW_OPS = ['OP_IF', 'OP_NOTIF', 'OP_ELSE', 'OP_ENDIF'];

function depths(script) {
  let d = 0;
  return script.map((ins) => {
    if (ins.op === 'OP_ELSE' || ins.op === 'OP_ENDIF') d--;
    const cur = d;
    if (['OP_IF', 'OP_NOTIF', 'OP_ELSE'].includes(ins.op)) d++;
    return cur;
  });
}

// pc runs of the leaf fragments that emit more than one op, in script order
function leafGroups(node) {
  if (node.text) return node.ops.length > 1 ? [node.ops] : [];
  const kids = node.child ? [node.child] : node.children ?? [];
  return kids.flatMap(leafGroups);
}

function treeHtml(node) {
  const own = esc(node.ops.join(','));
  const all = esc(subtreeOps(node).join(','));
  // .fh: the fragment's own text (name, parens, wrapper): the current opcode
  // lights up only that, not the whole subtree (andor( ... ) would light everything)
  if (node.text) return `<span class="frag" data-own="${own}" data-all="${all}"><span class="fh">${esc(node.text)}</span></span>`;
  if (node.wrap) return `<span class="frag" data-own="${own}" data-all="${all}"><span class="fh">${esc(node.wrap)}</span>${treeHtml(node.child)}</span>`;
  // <wbr>: a long miniscript wraps after a comma, not inside a fragment name
  const kids = node.children.map(treeHtml).join(',<wbr>');
  return `<span class="frag" data-own="${own}" data-all="${all}"><span class="fh">${esc(node.head)}(</span>${kids}<span class="fh">)</span></span>`;
}

const INPUTS = { policy: 'in-policy', miniscript: 'in-miniscript', descriptor: 'in-descriptor', script: 'in-script' };

// '' when the example has no such form (e.g. OP_RETURN has no policy)
function sourceText(sc, kind) {
  if (kind === 'policy') return sc.policy ?? '';
  if (kind === 'miniscript') return sc.miniscript ?? '';
  if (kind === 'descriptor') return sc.descriptor ?? '';
  return sc.script
    .filter((ins) => ins.op !== 'PHASE')
    .map(opText)
    .join(' ');
}

// POST /api/compile (API.md). {sc} on success, {error} on a compile error,
// {offline: true} when the backend is not reachable (the page is cached, or served by something else)
async function compile(body) {
  try {
    const r = await fetch('api/compile', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    // the backend always answers JSON; anything else is the proxy (rate limit, backend down) or not us
    if (!r.headers.get('content-type')?.includes('json'))
      return r.status === 429 ? { error: 'too many requests: wait a few seconds' } : { offline: true };
    const data = await r.json();
    return r.ok ? { sc: data } : { error: data.error ?? `HTTP ${r.status}` };
  } catch {
    return { offline: true };
  }
}

// policy / miniscript have no spaces; Script tokens are space separated
const cleanSource = (kind, text) => (kind === 'script' ? text.replace(/\s+/g, ' ').trim() : text.replace(/\s+/g, ''));

const OFFLINE = '✗ the backend is not reachable (locally: cd server && bacon)';

// Fields flow one way: policy compiles to miniscript, miniscript is wrapped in the descriptor.
// Typing a field fills the ones below it; the policy is never lifted back from a miniscript.
const COMPILE_DELAY = 300;
let compileTimer;

// the message goes under the field it is about: the one being edited
function setStatus(cls, text, field) {
  if (field) (field.dataset.kind === 'descriptor' ? $('desc-sum') : field.closest('.field')).after($('src-msg'));
  $('src-msg').className = `src-msg ${cls}`;
  $('src-msg').textContent = text;
}

// Typing compiles after a short pause; Enter compiles right away.
function onSourceInput(e) {
  clearTimeout(compileTimer);
  // the first keystroke already makes it not the example: blank the picker now, not after compiling
  state.scenario = null;
  $('scenario').value = '';
  $('desc-sum').hidden = true; // the descriptor below is about to change: its checksum is stale
  $('copy-desc').hidden = true;
  setStatus('busy', 'compiling…', e.target);
  compileTimer = setTimeout(() => compileField(e.target), COMPILE_DELAY);
}

async function compileField(el) {
  clearTimeout(compileTimer);
  const kind = el.dataset.kind;
  const text = cleanSource(kind, el.value);
  if (!text) {
    state.drafts[kind] = el.value;
    setStatus('', '', el);
    return;
  }
  const id = ++reqSeq;
  setStatus('busy', 'compiling…', el);
  // a descriptor names its own output type; a script is always wsh
  const res = await compile(kind === 'policy' || kind === 'miniscript' ? { kind, text, wrap: state.wrap } : { kind, text });
  if (id !== reqSeq) return; // a newer request (typing, example pick) took over
  if (res.offline || res.error) {
    // keep the text (also after blur) and the last good visualization
    state.drafts[kind] = el.value;
    el.classList.add('invalid');
    setStatus('warn', res.offline ? OFFLINE : `✗ ${res.error}`, el);
    return;
  }
  state.drafts = {};
  el.classList.remove('invalid');
  // a pasted checksum checked out: it moves from the field to the line below it
  if (kind === 'descriptor' && el.value.includes('#')) el.value = res.sc.descriptor;
  state.source = kind;
  state.origin = { kind, text, wrap: state.wrap };
  state.scenario = null; // edited: no longer the example, the picker goes blank
  state.live = { ...res.sc, name: 'custom' };
  if (res.sc.wrap) state.wrap = res.sc.wrap; // a typed descriptor picks the output
  state.path = 0;
  load();
  // only a policy is compiled (a choice among miniscripts); the rest is checked and encoded
  const DONE = { policy: 'compiled to miniscript', miniscript: 'valid miniscript', descriptor: 'valid descriptor', script: 'parsed' };
  setStatus('ok', `✓ ${DONE[kind]}`, el);
}

// pick an example: the backend compiles and runs it
async function loadExample(i) {
  const ex = scenarios[i];
  state.scenario = i;
  state.origin = null;
  state.path = 0;
  state.drafts = {};
  state.source = ex.api.kind === 'script' ? 'policy' : ex.api.kind;
  const id = ++reqSeq;
  setStatus('busy', 'compiling…');
  const res = await compile(ex.api);
  if (id !== reqSeq) return;
  state.live = res.sc ? { ...res.sc, name: ex.name, about: ex.about ?? res.sc.about } : null;
  if (res.sc) state.wrap = res.sc.wrap;
  setStatus(res.sc ? '' : 'warn', res.sc ? '' : res.offline ? OFFLINE : `✗ ${res.error}`);
  load();
}

function subtreeOps(node) {
  const kids = node.child ? [node.child] : node.children ?? [];
  return [...node.ops, ...kids.flatMap(subtreeOps)];
}

function renderStatic() {
  const sc = scenario();

  // script only hides policy / miniscript, so name the group by what is shown
  const groupLabel = (key, label) => (state.mode === 'script' && key === 'miniscript' ? 'compiled from miniscript' : label);
  $('scenario').innerHTML = Object.entries(groups)
    .map(([key, label]) => {
      label = groupLabel(key, label);
      const opts = scenarios
        .map((s, i) => [s, i])
        .filter(([s]) => (s.group ?? 'miniscript') === key && !(s.alt && PHONE.matches))
        .map(([s, i]) => `<option value="${i}" ${i === state.scenario ? 'selected' : ''}>${esc(s.name)}</option>`);
      return opts.length ? `<optgroup label="${esc(label)}">${opts.join('')}</optgroup>` : '';
    })
    .join('');
  // an edited example is not that example any more: nothing is picked
  $('scenario').insertAdjacentHTML('afterbegin', `<option value="" hidden ${state.scenario === null ? 'selected' : ''}></option>`);
  $('wrap').value = state.wrap;
  $('wrap-warn').hidden = !sc.outside_bip379;
  // spend path; option text can't be styled, so a failing path is marked with ✗
  $('paths').innerHTML = sc.paths
    .map((p, i) => `<option value="${i}" ${i === state.path ? 'selected' : ''}>${p.fails ? '✗ ' : ''}${esc(p.name)}</option>`)
    .join('');
  $('paths').disabled = sc.paths.length < 2;

  for (const [kind, id] of Object.entries(INPUTS)) {
    const el = $(id);
    if (document.activeElement === el) continue; // don't fight the user's typing
    const draft = state.drafts[kind];
    el.value = draft ?? sourceText(sc, kind);
    el.placeholder = el.value
      ? ''
      : kind === 'miniscript' && ['pkh', 'wpkh'].includes(sc.wrap)
        ? `${sc.wrap}() is a key template, no miniscript of its own`
        : kind === 'policy' && ['miniscript', 'descriptor'].includes(state.source)
          ? `not derived from the ${state.source}`
          : `no ${kind} form`;
    el.classList.toggle('invalid', draft !== undefined);
  }
  for (const id of Object.values(INPUTS)) fitHeight($(id));
  // the arrow only holds when the miniscript was compiled from the policy above it
  $('flow').innerHTML = state.source === 'policy' && sc.policy ? '↓ compiles to' : '';
  // shown only for the descriptor in the field: a draft there has no checksum yet
  $('desc-sum').hidden = !sc.checksum || Object.keys(state.drafts).length > 0;
  $('copy-desc').hidden = $('desc-sum').hidden;
  $('desc-sum').classList.toggle('test', !sc.importable);
  $('checksum').textContent = sc.checksum ? `#${sc.checksum}` : '';
  $('sum-note').textContent = sc.importable ? '' : 'test keys: not importable';
  $('sum-note').title = sc.importable ? '' : 'A wallet cannot use it: the keys are made up. Put real keys (hex, xpub) in the source.';
  const realKeys = sc.keys ?? [];
  $('keys-row').hidden = !realKeys.length;
  $('keys').innerHTML = realKeys.map((k) => `<div title="${esc(k.key)}">${esc(k.name)} = ${esc(shortKey(k.key))}</div>`).join('');
  $('miniscript').innerHTML = sc.tree ? treeHtml(sc.tree) : '<span class="muted">—</span>';
  $('frag-ops').hidden = true;
  $('spk').textContent = sc.spk ?? '';
  $('about').textContent = sc.about ?? '';
  $('about').hidden = !sc.about;

  const d = depths(sc.script);
  // grouped: the ops of one leaf fragment (pkh(C): DUP HASH160 <h> EQUALVERIFY CHECKSIG)
  // share a row, BOLT 3 style; control ops (IF, SWAP, ADD…) keep their own rows
  // a script that is one leaf (multi, pk) has no structure to show: one op per line
  const grouping = state.scriptView === 'grouped' && sc.tree && !sc.tree.text;
  const runs = grouping ? leafGroups(sc.tree) : [];
  const groupAt = new Map(runs.map((g) => [g[0], g]));
  const inGroup = new Set(runs.flat());
  const opSpan = (ins, pc) => `<span class="op ${ins.op === 'PUSH' ? 'push' : ''}" title="${esc(opText(ins))}">${esc(opText(ins))}</span>`;
  // pc -1 is step 0: the witness is on the stack, no opcode has run yet
  const startLine = '<li data-pc="-1" class="start-line" style="--depth:0"><span class="pc"></span><span class="op">start</span></li>';
  $('script').innerHTML = startLine + sc.script
    .map((ins, pc) => {
      if (ins.op === 'PHASE') return `<li data-pc="${pc}" class="phase-line"><span class="op">${esc(opText(ins))}</span></li>`;
      const g = groupAt.get(pc);
      if (g) {
        const ops = g.map((i) => `<span class="gop" data-pc="${i}">${opSpan(sc.script[i], i)}</span>`).join('');
        return `<li class="group" style="--depth:${d[pc]}"><span class="pc">${pc}</span><span class="gops">${ops}</span></li>`;
      }
      if (inGroup.has(pc)) return '';
      return `<li data-pc="${pc}" style="--depth:${d[pc]}"><span class="pc">${pc}</span>${opSpan(ins, pc)}</li>`;
    })
    .join('');
  $('script-view').hidden = !sc.tree || !!sc.tree.text;
  document.body.classList.toggle('script-grouped', runs.length > 0);
  $('script-view').textContent = state.scriptView === 'grouped' ? 'one op per line' : 'group by fragment';
  $('strip').innerHTML = '<li data-pc="-1" class="start">start</li>' + sc.script
    .map((ins, pc) => {
      const kind = ins.op === 'PHASE' ? 'phase' : ins.op === 'PUSH' ? 'push' : FLOW_OPS.includes(ins.op) ? 'ctl' : '';
      return `<li data-pc="${pc}" class="${kind}" style="--depth:${d[pc] ?? 0}">${esc(opText(ins))}</li>`;
    })
    .join('');

  // each tick is a mini stack: one cell per item, coloured by kind, scaled to
  // the deepest point of this run so the heights compare across steps
  const maxDepth = Math.max(...trace.steps.map((s) => s.stack.length), 1);
  $('timeline').classList.toggle('dense', maxDepth > 8);
  $('timeline').innerHTML = trace.steps
    .map((s, i) => {
      const cls = i === 0 ? 'start' : s.error ? 'error' : s.executed ? '' : 'skipped';
      const title = i === 0 ? 'start' : s.pcs.length > 1 ? `skipped ${s.pcs.length} ops` : opText(sc.script[s.pc]);
      const cells = s.stack.map((it) => `<i class="k-${it.kind}"></i>`).join('');
      const h = (s.stack.length / maxDepth) * 100;
      return `<button class="tick ${cls}" data-step="${i}" title="${esc(`${title} · stack ${s.stack.length}`)}"><span style="height:${h}%">${cells}</span></button>`;
    })
    .join('');

  // size each well to the deepest point of this run (+1 spare row), so it
  // neither jumps between steps nor stretches into empty space on big screens
  const depth = (key) => Math.max(...trace.steps.map((s) => s[key].length), 1) + 1;
  $('stack').parentElement.style.setProperty('--rows', Math.max(depth('stack'), 3));
  $('alt').parentElement.style.setProperty('--rows', Math.max(depth('alt'), 2));

  document.body.dataset.mode = state.mode;
  for (const b of $('mode').querySelectorAll('button')) b.classList.toggle('on', b.dataset.mode === state.mode);
}

// --- per-step parts ---

function itemHtml(x, cls = '') {
  const hex = x.hex === '' ? 'empty' : x.hex.length > 22 ? `${x.hex.slice(0, 8)}…${x.hex.slice(-6)}` : x.hex;
  const size = x.hex.length / 2;
  return `<div class="item k-${x.kind} ${cls}"><span class="lbl" title="${esc(x.label)}">${esc(x.label)}</span><span class="hex">${esc(hex)} <span class="size">${size}B</span></span></div>`;
}

function render() {
  const sc = scenario();
  const step = trace.steps[state.step];
  const ins = step.pc >= 0 ? sc.script[step.pc] : null;

  // script lines: what already ran, what was skipped, where we are
  const status = new Map([[-1, 'done']]); // the start line (initial stack) is always behind us
  for (const s of trace.steps.slice(1, state.step + 1)) for (const pc of s.pcs) status.set(pc, s.error ? 'error' : s.executed ? 'done' : 'skipped');
  // classList, not className: keeps the lines' own classes (start-line, phase-line, push…)
  for (const li of [...$('script').querySelectorAll('[data-pc]'), ...$('strip').children]) {
    const pc = Number(li.dataset.pc);
    li.classList.remove('pending', 'done', 'skipped', 'error');
    li.classList.add(status.get(pc) ?? 'pending');
    li.classList.toggle('current', step.pcs.includes(pc));
  }
  // a grouped row is the current line while one of its ops is (its ops dim on their own)
  for (const row of $('script').querySelectorAll('.group')) row.classList.toggle('current', !!row.querySelector('.current'));
  // a skipped run lights whole rows, not every op in them
  $('script').classList.toggle('run', step.pcs.length > 1);
  scrollStrip();

  // miniscript fragment that emitted the current opcode
  for (const f of $('miniscript').querySelectorAll('.frag')) {
    const own = f.dataset.own ? f.dataset.own.split(',').map(Number) : [];
    f.classList.toggle('active', step.pcs.some((pc) => own.includes(pc)));
  }

  // explanation
  const run = step.pcs.length > 1;
  const title = run ? `skipped ${step.pcs.length} ops` : ins ? opText(ins) : 'start';
  const desc = run
    ? `Ops ${step.pcs[0]}-${step.pcs.at(-1)} are in a branch that is not taken: the stack does not change.`
    : ins
      ? describe(ins)
      : 'The spending data is placed on the stack, then the script runs op by op.';
  let note = '';
  if (step.error) note = `<div class="err">✗ ${esc(step.error)}</div>`;
  else if (run) note = '<div class="note">The interpreter still reads them: they count toward the 201-op limit, and a disabled opcode (OP_CAT…) here would fail the script.</div>';
  else if (step.note) note = `<div class="note">${esc(step.note)}</div>`;

  // what this step took off the stack and put on it
  const chip = (x, cls) => `<span class="chipx k-${x.kind} ${cls}">${esc(x.label)}</span>`;
  const delta =
    state.step === 0 || (!step.popped.length && !step.pushed.length)
      ? ''
      : `<div class="delta">${step.popped.length ? `<span class="k">popped</span>${step.popped.map((x) => chip(x, 'gone')).join('')}` : ''}${
          step.pushed.length ? `<span class="k">${step.popped.length ? '→ ' : ''}pushed</span>${step.pushed.map((x) => chip(x, 'new')).join('')}` : ''
        }</div>`;

  $('explain').innerHTML = state.blocked
    ? `<div class="op-line"><span class="op-title err">${BLOCKED[state.blocked].title}</span><span class="desc">${blockedHtml(state.blocked, sc)}</span></div>`
    :`<div class="op-line"><span class="op-title${step.pc === -1 ? ' start' : ''}">${esc(title)}</span><span class="desc">${esc(desc)}</span><span class="more" aria-hidden="true"></span></div>${note}${delta}`;
  // phone: is the one-line clamped description cut off? then show the ▾ hint
  const d = $('explain').querySelector('.desc');
  $('explain').classList.toggle('clamped', !$('explain').classList.contains('expanded') && d.scrollHeight > d.clientHeight + 1);

  // stack, top first. One step forward is animated: popped items leave first,
  // then pushed ones drop in. Going back or jumping redraws at once.
  const fresh = new Set(step.pushed.map(key));
  const animate = state.step > 0 && state.step === drawn + 1;
  drawn = state.step;
  let items = step.stack
    .slice()
    .reverse()
    .map((x) => itemHtml(x, fresh.has(key(x)) ? `new${animate ? ' enter' : ''}${animate && step.popped.length ? ' after-pop' : ''}` : ''));
  if (animate && step.popped.length) {
    // ghosts of the popped items, in their order on the previous stack, right under the pushed ones
    const popped = new Set(step.popped.map(key));
    const ghosts = trace.steps[state.step - 1].stack
      .slice()
      .reverse()
      .filter((x) => popped.has(key(x)))
      .map((x) => itemHtml(x, 'leaving'));
    items = [...items.slice(0, step.pushed.length), ...ghosts, ...items.slice(step.pushed.length)];
  }
  $('stack').innerHTML = items.length ? items.join('') : '<div class="empty-stack">empty</div>';

  $('alt-toggle').checked = state.alt;
  $('keys-toggle').checked = state.testKeys;
  if (altOn()) {
    const alt = step.alt;
    $('alt').innerHTML = alt.length
      ? alt
          .slice()
          .reverse()
          .map((x) => itemHtml(x, step.toAlt && key(x) === key(step.toAlt) ? `new${animate ? ' enter after-pop' : ''}` : ''))
          .join('')
      : '<div class="empty-stack">empty</div>';
  }

  // footer
  $('counter').textContent = `step ${state.step} / ${last()}`;
  const done = state.step === last();
  $('result').className = `result ${done ? (trace.result.ok ? 'ok' : 'fail') : ''}`;
  // phone shows only the mark (the step card already says why it failed)
  $('result').innerHTML = done ? `<span class="mark">${trace.result.ok ? '✓' : '✗'}</span><span class="msg"> ${esc(trace.result.message)}</span>` : '';
  for (const t of $('timeline').children) t.classList.toggle('current', Number(t.dataset.step) === state.step);
  $('first').disabled = $('prev').disabled = state.step === 0;
  $('next').disabled = $('last').disabled = state.step === last();
  $('play').disabled = last() === 0;
  updateLink();
}

// a long script scrolls inside its panel (strip on phones, listing on
// desktop): keep the current op in view (scrollTop, not scrollIntoView,
// which would also scroll the page)
function scrollStrip() {
  for (const box of [$('strip'), $('script').parentElement]) {
    const cur = box.querySelector('.current');
    if (!cur || box.scrollHeight <= box.clientHeight) continue;
    const top = cur.getBoundingClientRect().top - box.getBoundingClientRect().top + box.scrollTop;
    box.scrollTop = top - (box.clientHeight - cur.offsetHeight) / 2;
  }
}

// --- navigation ---

// every manual move stops the autoplay; only the autoplay passes auto = true
function go(i, auto = false) {
  if (!auto) stopPlay();
  state.step = Math.max(0, Math.min(last(), i));
  render();
}

function next() {
  go(state.step + 1);
}

// autoplay: one step per PLAY_MS, long enough for the pop / push animation
const PLAY_MS = 1300;
let playTimer = null;

function stopPlay() {
  clearTimeout(playTimer);
  playTimer = null;
  $('play').classList.remove('on');
  $('play').textContent = '▷';
}

function playTick() {
  go(state.step + 1, true);
  if (state.step >= last()) return stopPlay();
  playTimer = setTimeout(playTick, PLAY_MS);
}

$('play').onclick = (e) => {
  e.currentTarget.blur();
  if (playTimer) return stopPlay();
  if (state.step >= last()) go(0);
  $('play').classList.add('on');
  $('play').textContent = '❚❚';
  playTimer = setTimeout(playTick, 400);
};

$('first').onclick = () => go(0);
$('prev').onclick = () => go(state.step - 1);
$('next').onclick = next;
$('last').onclick = () => go(last());

$('scenario').onchange = (e) => {
  e.target.blur();
  loadExample(Number(e.target.value));
};

// another output type: rebuild from the field the user typed into last; a
// descriptor names its own wrapper, so then from what is inside it
$('wrap').onchange = (e) => {
  state.wrap = e.target.value;
  e.target.blur();
  // rebuild from the topmost field that has text; a descriptor's own text names the old output
  if (state.source === 'policy' && $('in-policy').value.trim()) return compileField($('in-policy'));
  if ($('in-miniscript').value.trim()) return compileField($('in-miniscript'));
  // pkh / wpkh have no miniscript: carry their key over as pk(key)
  const key = /^w?pkh\((.+)\)$/.exec(scenario().descriptor ?? '')?.[1];
  if (!key) return;
  $('in-miniscript').value = `pk(${key})`;
  compileField($('in-miniscript'));
};

$('copy-desc').onclick = async () => {
  const sc = scenario();
  const full = `${sc.descriptor}#${sc.checksum}`;
  const line = $('desc-sum');
  try {
    await copyText(full);
    $('copied').textContent = `✓ copied ${full}`;
    $('copied').classList.remove('fail');
  } catch {
    $('copied').textContent = '✗ copy failed: select the field and copy it by hand';
    $('copied').classList.add('fail');
  }
  line.classList.add('show-copied');
  clearTimeout(line.copiedTimer);
  line.copiedTimer = setTimeout(() => line.classList.remove('show-copied'), 2500);
};

$('script-view').onclick = (e) => {
  state.scriptView = state.scriptView === 'grouped' ? 'ops' : 'grouped';
  savePref('scriptView', state.scriptView);
  e.currentTarget.blur();
  renderStatic();
  render();
};

// a row of the cost table picks that spend path
$('cost').onclick = (e) => {
  const row = e.target.closest('tr[data-path]');
  if (!row) return;
  state.path = Number(row.dataset.path);
  $('paths').value = row.dataset.path;
  load();
};

// N: the next spend path, after the last one the first again
function nextPath() {
  const n = $('paths').options.length;
  if (n < 2 || state.blocked) return;
  state.path = (state.path + 1) % n;
  $('paths').value = String(state.path);
  load();
}

$('paths').onchange = (e) => {
  state.path = Number(e.target.value);
  e.target.blur();
  load();
};

function setMode(mode) {
  // the mode only changes the source fields: show them if folded (phone)
  if (mode !== state.mode) setSrcFold(false);
  state.mode = mode;
  savePref('mode', state.mode);
  renderStatic();
  render();
}

$('mode').onclick = (e) => {
  const b = e.target.closest('[data-mode]');
  if (b) setMode(b.dataset.mode);
};

// source fields are as tall as their content, so the whole text is visible
function fitHeight(el) {
  if (!el.offsetParent) return; // hidden: ResizeObserver refits once shown
  el.style.height = 'auto';
  el.style.height = `${el.scrollHeight + el.offsetHeight - el.clientHeight}px`;
}
// fires when a field becomes visible or its width changes (rewrap)
const fieldResize = new ResizeObserver((entries) => entries.forEach((e) => fitHeight(e.target)));

for (const id of Object.values(INPUTS)) {
  const el = $(id);
  fieldResize.observe(el);
  el.addEventListener('input', () => fitHeight(el));
  el.addEventListener('input', onSourceInput);
  el.addEventListener('keydown', (e) => {
    // Shift+Enter: newline
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      compileField(el);
      el.blur();
    } else if (e.key === 'Escape') {
      el.blur();
    }
  });
}

// re-run the current example, staying on the same step where possible
function reload() {
  const step = state.step;
  load();
  go(step);
}

function setAlt(on) {
  state.alt = on;
  savePref('alt', on ? 'on' : 'off');
  reload();
}

// crossing the phone width turns the alt stack on or off
PHONE.onchange = reload;

// desktop: some controls move into [data-desk] slots, next to what they change;
// phone: they stay where the markup has them (the toggles in the header)
const movable = [...document.querySelectorAll('[data-desk]')].map((slot) => {
  const el = $(slot.dataset.desk).closest('label');
  return { el, slot, home: el.parentNode, next: el.nextSibling };
});
const placeControls = () => {
  for (const { el, slot, home, next } of movable) {
    if (PHONE.matches) home.insertBefore(el, next);
    else slot.append(el);
  }
};
placeControls();
PHONE.addEventListener('change', placeControls);

$('alt-toggle').onchange = (e) => {
  e.target.blur();
  setAlt(e.target.checked);
};

function setTestKeys(on) {
  state.testKeys = on;
  savePref('testKeys', on ? 'on' : 'off');
  reload();
}

$('keys-toggle').onchange = (e) => {
  e.target.blur();
  setTestKeys(e.target.checked);
};

$('explain').onclick = (e) => {
  if (e.target.closest('#keys-on')) setTestKeys(true);
  if (e.target.closest('#alt-on')) setAlt(true);
  // phone: the opcode description is clamped to one line, a tap expands it
  const ex = $('explain').classList;
  if (e.target.closest('.desc, .more') && (ex.contains('clamped') || ex.contains('expanded'))) {
    ex.toggle('expanded');
    ex.remove('clamped');
    const d = $('explain').querySelector('.desc');
    if (!ex.contains('expanded')) ex.toggle('clamped', d.scrollHeight > d.clientHeight + 1);
  }
};

$('timeline').onclick = (e) => {
  const t = e.target.closest('[data-step]');
  if (t) go(Number(t.dataset.step));
};

// clicking a script line jumps to the step that executed it (if reached)
$('script').onclick = $('strip').onclick = (e) => {
  // a grouped row outside its ops (the pc number) means its first op
  const li = e.target.closest('[data-pc]') ?? e.target.closest('.group')?.querySelector('[data-pc]');
  if (!li) return;
  const i = trace.steps.findIndex((s) => s.pcs.includes(Number(li.dataset.pc)));
  if (i >= 0) go(i);
};

// phone: the source panel folds down to its header (example picker)
function setSrcFold(folded) {
  document.body.classList.toggle('src-folded', folded);
  $('src-fold').textContent = folded ? '▸ edit' : '▾ hide';
  $('src-fold').setAttribute('aria-expanded', String(!folded));
  savePref('srcFold', folded ? 'on' : 'off');
}
$('src-fold').onclick = (e) => {
  setSrcFold(!document.body.classList.contains('src-folded'));
  e.currentTarget.blur();
};

// phone: horizontal swipe steps (left = forward, like turning a page)
const SWIPE_MIN = 50;
let swipe = null;
const explore = document.querySelector('main.explore');
explore.addEventListener(
  'touchstart',
  (e) => {
    const t = e.touches[0];
    swipe = e.touches.length === 1 && !e.target.closest('input, textarea, select') ? { x: t.clientX, y: t.clientY } : null;
  },
  { passive: true },
);
explore.addEventListener('touchend', (e) => {
  if (!swipe) return;
  const t = e.changedTouches[0];
  const dx = t.clientX - swipe.x;
  const dy = t.clientY - swipe.y;
  swipe = null;
  if (Math.abs(dx) < SWIPE_MIN || Math.abs(dx) < 1.5 * Math.abs(dy)) return;
  if (dx < 0) next();
  else go(state.step - 1);
});

// hovering (or tapping, on a phone) a miniscript fragment highlights the opcodes it produced
function highlightFrag(f) {
  const ops = f?.dataset.all ? f.dataset.all.split(',').map(Number) : [];
  for (const li of [...$('script').querySelectorAll('[data-pc]'), ...$('strip').children]) li.classList.toggle('hl', ops.includes(Number(li.dataset.pc)));
  for (const row of $('script').querySelectorAll('.group')) row.classList.toggle('hl', !!row.querySelector('.hl'));
  for (const x of $('miniscript').querySelectorAll('.frag')) x.classList.toggle('hover', x === f);
  const opsText = [...$('strip').children].filter((li) => li.classList.contains('hl')).map((li) => li.textContent);
  $('frag-ops').textContent = opsText.length ? `→ ${opsText.join(' ')}` : '';
  $('frag-ops').hidden = !PHONE.matches || !opsText.length;
}
$('miniscript').onmouseover = (e) => highlightFrag(e.target.closest('.frag'));
$('miniscript').onmouseleave = () => highlightFrag(null);
// a tap outside the map clears it: touch screens send no mouseleave
document.addEventListener('click', (e) => {
  if (PHONE.matches) highlightFrag(e.target.closest('#miniscript .frag'));
});

// Step keys are caught in the capture phase, so they work whatever has focus
// (the example select, a chip, a button). Text fields keep their keys:
// Enter / Esc leaves the field, then the step keys work again.
const STEP_KEYS = {
  ArrowRight: next,
  l: next,
  ArrowLeft: () => go(state.step - 1),
  h: () => go(state.step - 1),
};

document.addEventListener(
  'keydown',
  (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey || $('help-dlg').open) return;
    if (e.target.matches('input[type=text], textarea')) return;
    if (e.key === '?') {
      e.preventDefault();
      openHelp();
      return;
    }
    const fn = STEP_KEYS[e.key] ?? KEYS[e.key];
    if (!fn) return;
    e.preventDefault();
    e.stopPropagation();
    fn();
  },
  true,
);

const KEYS = {
  Home: () => go(0),
  End: () => go(last()),
  ' ': next,
  k: () => setTestKeys(!state.testKeys),
  a: () => setAlt(!state.alt),
  d: () => setMode('miniscript'), // the "descriptor" mode: policy -> miniscript -> descriptor
  s: () => setMode('script'),
  e: editSource,
  n: nextPath,
};

// E: the cursor into the first source field of the mode that has text (policy is
// empty for a miniscript or descriptor source), at the end of that text
function editSource() {
  setSrcFold(false);
  const fields = state.mode === 'script' ? ['in-script'] : ['in-policy', 'in-miniscript', 'in-descriptor'];
  const el = $(fields.find((f) => $(f).value.trim()) ?? fields[0]);
  el.focus();
  el.setSelectionRange(el.value.length, el.value.length);
}

function openHelp() {
  $('help-dlg').showModal();
  $('help-dlg').focus(); // not the × button: no focus ring on open
}
$('help').onclick = (e) => {
  e.currentTarget.blur();
  openHelp();
};
$('help-close').onclick = () => $('help-dlg').close();
// a click on the backdrop lands on the dialog element itself
$('help-dlg').onclick = (e) => {
  if (e.target === e.currentTarget) e.currentTarget.close();
};

// --- permalinks (link.js): the URL fragment follows the run, so copying it shares this view ---

let linked = location.hash; // what we wrote last: a hashchange to it is our own

function updateLink() {
  if (!state.live) return; // nothing compiled yet (or offline): keep the link that came in
  const at = state.scenario !== null ? { example: scenarios[state.scenario].name } : state.origin && { source: state.origin };
  if (!at) return;
  const hash = writeLink({ ...at, path: state.path, step: state.step, mode: state.mode });
  if (hash === location.hash) return;
  linked = hash;
  history.replaceState(null, '', hash);
}

// open what a link names: compile it, then its path and step, bounded by the run
async function openLink(link) {
  setMode(link.mode);
  if (link.example !== undefined) await loadExample(link.example);
  else {
    if (link.source.wrap) state.wrap = link.source.wrap;
    const el = $(INPUTS[link.source.kind]);
    el.value = link.source.text;
    await compileField(el);
  }
  if (!state.live) return;
  const path = Math.min(link.path, Math.max(0, state.live.paths.length - 1));
  if (path !== state.path) {
    state.path = path;
    load();
  }
  go(link.step);
}

const exampleNames = scenarios.map((s) => s.name);

// a link pasted into this tab
window.addEventListener('hashchange', () => {
  if (location.hash === linked) return;
  const link = readLink(location.hash, exampleNames);
  if (link) openLink(link);
});

initTheme();
setSrcFold(loadPref('srcFold', 'on') === 'on');
load(); // empty first, so there is something to draw while the backend answers
// a link opens its view; else start on a wsh example (the output type the policy / miniscript fields are made for)
const opened = readLink(location.hash, exampleNames);
if (opened) openLink(opened);
else loadExample(Math.max(0, scenarios.findIndex((s) => s.name.startsWith('P2WSH'))));
