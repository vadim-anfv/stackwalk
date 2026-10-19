// Train mode: show a miniscript, the user types the Script it compiles to.
// Exercises and the leaderboard are mock data for UI design.

import { ALIASES, suggest, tokenize } from './ops.js';

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);

const EXERCISES = [
  { ms: 'pk(A)', level: 1, answer: ['<A>', 'OP_CHECKSIG'] },
  { ms: 'pkh(A)', level: 1, answer: ['OP_DUP', 'OP_HASH160', '<HASH160(A)>', 'OP_EQUALVERIFY', 'OP_CHECKSIG'] },
  { ms: 'multi(2,A,B,C)', level: 1, answer: ['OP_2', '<A>', '<B>', '<C>', 'OP_3', 'OP_CHECKMULTISIG'] },
  { ms: 'and_v(v:pk(A),pk(B))', level: 2, answer: ['<A>', 'OP_CHECKSIGVERIFY', '<B>', 'OP_CHECKSIG'] },
  { ms: 'or_d(pk(A),pk(B))', level: 2, answer: ['<A>', 'OP_CHECKSIG', 'OP_IFDUP', 'OP_NOTIF', '<B>', 'OP_CHECKSIG', 'OP_ENDIF'] },
  { ms: 'or_b(pk(A),s:pk(B))', level: 2, answer: ['<A>', 'OP_CHECKSIG', 'OP_SWAP', '<B>', 'OP_CHECKSIG', 'OP_BOOLOR'] },
  { ms: 'and_v(v:pk(A),older(144))', level: 2, answer: ['<A>', 'OP_CHECKSIGVERIFY', '<144>', 'OP_CHECKSEQUENCEVERIFY'] },
  {
    ms: 'andor(pk(A),older(1008),pk(B))',
    level: 3,
    answer: ['<A>', 'OP_CHECKSIG', 'OP_NOTIF', '<B>', 'OP_CHECKSIG', 'OP_ELSE', '<1008>', 'OP_CHECKSEQUENCEVERIFY', 'OP_ENDIF'],
  },
  {
    ms: 'thresh(2,pk(A),s:pk(B),s:pk(C))',
    level: 3,
    answer: ['<A>', 'OP_CHECKSIG', 'OP_SWAP', '<B>', 'OP_CHECKSIG', 'OP_ADD', 'OP_SWAP', '<C>', 'OP_CHECKSIG', 'OP_ADD', 'OP_2', 'OP_EQUAL'],
  },
];

// one-tap tokens for phones, where there is no Tab key
const PALETTE = ['A', 'B', 'C', 'sig', 'sigv', 'dup', 'h160', 'eqv', 'eq', 'if', 'notif', 'else', 'fi', 'ifdup', 'swap', 'add', 'csv', 'cltv', 'msig', 'v'];

const BOARD = {
  today: [
    { name: 'satoshi_fan', solved: 41, acc: 98, avg: 6.2 },
    { name: 'opcode_ninja', solved: 37, acc: 95, avg: 7.9 },
    { name: 'tapleaf', solved: 30, acc: 91, avg: 8.4 },
    { name: 'hodl_reader', solved: 22, acc: 88, avg: 11.0 },
    { name: 'csv_enjoyer', solved: 15, acc: 80, avg: 14.3 },
  ],
  week: [
    { name: 'opcode_ninja', solved: 212, acc: 96, avg: 7.1 },
    { name: 'satoshi_fan', solved: 198, acc: 97, avg: 6.8 },
    { name: 'witness_w', solved: 140, acc: 93, avg: 9.2 },
    { name: 'tapleaf', solved: 121, acc: 90, avg: 8.9 },
    { name: 'hodl_reader', solved: 87, acc: 86, avg: 12.4 },
  ],
  all: [
    { name: 'opcode_ninja', solved: 1840, acc: 95, avg: 7.4 },
    { name: 'witness_w', solved: 1502, acc: 94, avg: 8.8 },
    { name: 'satoshi_fan', solved: 1311, acc: 97, avg: 6.9 },
    { name: 'tapleaf', solved: 990, acc: 91, avg: 9.0 },
    { name: 'csv_enjoyer', solved: 640, acc: 83, avg: 13.1 },
  ],
};

const t = {
  idx: -1,
  checked: false,
  correct: false,
  revealed: false,
  started: 0,
  stopped: 0,
  sel: 0,
  board: 'today',
  stats: { solved: 0, attempts: 0, streak: 0, best: null, times: [] },
};

let timer;

export function initTrain() {
  $('t-input').addEventListener('input', update);
  $('t-input').addEventListener('keydown', onKey);
  $('t-input').addEventListener('click', update);
  $('t-check').onclick = check;
  $('t-answer').onclick = () => {
    t.revealed = true;
    t.checked = true;
    t.stats.streak = 0;
    renderResult();
    renderStats();
    $('t-input').focus();
  };
  $('t-next').onclick = next;
  // mousedown keeps the textarea focused, so the phone keyboard stays open
  $('t-suggest').onmousedown = $('t-palette').onmousedown = (e) => e.preventDefault();
  $('t-suggest').onclick = (e) => {
    const b = e.target.closest('[data-i]');
    if (!b) return;
    t.sel = Number(b.dataset.i);
    accept();
  };
  $('t-palette').innerHTML = PALETTE.map((p) => `<button data-tok="${esc(p)}">${esc(p)}</button>`).join('');
  $('t-palette').onclick = (e) => {
    const b = e.target.closest('[data-tok]');
    if (b) insert(b.dataset.tok);
  };
  $('t-board-tabs').onclick = (e) => {
    const b = e.target.closest('[data-board]');
    if (!b) return;
    t.board = b.dataset.board;
    renderBoard();
  };
  $('t-cheats').innerHTML =
    Object.entries(ALIASES)
      .map(([a, op]) => `<div><kbd>${esc(a)}</kbd><span>OP_${esc(op)}</span></div>`)
      .join('') +
    '<div><kbd>A</kbd><span>&lt;A&gt; key push</span></div>' +
    '<div><kbd>h(A)</kbd><span>&lt;HASH160(A)&gt;</span></div>' +
    '<div><kbd>144</kbd><span>&lt;144&gt; / OP_2 for 0..16</span></div>' +
    '<div><kbd>dup</kbd><span>full names work too</span></div>';
  next();
}

export function focusTrain() {
  $('t-input').focus();
}

function next() {
  let i;
  do i = Math.floor(Math.random() * EXERCISES.length);
  while (EXERCISES.length > 1 && i === t.idx);
  t.idx = i;
  t.checked = t.correct = t.revealed = false;
  t.started = performance.now();
  t.stopped = 0;
  $('t-input').value = '';
  const ex = EXERCISES[i];
  $('t-ms').textContent = ex.ms;
  $('t-level').textContent = `level ${ex.level}`;
  clearInterval(timer);
  timer = setInterval(renderTimer, 200);
  update();
  renderResult();
  renderStats();
  renderBoard();
  $('t-input').focus();
}

function currentToken() {
  const el = $('t-input');
  const before = el.value.slice(0, el.selectionStart);
  return /\S*$/.exec(before)[0];
}

function update() {
  const toks = tokenize($('t-input').value);
  $('t-preview').innerHTML = toks.length
    ? toks.map((x) => `<span class="tok tok-${x.kind}">${esc(x.canon)}</span>`).join('')
    : '<span class="muted">tokens appear here as you type</span>';

  const list = suggest(currentToken());
  t.sel = Math.min(t.sel, Math.max(list.length - 1, 0));
  $('t-suggest').innerHTML = list.length
    ? list
        .map((s, i) => `<button class="sug ${i === t.sel ? 'on' : ''}" data-i="${i}"><b>${esc(s.typed)}</b> → ${esc(s.op)}</button>`)
        .join('') + '<span class="muted hint"><kbd>Tab</kbd> complete · <kbd>↑</kbd><kbd>↓</kbd> pick</span>'
    : '';
  t.suggestions = list;

  if (t.checked && !t.correct && !t.revealed) {
    t.checked = false;
    renderResult();
  }
}

// Insert a token at the caret (palette tap); replaces a partially typed token.
function insert(tok) {
  const el = $('t-input');
  const partial = currentToken();
  const start = el.selectionStart - partial.length;
  const tail = el.value.slice(el.selectionStart).replace(/^\S*\s*/, '');
  const head = el.value.slice(0, start);
  const sep = head && !/\s$/.test(head) ? ' ' : '';
  el.value = head + sep + tok + ' ' + tail;
  el.selectionStart = el.selectionEnd = (head + sep + tok + ' ').length;
  update();
}

function accept() {
  const s = t.suggestions?.[t.sel];
  if (!s) return false;
  const el = $('t-input');
  const tok = currentToken();
  const start = el.selectionStart - tok.length;
  const rest = el.value.slice(el.selectionStart).replace(/^\S*/, '');
  el.value = el.value.slice(0, start) + s.op + ' ' + rest.replace(/^\s+/, '');
  el.selectionStart = el.selectionEnd = start + s.op.length + 1;
  t.sel = 0;
  update();
  return true;
}

function onKey(e) {
  const open = t.suggestions?.length > 0;
  if (e.key === 'Tab' && open) {
    e.preventDefault();
    accept();
  } else if (e.key === 'ArrowDown' && open) {
    e.preventDefault();
    t.sel = (t.sel + 1) % t.suggestions.length;
    update();
  } else if (e.key === 'ArrowUp' && open) {
    e.preventDefault();
    t.sel = (t.sel - 1 + t.suggestions.length) % t.suggestions.length;
    update();
  } else if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    next();
  } else if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    if (t.checked && (t.correct || t.revealed)) next();
    else check();
  } else if (e.key === 'Escape') {
    $('t-suggest').innerHTML = '';
    t.suggestions = [];
  }
}

function check() {
  const got = tokenize($('t-input').value).map((x) => x.canon);
  if (!got.length) return;
  const ex = EXERCISES[t.idx];
  t.correct = got.length === ex.answer.length && got.every((x, i) => x === ex.answer[i]);
  t.checked = true;
  t.stats.attempts++;
  if (t.correct) {
    t.stopped = performance.now();
    const secs = (t.stopped - t.started) / 1000;
    t.stats.solved++;
    t.stats.streak++;
    t.stats.times.push(secs);
    t.stats.best = t.stats.best === null ? secs : Math.min(t.stats.best, secs);
  } else {
    t.stats.streak = 0;
  }
  renderResult();
  renderStats();
  renderBoard();
}

function renderTimer() {
  const end = t.stopped || performance.now();
  $('t-timer').textContent = `${((end - t.started) / 1000).toFixed(1)}s`;
}

function renderResult() {
  const box = $('t-result');
  if (!t.checked) {
    box.className = 'panel t-result';
    box.innerHTML = '<span class="muted">Enter to check · Ctrl+Enter to skip</span>';
    return;
  }
  const ex = EXERCISES[t.idx];
  const got = tokenize($('t-input').value).map((x) => x.canon);
  const n = Math.max(got.length, ex.answer.length);
  const yours = [];
  const expected = [];
  for (let i = 0; i < n; i++) {
    const g = got[i];
    const a = ex.answer[i];
    yours.push(g === undefined ? '<span class="tok missing">·</span>' : `<span class="tok ${g === a ? 'good' : 'bad'}">${esc(g)}</span>`);
    expected.push(a === undefined ? '<span class="tok missing">·</span>' : `<span class="tok ${g === a ? 'good' : 'want'}">${esc(a)}</span>`);
  }
  const showAnswer = !t.correct;
  box.className = `panel t-result ${t.correct ? 'ok' : 'fail'}`;
  box.innerHTML = `
    <div class="verdict">${t.correct ? '✓ correct, Enter for next' : t.revealed ? 'answer shown, Enter for next' : '✗ not quite, fix it and press Enter again'}</div>
    <div class="cmp"><span class="k">yours</span><div class="toks">${yours.join('')}</div></div>
    ${showAnswer && t.revealed ? `<div class="cmp"><span class="k">expected</span><div class="toks">${expected.join('')}</div></div>` : ''}`;
}

function renderStats() {
  const s = t.stats;
  const avg = s.times.length ? s.times.reduce((a, b) => a + b, 0) / s.times.length : null;
  const acc = s.attempts ? Math.round((s.solved / s.attempts) * 100) : null;
  $('t-stats').innerHTML = [
    ['solved', s.solved],
    ['streak', s.streak],
    ['accuracy', acc === null ? '–' : `${acc}%`],
    ['avg time', avg === null ? '–' : `${avg.toFixed(1)}s`],
    ['best', s.best === null ? '–' : `${s.best.toFixed(1)}s`],
  ]
    .map(([k, v]) => `<div class="stat"><span class="v">${v}</span><span class="k">${k}</span></div>`)
    .join('');
}

function renderBoard() {
  for (const b of $('t-board-tabs').children) b.classList.toggle('on', b.dataset.board === t.board);
  const s = t.stats;
  const you = {
    name: 'you',
    solved: s.solved,
    acc: s.attempts ? Math.round((s.solved / s.attempts) * 100) : 0,
    avg: s.times.length ? s.times.reduce((a, b) => a + b, 0) / s.times.length : 0,
    you: true,
  };
  const rows = [...BOARD[t.board], you].sort((a, b) => b.solved - a.solved);
  $('t-board').innerHTML =
    '<tr><th>#</th><th>name</th><th>solved</th><th>acc</th><th>avg</th></tr>' +
    rows
      .map(
        (r, i) =>
          `<tr class="${r.you ? 'you' : ''}"><td>${i + 1}</td><td>${esc(r.name)}</td><td>${r.solved}</td><td>${r.acc}%</td><td>${r.avg ? r.avg.toFixed(1) + 's' : '–'}</td></tr>`,
      )
      .join('');
}
