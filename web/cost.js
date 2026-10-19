// Desktop side panels under the source: the input as sent (witness / scriptSig) for the
// current spend path, and what every path costs, with the script limits it runs into.

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const $ = (id) => document.getElementById(id);
const bytes = (it) => it.hex.length / 2;

// stack + alt stack at their highest point of the run (consensus limit 1000)
const peak = (t) => Math.max(0, ...t.steps.map((s) => s.stack.length + s.alt.length));

const SCRIPT_NAME = { wsh: 'witnessScript', sh: 'redeemScript' };
// how the script item at the end is checked before it runs
const SCRIPT_CHECK = {
  wsh: 'its sha256 must match the scriptPubKey; then it runs on the items above',
  sh: 'its hash160 must match the scriptPubKey; then it runs on the items above',
};

// Core: consensus (block-invalid) vs standard (relayed and mined by default)
function limits(sc, path, t) {
  const sp = path.spend;
  const data = sp.script_last ? sp.items.slice(0, -1) : sp.items;
  const out = [];
  if (sc.wrap === 'wsh') {
    out.push(['witnessScript', sc.script_bytes, 3600, 'standard', 'B']);
    out.push(['witness items', data.length, 100, 'standard', '']);
    out.push(['largest item', Math.max(0, ...data.map(bytes)), 80, 'standard', 'B']);
  } else if (sc.wrap === 'sh') {
    out.push(['redeemScript', sc.script_bytes, 520, 'consensus', 'B']);
  }
  if (sp.field === 'scriptSig') out.push(['scriptSig', sp.bytes, 1650, 'standard', 'B']);
  out.push(['ops', t.ops, 201, 'consensus', '']);
  out.push(['stack peak', peak(t), 1000, 'consensus', '']);
  return out;
}

export function renderCost(sc, pathIdx) {
  const path = sc.paths[pathIdx];
  const t = sc.traces[pathIdx];
  document.body.classList.toggle('no-cost', !path);
  if (!path) return;
  const sp = path.spend;

  // the input as sent
  $('spend-title').textContent = sp.field;
  const scriptName = SCRIPT_NAME[sc.wrap];
  $('spend-items').innerHTML = sp.items
    .map((it, i) => {
      const isScript = sp.script_last && i === sp.items.length - 1;
      const note = isScript ? `<div class="spend-note">not stack data: ${esc(SCRIPT_CHECK[sc.wrap] ?? 'it is checked, then run')}</div>` : '';
      return `<li class="${isScript ? 'is-script' : ''}"><span class="spend-i">${i}</span><span class="chipx k-${it.kind}">${esc(isScript && scriptName ? scriptName : it.label)}</span><span class="spend-b">${bytes(it)} B</span>${note}</li>`;
    })
    .join('');
  const what = sp.field === 'witness' ? 'witness' : 'scriptSig';
  $('spend-size').innerHTML =
    `${what} <b>${sp.bytes} B</b> · input <b title="the whole input: outpoint, scriptSig and sequence at 4 weight units per byte, the witness at 1; divided by 4">${sp.vbytes} vB</b>`;

  // every path: what it costs and how close it runs to the limits
  const rows = sc.paths.map((p, i) => {
    const tr = sc.traces[i];
    const res = tr.result.ok ? '<span class="ok">✓</span>' : `<span class="fail" title="${esc(tr.result.message)}">✗</span>`;
    return `<tr data-path="${i}" class="${i === pathIdx ? 'current' : ''}"><td class="cost-name">${esc(p.name)}</td><td>${p.spend.vbytes}</td><td>${tr.ops}</td><td>${peak(tr)}</td><td>${res}</td></tr>`;
  });
  $('cost').innerHTML =
    '<thead><tr><th>path</th><th title="input size in vbytes">vB</th><th title="opcodes counted toward the 201 limit">ops</th><th title="stack + alt stack at the highest point">stack</th><th></th></tr></thead>' +
    `<tbody>${rows.join('')}</tbody>`;

  $('limits').innerHTML = limits(sc, path, t)
    .map(([name, v, max, rule, unit]) => {
      // only a breach is marked: a signature is always 72 of the 80 bytes, that is no warning
      const cls = v > max ? 'over' : '';
      return `<li class="${cls}"><span>${name}</span><span class="lim-v">${v}${unit && ` ${unit}`} / ${max}</span><span class="lim-rule ${rule}">${rule}</span></li>`;
    })
    .join('');
}
