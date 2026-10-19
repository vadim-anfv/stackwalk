// Applies a saved theme before first paint (no flash): a classic script in <head>,
// not a module, so it runs before the body is drawn. The switch itself is in app.js.
try {
  const t = localStorage.getItem('stackwalk.theme');
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
} catch {}
