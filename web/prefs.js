// Per-browser preferences in localStorage (keys prefixed: the origin is shared with the
// rest of vadim.rs), and the theme switch. Storage may be unavailable: then defaults.
import { $ } from './dom.js';

export function loadPref(key, fallback) {
  try {
    return localStorage.getItem(`stackwalk.${key}`) ?? fallback;
  } catch {
    return fallback;
  }
}

export function savePref(key, value) {
  try {
    localStorage.setItem(`stackwalk.${key}`, value);
  } catch {}
}

// auto = follow the system; light / dark pin it (applied before first paint by theme.js)
const THEMES = ['auto', 'light', 'dark'];
const THEME_ICONS = { auto: '◐', light: '☀', dark: '☾' };

function setTheme(theme) {
  if (theme === 'auto') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
  // the name is hidden on narrow screens, the icon stays
  $('theme').innerHTML = `${THEME_ICONS[theme]}<span class="theme-name"> ${theme}</span>`;
  $('theme').title = `Theme: ${theme} (auto = system). Click: auto → light → dark`;
  savePref('theme', theme);
}

export function initTheme() {
  setTheme(THEMES.includes(loadPref('theme')) ? loadPref('theme') : 'auto');
  $('theme').onclick = (e) => {
    const cur = loadPref('theme', 'auto');
    setTheme(THEMES[(THEMES.indexOf(cur) + 1) % THEMES.length]);
    e.currentTarget.blur();
  };
}
