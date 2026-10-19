// DOM helpers shared by the modules. Every string that goes into innerHTML goes
// through esc; attributes in generated markup are always double-quoted.

export const $ = (id) => document.getElementById(id);
export const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
