// A private key in the source text is stopped here, before it is sent anywhere or put in
// the URL. By shape only (WIF: 51-52 base58 chars from 5 / 9 / K / L / c; xprv / tprv); the
// server checks again by decoding.

const B58 = '[1-9A-HJ-NP-Za-km-z]';
const PRIVATE = new RegExp(`(^|[^1-9A-Za-z])([59]${B58}{50}|[KLc]${B58}{51}|[xt]prv${B58}{100,})(?![1-9A-Za-z])`);

export const privateKeyIn = (text) => PRIVATE.test(text);
