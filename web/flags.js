// Feature flags. Set a flag to false to ship without that feature.
// Hidden markup is tagged with `flag-<name>` and hidden via body classes.
// Some features are also cut out of the deploy build: code between
// `flag:<name>` markers is removed by the release build (server/build/web.rs).
export const FLAGS = {
  // flag:train
  train: false, // train view: write the Script for a miniscript
  leaderboard: true, // train: leaderboard panel (needs a backend for real)
  // /flag:train
  altStack: true, // explore: alt stack column + scenarios that use it
};

export function applyFlags() {
  for (const [name, on] of Object.entries(FLAGS)) document.body.classList.toggle(`ff-${name}`, on);
}
