// Minimal CJS-style `require` shim for ESM-only runtimes (Vite/Tauri).
//
// Some optimized dependencies consult `require("react")` at runtime via esbuild's `__require`
// helper, which relies on a lexical `require` binding. Vite injects
// `var require = globalThis.require;` for optimized deps, so we only need
// `globalThis.require` defined before modules execute.
(function () {
  var registry = globalThis.__sdr_require__;
  if (!registry || typeof registry !== "object") {
    registry = globalThis.__sdr_require__ = Object.create(null);
  }

  var previousRequire = globalThis.require;
  globalThis.require = function (id) {
    if (Object.prototype.hasOwnProperty.call(registry, id)) {
      return registry[id];
    }
    if (typeof previousRequire === "function") {
      return previousRequire(id);
    }
    throw new Error('Unknown require: "' + id + '"');
  };
})();

