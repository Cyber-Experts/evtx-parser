// Tiny shim for the deprecated `node-domexception` package. Node ≥ 17 has
// `DOMException` as a global; fetch-blob's only use of this dep is a
// runtime fallback for older Node, which Vercel and modern dev shells no
// longer hit. Re-exporting the global makes the deprecation warning go
// away without changing behavior.
module.exports = globalThis.DOMException;
