const wasm = require('./keccak-tiny.wasm');

// The emscripten's Module object.
// See http://kripken.github.io/emscripten-site/docs/api_reference/module.html for details.
var Module = {};

Module.noInitialRun = true;
Module.wasmBinary = wasm;
