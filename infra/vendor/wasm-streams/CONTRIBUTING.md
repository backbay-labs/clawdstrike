# Testing

The tests use [wasm-pack](https://drager.github.io/wasm-pack/).
See the [wasm-bindgen guide](https://wasm-bindgen.github.io/wasm-bindgen/wasm-bindgen-test/usage.html) for more information.

We run the tests in Node.js, Chrome and Firefox:
```
wasm-pack test --node
WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --headless --chrome
WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --headless --firefox
```

When debugging the browser tests, remove the `--headless` flag:
```
WASM_BINDGEN_USE_BROWSER=1 wasm-pack test --chrome
```
