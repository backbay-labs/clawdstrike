use js_sys::Object;
use wasm_bindgen::{prelude::wasm_bindgen, JsCast};

#[wasm_bindgen]
extern "C" {
    pub type GlobalScope;

    pub type Performance;

    #[wasm_bindgen(structural, method, getter, js_name = "performance")]
    pub fn performance(this: &GlobalScope) -> Performance;

    #[wasm_bindgen(method, js_name = "now")]
    pub fn now(this: &Performance) -> f64;

    #[cfg(feature = "tokio")]
    #[wasm_bindgen(catch , method, js_name = setTimeout)]
    pub fn set_timeout_with_callback_and_timeout_and_arguments_0(
        this: &GlobalScope,
        handler: &::js_sys::Function,
        timeout: i32,
    ) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue>;
}

pub fn performance_now() -> f64 {
    let global_this: Object = js_sys::global();
    let global_scope = global_this.unchecked_ref::<GlobalScope>();
    global_scope.performance().now()
}

#[cfg(feature = "tokio")]
pub fn set_timeout(
    handler: &::js_sys::Function,
    timeout: i32,
) -> Result<wasm_bindgen::JsValue, wasm_bindgen::JsValue> {
    let global_this: Object = js_sys::global();
    let global_scope = global_this.unchecked_ref::<GlobalScope>();
    global_scope.set_timeout_with_callback_and_timeout_and_arguments_0(handler, timeout)
}
