use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::sink::Sink;
use wasm_bindgen::prelude::*;

/// A Sink that always errors on the first write.
pub struct FailingSink {
    failed: bool,
}

impl FailingSink {
    pub fn new() -> Self {
        Self { failed: false }
    }
}

impl Default for FailingSink {
    fn default() -> Self {
        Self::new()
    }
}

impl Sink<JsValue> for FailingSink {
    type Error = JsValue;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, _item: JsValue) -> Result<(), Self::Error> {
        if !self.failed {
            self.failed = true;
            // Return an error on first write
            Err(JsValue::from_str("intentional error"))
        } else {
            Ok(())
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.failed {
            Poll::Ready(Err(JsValue::from_str("sink has failed")))
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}
