#![allow(dead_code)]

use std::future::Future;
use std::time::Duration;

pub async fn sleep(d: Duration) {
    #[cfg(not(all(target_family = "wasm", feature = "wasm-bindgen")))]
    tokio::time::sleep(d).await;
    #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
    wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |rs, rj| {
        use wasm_bindgen::{JsCast, UnwrapThrowExt};

        let global = js_sys::global();
        let res = if let Some(window) = global.dyn_ref::<web_sys::Window>() {
            window.set_timeout_with_callback_and_timeout_and_arguments_0(&rs, d.as_millis() as _)
        } else if let Some(worker) = global.dyn_ref::<web_sys::WorkerGlobalScope>() {
            worker.set_timeout_with_callback_and_timeout_and_arguments_0(&rs, d.as_millis() as _)
        } else {
            panic!("global window or worker unavailable");
        };
        if let Err(e) = res {
            rj.call1(&rj, &e).unwrap_throw();
        }
    }))
    .await
    .expect("unable to setTimeout");
    #[cfg(all(target_family = "wasm", not(feature = "wasm-bindgen")))]
    const _: () =
        { panic!("Using ic-agent from WASM requires enabling the `wasm-bindgen` feature") };
}

#[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
pub fn spawn(f: impl Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(f);
}

#[cfg(not(all(target_family = "wasm", feature = "wasm-bindgen")))]
pub fn spawn(f: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(f);
}

macro_rules! log {
    ($name:ident, $($t:tt)*) => { #[cfg(feature = "tracing")] { tracing::$name!($($t)*) } };
}
