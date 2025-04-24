#![allow(dead_code)]

use std::cell::RefCell;
use std::future::Future;
use std::mem::swap;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::thread::LocalKey;
use std::time::Duration;

use pin_project::pin_project;

pub(crate) async fn sleep(d: Duration) {
    #[cfg(not(all(target_family = "wasm", feature = "wasm-bindgen")))]
    tokio::time::sleep(d).await;
    #[cfg(all(target_family = "wasm", feature = "wasm-bindgen"))]
    wasm_bindgen_futures::JsFuture::from(js_sys::Promise::new(&mut |rs, rj| {
        if let Err(e) = web_sys::window()
            .expect("global window unavailable")
            .set_timeout_with_callback_and_timeout_and_arguments_0(&rs, d.as_millis() as _)
        {
            use wasm_bindgen::UnwrapThrowExt;
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
pub(crate) fn spawn(f: impl Future<Output = ()> + 'static) {
    wasm_bindgen_futures::spawn_local(f);
}

#[cfg(not(all(target_family = "wasm", feature = "wasm-bindgen")))]
pub(crate) fn spawn(f: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(f);
}

macro_rules! log {
    ($name:ident, $($t:tt)*) => { #[cfg(feature = "tracing")] { tracing::$name!($($t)*) } };
}

pub(crate) struct TaskLocal<T>(RefCell<Option<T>>);

impl<T> TaskLocal<T> {
    pub(crate) const fn new() -> Self {
        Self(RefCell::new(None))
    }
}

#[pin_project]
pub(crate) struct TaskLocalContextFuture<T: 'static, F> {
    #[pin]
    f: F,
    t: Option<T>,
    key: &'static LocalKey<TaskLocal<T>>,
}

macro_rules! task_local {
    ($vis:vis static $name:ident : $type:ty ; ) => {
        std::thread_local! {
            $vis static $name : $crate::util::TaskLocal<$type> = $crate::util::TaskLocal::new();
        }
    };
}

pub(crate) fn in_context_of<T: 'static, F: Future>(
    key: &'static LocalKey<TaskLocal<T>>,
    val: T,
    f: F,
) -> TaskLocalContextFuture<T, F> {
    TaskLocalContextFuture {
        t: Some(val),
        f,
        key,
    }
}

impl<T, F> Future for TaskLocalContextFuture<T, F>
where
    F: Future,
{
    type Output = F::Output;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        this.key.with(|key| swap(&mut *key.0.borrow_mut(), this.t));
        let result = this.f.poll(cx);
        this.key.with(|key| swap(&mut *key.0.borrow_mut(), this.t));
        result
    }
}

pub(crate) struct NoContextError;

pub(crate) fn try_from_context<T: 'static, R>(
    key: &'static LocalKey<TaskLocal<T>>,
    f: impl FnOnce(&mut T) -> R,
) -> Result<R, NoContextError> {
    key.with(|key| {
        let mut borrow = key.0.borrow_mut();
        if let Some(val) = &mut *borrow {
            Ok(f(val))
        } else {
            Err(NoContextError)
        }
    })
}

pub(crate) fn from_context<T: 'static, R>(
    key: &'static LocalKey<TaskLocal<T>>,
    f: impl FnOnce(&mut T) -> R,
) -> R {
    try_from_context(key, f).unwrap_or_else(|_| panic!("no context available"))
}
