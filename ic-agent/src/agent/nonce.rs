use rand::{rngs::OsRng, Rng};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

/// A Factory for nonce blobs.
#[derive(Clone)]
pub struct NonceFactory {
    inner: Arc<dyn NonceGenerator>,
}

impl NonceFactory {
    /// Creates a nonce factory from an iterator over blobs. The iterator is not assumed to be fused.
    pub fn from_iterator(iter: Box<dyn Iterator<Item = Vec<u8>> + Send>) -> Self {
        Self {
            inner: Arc::new(Iter::from(iter)),
        }
    }

    /// Creates a nonce factory that generates random blobs using `getrandom`.
    pub fn random() -> NonceFactory {
        Self {
            inner: Arc::new(RandomBlob {}),
        }
    }

    /// Creates a nonce factory that returns None every time.
    pub fn empty() -> NonceFactory {
        Self {
            inner: Arc::new(Empty),
        }
    }

    /// Creates a nonce factory that generates incrementing blobs.
    pub fn incrementing() -> NonceFactory {
        Self {
            inner: Arc::new(Incrementing::default()),
        }
    }

    /// Generates a nonce, if one is available. Otherwise, returns None.
    pub fn generate(&self) -> Option<Vec<u8>> {
        NonceGenerator::generate(self)
    }
}

impl NonceGenerator for NonceFactory {
    fn generate(&self) -> Option<Vec<u8>> {
        self.inner.generate()
    }
}

/// An interface for generating nonces.
pub trait NonceGenerator: Send + Sync {
    /// Generates a nonce, if one is available. Otherwise, returns None.
    fn generate(&self) -> Option<Vec<u8>>;
}

#[expect(unused)]
pub(crate) struct Func<T>(pub T);
impl<T: Send + Sync + Fn() -> Option<Vec<u8>>> NonceGenerator for Func<T> {
    fn generate(&self) -> Option<Vec<u8>> {
        (self.0)()
    }
}

pub(crate) struct Iter<T>(Mutex<T>);
impl<T: Send + Iterator<Item = Vec<u8>>> From<T> for Iter<T> {
    fn from(val: T) -> Iter<T> {
        Iter(Mutex::new(val))
    }
}
impl<T: Send + Iterator<Item = Vec<u8>>> NonceGenerator for Iter<T> {
    fn generate(&self) -> Option<Vec<u8>> {
        self.0.lock().unwrap().next()
    }
}

#[derive(Default)]
pub(crate) struct RandomBlob {}
impl NonceGenerator for RandomBlob {
    fn generate(&self) -> Option<Vec<u8>> {
        Some(OsRng.gen::<[u8; 16]>().to_vec())
    }
}

#[derive(Default)]
pub(crate) struct Empty;
impl NonceGenerator for Empty {
    fn generate(&self) -> Option<Vec<u8>> {
        None
    }
}

#[derive(Default)]
pub(crate) struct Incrementing {
    next: AtomicU64,
}
impl From<u64> for Incrementing {
    fn from(val: u64) -> Incrementing {
        Incrementing {
            next: AtomicU64::new(val),
        }
    }
}
impl NonceGenerator for Incrementing {
    fn generate(&self) -> Option<Vec<u8>> {
        let val = self.next.fetch_add(1, Ordering::Relaxed);
        Some(val.to_le_bytes().to_vec())
    }
}

impl<N: NonceGenerator + ?Sized> NonceGenerator for Box<N> {
    fn generate(&self) -> Option<Vec<u8>> {
        (**self).generate()
    }
}
impl<N: NonceGenerator + ?Sized> NonceGenerator for Arc<N> {
    fn generate(&self) -> Option<Vec<u8>> {
        (**self).generate()
    }
}
