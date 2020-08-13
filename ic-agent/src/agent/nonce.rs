use crate::Blob;
use rand::rngs::OsRng;
use rand::Rng;
use std::sync::Mutex;

/// A Factory for nonce blobs.
pub struct NonceFactory {
    inner: Mutex<Box<dyn Iterator<Item = Blob> + Send>>,
}

impl NonceFactory {
    pub fn from_iterator(iter: Box<dyn Iterator<Item = Blob> + Send>) -> Self {
        Self {
            inner: Mutex::new(iter),
        }
    }

    pub fn random() -> NonceFactory {
        Self::from_iterator(Box::new(RandomBlobIter {}))
    }

    pub fn empty() -> NonceFactory {
        Self::from_iterator(Box::new(EmptyBlobIter {}))
    }

    pub fn incrementing() -> NonceFactory {
        Self::from_iterator(Box::new(IncrementingIter { next: 0 }))
    }

    pub fn generate(&self) -> Option<Blob> {
        self.inner.lock().unwrap().next()
    }
}

struct RandomBlobIter {}

impl Iterator for RandomBlobIter {
    type Item = Blob;

    fn next(&mut self) -> Option<Self::Item> {
        Some(Blob(OsRng.gen::<[u8; 16]>().to_vec()))
    }
}

struct EmptyBlobIter {}

impl Iterator for EmptyBlobIter {
    type Item = Blob;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

struct IncrementingIter {
    next: u64,
}

impl Iterator for IncrementingIter {
    type Item = Blob;

    fn next(&mut self) -> Option<Self::Item> {
        let blob = Blob(self.next.to_le_bytes().to_vec());
        self.next += 1;
        Some(blob)
    }
}
