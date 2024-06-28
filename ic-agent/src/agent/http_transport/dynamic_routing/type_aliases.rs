use arc_swap::ArcSwap;
use std::sync::Arc;
use tokio::sync::{mpsc, watch};

/// A type alias for the sender end of a watch channel.
pub type SenderWatch<T> = watch::Sender<Option<T>>;

/// A type alias for the receiver end of a watch channel.
pub type ReceiverWatch<T> = watch::Receiver<Option<T>>;

/// A type alias for the sender end of a multi-producer, single-consumer channel.
pub type SenderMpsc<T> = mpsc::Sender<T>;

/// A type alias for the receiver end of a multi-producer, single-consumer channel.
pub type ReceiverMpsc<T> = mpsc::Receiver<T>;

/// A type alias for an atomic swap operation on a shared value.
pub type AtomicSwap<T> = Arc<ArcSwap<T>>;
