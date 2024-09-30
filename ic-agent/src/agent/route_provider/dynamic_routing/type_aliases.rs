use arc_swap::ArcSwap;
use std::sync::Arc;

/// A type alias for the sender end of a watch channel.
pub(super) type SenderWatch<T> = async_watch::Sender<Option<T>>;

/// A type alias for the receiver end of a watch channel.
pub(super) type ReceiverWatch<T> = async_watch::Receiver<Option<T>>;

/// A type alias for the sender end of a multi-producer, single-consumer channel.
pub(super) type SenderMpsc<T> = async_channel::Sender<T>;

/// A type alias for the receiver end of a multi-producer, single-consumer channel.
pub(super) type ReceiverMpsc<T> = async_channel::Receiver<T>;

/// A type alias for an atomic swap operation on a shared value.
pub(super) type AtomicSwap<T> = Arc<ArcSwap<T>>;
