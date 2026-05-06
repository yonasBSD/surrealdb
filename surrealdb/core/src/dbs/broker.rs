use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use crate::catalog::SubscriptionDefinition;
use crate::types::PublicNotification;

/// Pluggable broker for forwarding [`PublicNotification`] live query events across nodes.
/// Default implementations may be no-ops; concrete types should be cheap behind [`std::sync::Arc`].
pub trait MessageBroker: Send + Sync + Debug {
	fn can_be_sent(
		&self,
		node_id: uuid::Uuid,
		subscription: &SubscriptionDefinition,
	) -> Result<bool>;

	/// Deliver a live query event for the given subscription to its owning node.
	fn send(
		&self,
		notification: PublicNotification,
	) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;
}
