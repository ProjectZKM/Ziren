use serde::{Deserialize, Serialize};

/// Global Lookup Event.
///
/// This event is emitted for all lookups that are sent or received across different shards.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[repr(C)]
pub struct GlobalLookupEvent {
    /// The message.
    pub message: [u32; 7],
    /// Whether the lookup is received or sent.
    pub is_receive: bool,
    /// The kind of the lookup event.
    pub kind: u8,
}
