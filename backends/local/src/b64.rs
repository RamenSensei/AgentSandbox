//! Base64 helpers. Re-exported from [`ak_core::b64`] — the encoding is part
//! of the protocol (file contents travel base64 in actions and state sync),
//! so there is exactly one implementation, in core.

pub use ak_core::b64::{decode, encode};
