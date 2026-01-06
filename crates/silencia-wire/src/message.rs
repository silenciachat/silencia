// Message wire format (protobuf generated)

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/silencia.message.rs"));
}

pub use proto::{ChatMessage, EncryptedMessage, IdentityAnnouncement, Message};
