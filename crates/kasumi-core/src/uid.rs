//! Opaque unique id for new profiles/groups. The exact format isn't load-bearing
//! — import/share fixtures normalise it — but it must be collision-free across a
//! session, so use a random UUID v4.

use uuid::Uuid;

pub fn uid() -> String {
    Uuid::new_v4().to_string()
}
