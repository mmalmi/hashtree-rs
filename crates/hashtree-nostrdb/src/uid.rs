/// User ID (UID) wrapper type
///
/// UIDs are 32-bit integers that map to pubkeys in the nostrdb social graph
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct Uid(pub u32);

impl Uid {
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl From<u32> for Uid {
    fn from(id: u32) -> Self {
        Self::new(id)
    }
}

impl From<Uid> for u32 {
    fn from(uid: Uid) -> Self {
        uid.0
    }
}
