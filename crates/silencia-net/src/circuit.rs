/// Onion circuit management (stub for W3-W6)
pub struct Circuit {
    pub hops: Vec<String>,
}

impl Default for Circuit {
    fn default() -> Self {
        Self::new()
    }
}

impl Circuit {
    pub fn new() -> Self {
        Self { hops: vec![] }
    }
}
