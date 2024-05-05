use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerResponse {
    pub interval: u32,
    pub peers: Vec<[u8; 6]>,
}

