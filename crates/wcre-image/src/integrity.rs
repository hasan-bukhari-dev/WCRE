use sha2::{Digest, Sha256};

use crate::format::WCR_V2_DIGEST_SIZE;

pub(crate) struct Sha256State {
    hasher: Sha256,
}

impl Sha256State {
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
    }

    pub(crate) fn finalize(self) -> [u8; WCR_V2_DIGEST_SIZE] {
        self.hasher.finalize().into()
    }
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; WCR_V2_DIGEST_SIZE] {
    let mut state = Sha256State::new();
    state.update(bytes);
    state.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_empty_vector() {
        let digest = sha256(b"");

        assert_eq!(
            digest,
            [
                0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F,
                0xB9, 0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B,
                0x78, 0x52, 0xB8, 0x55,
            ]
        );
    }

    #[test]
    fn streaming_sha256_matches_one_shot_sha256() {
        let expected = sha256(b"WCRE checkpoint integrity");

        let mut state = Sha256State::new();
        state.update(b"WCRE checkpoint ");
        state.update(b"integrity");

        assert_eq!(state.finalize(), expected);
    }
}
