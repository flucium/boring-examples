use boring::hash::MessageDigest;

pub fn sha256_digest(input: &[u8]) -> [u8; 32] {
    unsafe {
        boring::hash::hash(MessageDigest::sha256(), input)
            .unwrap()
            .get_unchecked(..32)
            .try_into()
            .unwrap()
    }
}
