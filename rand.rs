pub fn generate()->[u8;32]{
    let mut buf = [0u8; 32];
    
    // cryptographically pseudo-random bytes.
    if let Err(err) = boring::rand::rand_bytes(&mut buf) {
        panic!("Error: {}", err);
    }

    buf
}
