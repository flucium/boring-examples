use boring_sys;

fn sign(private_key: &[u8; 32], message: &[u8]) -> Result<[u8; 64], ()> {
    unsafe {
        let pkey = boring_sys::EVP_PKEY_new_raw_private_key(
            boring_sys::EVP_PKEY_ED25519,
            std::ptr::null_mut(),
            private_key.as_ptr() as *mut _,
            private_key.len(),
        );

        let ctx = boring_sys::EVP_MD_CTX_new();

        boring_sys::EVP_DigestSignInit(
            ctx,
            std::ptr::null_mut(),
            boring_sys::EVP_sha512(),
            std::ptr::null_mut(),
            pkey,
        );

        let mut out_signature_len: usize = 0;
        if boring_sys::EVP_DigestSign(
            ctx,
            std::ptr::null_mut(),
            &mut out_signature_len,
            std::ptr::null_mut(),
            0,
        ) != 1
        {
            Err(())?
        }

        let mut out_signature: Vec<u8> = vec![0; out_signature_len];
        if boring_sys::EVP_DigestSign(
            ctx,
            out_signature.as_mut_ptr() as *mut _,
            &mut out_signature_len,
            message.as_ptr(),
            message.len(),
        ) != 1
        {
            Err(())?
        }

        Ok(out_signature
            .iter()
            .cloned()
            .take(64)
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap())
    }
}

fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<bool, ()> {
    unsafe {
        let pkey = boring_sys::EVP_PKEY_new_raw_public_key(
            boring_sys::EVP_PKEY_ED25519,
            std::ptr::null_mut(),
            public_key.as_ptr() as *mut _,
            public_key.len(),
        );

        let ctx = boring_sys::EVP_MD_CTX_new();

        boring_sys::EVP_DigestVerifyInit(
            ctx,
            std::ptr::null_mut(),
            boring_sys::EVP_sha512(),
            std::ptr::null_mut(),
            pkey,
        );

        boring_sys::EVP_DigestVerify(
            ctx,
            signature.as_ptr() as *mut _,
            signature.len(),
            std::ptr::null_mut(),
            0,
        );

        let out_verify = boring_sys::EVP_DigestVerify(
            ctx,
            signature.as_ptr() as *mut _,
            signature.len(),
            message.as_ptr(),
            message.len(),
        );

        Ok(out_verify == 1)
    }
}


fn main() {
    let mut out_public_key: [u8; 32] = [0; 32];

    let mut out_private_key: [u8; 32] = [0; 32];

    unsafe {
        boring_sys::ED25519_keypair(out_public_key.as_mut_ptr(), out_private_key.as_mut_ptr())
    };

    let signature = sign(&out_private_key, b"hello world").unwrap();

    let verify = verify(&out_public_key, b"hello world", &signature).unwrap();

    println!("verify: {}", verify);
}
