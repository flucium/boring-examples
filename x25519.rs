// EVP

fn diffie_hellman(private_key: &[u8; 32], public_key: &[u8; 32]) -> Result<[u8; 32], ()> {
    let x25519 = boring_sys::EVP_PKEY_X25519;

    let key = unsafe {
        boring_sys::EVP_PKEY_new_raw_private_key(
            x25519,
            ptr::null_mut(),
            &private_key[0],
            private_key.len(),
        )
    };

    let peer_key = unsafe {
        boring_sys::EVP_PKEY_new_raw_public_key(
            x25519,
            ptr::null_mut(),
            &public_key[0],
            public_key.len(),
        )
    };

    let ctx = unsafe { boring_sys::EVP_PKEY_CTX_new(key, ptr::null_mut()) };

    if unsafe { boring_sys::EVP_PKEY_derive_init(ctx) } != 1 {
        Err(())?
    }

    if unsafe { boring_sys::EVP_PKEY_derive_set_peer(ctx, peer_key) } != 1 {
        Err(())?
    }

    let mut len = 0;

    if unsafe { boring_sys::EVP_PKEY_derive(ctx, ptr::null_mut(), &mut len) } != 1 {
        Err(())?
    }

    let mut shared_secret = vec![0u8; len as usize];

    if unsafe { boring_sys::EVP_PKEY_derive(ctx, &mut shared_secret[0], &mut len) } != 1 {
        Err(())?
    }

    unsafe {
        boring_sys::EVP_PKEY_CTX_free(ctx);
    }

    Ok(shared_secret.get(..32).unwrap().try_into().unwrap())
}

fn gen_private_key() -> Result<[u8; 32], ()> {
    let x25519 = boring_sys::EVP_PKEY_X25519;

    let mut key = unsafe { boring_sys::EVP_PKEY_new() };

    let mut private_key = [0u8; 32];

    unsafe {
        let ctx = boring_sys::EVP_PKEY_CTX_new_id(x25519, ptr::null_mut());

        if boring_sys::EVP_PKEY_keygen_init(ctx) != 1 {
            Err(())?
        }

        if boring_sys::EVP_PKEY_keygen(ctx, &mut key) != 1 {
            Err(())?
        }

        boring_sys::EVP_PKEY_CTX_free(ctx);

        let mut len = 0;

        if boring_sys::EVP_PKEY_get_raw_private_key(key, ptr::null_mut(), &mut len) != 1 {
            Err(())?
        }

        if boring_sys::EVP_PKEY_get_raw_private_key(key, &mut private_key[0], &mut len) != 1 {
            Err(())?
        }
    }

    Ok(private_key)
}

fn gen_public_key_from_private_key(private_key: &[u8; 32]) -> Result<[u8; 32], ()> {
    let x25519 = boring_sys::EVP_PKEY_X25519;

    let key = unsafe {
        boring_sys::EVP_PKEY_new_raw_private_key(
            x25519,
            ptr::null_mut(),
            &private_key[0],
            private_key.len(),
        )
    };

    unsafe {
        let mut len = 0;

        if boring_sys::EVP_PKEY_get_raw_public_key(key, ptr::null_mut(), &mut len) != 1 {
            Err(())?
        }

        let mut public_key = [0u8; 32];

        if boring_sys::EVP_PKEY_get_raw_public_key(key, &mut public_key[0], &mut len) != 1 {
            Err(())?
        }

        Ok(public_key)
    }
}
