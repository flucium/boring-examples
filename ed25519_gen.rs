// EVP
// Key generation
use core::ptr;

fn gen_private_key() -> Result<[u8; 32], ()> {
    let ed25519 = boring_sys::EVP_PKEY_ED25519;

    let mut key = unsafe { boring_sys::EVP_PKEY_new() };

    let mut private_key = [0u8; 32];

    unsafe {
        let ctx = boring_sys::EVP_PKEY_CTX_new_id(ed25519, ptr::null_mut());

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
    let ed25519 = boring_sys::EVP_PKEY_ED25519;

    let key = unsafe {
        boring_sys::EVP_PKEY_new_raw_private_key(
            ed25519,
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
