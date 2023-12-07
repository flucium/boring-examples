// EVP

use core::mem::zeroed;

use boring_sys::{ENGINE_new, EVP_AEAD_CTX_init, EVP_AEAD_CTX};

pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = unsafe { boring_sys::EVP_aead_chacha20_poly1305() };

    unsafe {
        let mut ctx: EVP_AEAD_CTX = zeroed();

        if EVP_AEAD_CTX_init(&mut ctx, cipher, key.as_ptr(), key.len(), 16, ENGINE_new()) != 1 {
            Err(())?;
        }

        let mut len: usize = 0;

        let mut cipher = vec![0; message.len() + 16];

        if boring_sys::EVP_AEAD_CTX_seal(
            &mut ctx,
            cipher.as_mut_ptr(),
            &mut len,
            cipher.len(),
            nonce.as_ptr(),
            nonce.len(),
            message.as_ptr(),
            message.len(),
            associated_data.as_ptr(),
            associated_data.len(),
        ) != 1
        {
            Err(())?;
        }

        cipher.truncate(len);

        Ok(cipher)
    }
}

pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, ()> {
    let cipher = unsafe { boring_sys::EVP_aead_chacha20_poly1305() };

    unsafe {
        let mut ctx: EVP_AEAD_CTX = zeroed();

        if EVP_AEAD_CTX_init(&mut ctx, cipher, key.as_ptr(), key.len(), 16, ENGINE_new()) != 1 {
            Err(())?;
        }

        let mut len: usize = 0;

        let mut cipher = vec![0; message.len() + 16];

        if boring_sys::EVP_AEAD_CTX_open(
            &mut ctx,
            cipher.as_mut_ptr(),
            &mut len,
            cipher.len(),
            nonce.as_ptr(),
            nonce.len(),
            message.as_ptr(),
            message.len(),
            associated_data.as_ptr(),
            associated_data.len(),
        ) != 1
        {
            Err(())?;
        }

        cipher.truncate(len);

        Ok(cipher)
    }
}
