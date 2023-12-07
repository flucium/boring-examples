use boring_sys::{
    EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_init, EVP_DecryptFinal_ex, EVP_DecryptInit_ex,
    EVP_DecryptUpdate, EVP_EncryptFinal_ex, EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_CIPHER_CTX,
    EVP_CTRL_GCM_SET_TAG,
};
use core::{mem::zeroed, ptr::null_mut};

pub fn encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    message: &[u8],
) -> core::result::Result<Vec<u8>, ()> {
    let cipher = boring::symm::Cipher::aes_256_gcm();

    unsafe {
        let mut ctx: EVP_CIPHER_CTX = zeroed();

        EVP_CIPHER_CTX_init(&mut ctx);

        if EVP_EncryptInit_ex(
            &mut ctx,
            cipher.as_ptr(),
            null_mut(),
            key.as_ptr(),
            nonce.as_ptr(),
        ) != 1
        {
            Err(())?;
        }

        if EVP_EncryptUpdate(
            &mut ctx,
            null_mut(),
            &mut 0,
            associated_data.as_ptr(),
            associated_data.len() as i32,
        ) != 1
        {
            Err(())?;
        }

        let mut len: i32 = 0;

        let mut cipher = vec![0; message.len() + 16];

        if EVP_EncryptUpdate(
            &mut ctx,
            cipher.as_mut_ptr(),
            &mut len,
            message.as_ptr(),
            message.len() as i32,
        ) != 1
        {
            Err(())?;
        }

        let c_len = len as usize;

        if EVP_EncryptFinal_ex(&mut ctx, cipher.as_mut_ptr().add(c_len), &mut len) != 1 {
            Err(())?;
        }

        cipher.truncate(c_len + len as usize);

        let mut tag = vec![0; 16];

        if boring_sys::EVP_CIPHER_CTX_ctrl(
            &mut ctx,
            boring_sys::EVP_CTRL_GCM_GET_TAG,
            tag.len() as i32,
            tag.as_mut_ptr() as *mut std::ffi::c_void,
        ) != 1
        {
            Err(())?;
        }

        cipher.extend_from_slice(&tag);

        Ok(cipher)
    }
}

pub fn decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    associated_data: &[u8],
    message: &[u8],
) -> core::result::Result<Vec<u8>, ()> {
    let cipher = boring::symm::Cipher::aes_256_gcm();

    unsafe {
        let mut ctx: EVP_CIPHER_CTX = zeroed();

        EVP_CIPHER_CTX_init(&mut ctx);

        if EVP_DecryptInit_ex(
            &mut ctx,
            cipher.as_ptr(),
            null_mut(),
            key.as_ptr(),
            nonce.as_ptr(),
        ) != 1
        {
            Err(())?;
        }

        if EVP_DecryptUpdate(
            &mut ctx,
            null_mut(),
            &mut 0,
            associated_data.as_ptr(),
            associated_data.len() as i32,
        ) != 1
        {
            Err(())?;
        }

        let mut len: i32 = 0;

        let mut plain = vec![0; message.len() - 16];

        if EVP_DecryptUpdate(
            &mut ctx,
            plain.as_mut_ptr(),
            &mut len,
            message.as_ptr(),
            message.len() as i32 - 16,
        ) != 1
        {
            Err(())?;
        }

        let p_len = len as usize;

        if EVP_CIPHER_CTX_ctrl(
            &mut ctx,
            EVP_CTRL_GCM_SET_TAG,
            16,
            message.as_ptr().add(p_len) as *mut std::ffi::c_void,
        ) != 1
        {
            Err(())?;
        }

        if EVP_DecryptFinal_ex(&mut ctx, plain.as_mut_ptr().add(p_len), &mut len) != 1 {
            Err(())?;
        }

        plain.truncate(p_len + len as usize);

        Ok(plain)
    }
}
