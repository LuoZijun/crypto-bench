use libsodium_sys::{
    crypto_aead_aes256gcm_KEYBYTES,  // KEY-LEN
    crypto_aead_aes256gcm_NPUBBYTES, // NONCE-LEN
    crypto_aead_aes256gcm_ABYTES,    // TAG-LEN
    crypto_aead_aes256gcm_keygen,
    crypto_aead_aes256gcm_encrypt,

    crypto_aead_chacha20poly1305_IETF_KEYBYTES,  // KEY-LEN
    crypto_aead_chacha20poly1305_IETF_NPUBBYTES, // NONCE-LEN
    crypto_aead_chacha20poly1305_IETF_ABYTES,    // TAG-LEN
    crypto_aead_chacha20poly1305_ietf_keygen,
    crypto_aead_chacha20poly1305_ietf_encrypt,

    crypto_aead_aes256gcm_is_available,
    sodium_init as init,
};

use std::sync::Once;


static SODIUM_INIT: Once = Once::new();


fn sodium_init() {
    SODIUM_INIT.call_once(|| {
        unsafe { assert_eq!(init(), 0) };
    });
}


#[bench]
fn aes_256_gcm(b: &mut test::Bencher) {
    sodium_init();

    let mut key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];

    unsafe {
        assert!(crypto_aead_aes256gcm_is_available() != 0, "Not available on this CPU");
        
        assert_eq!(crypto_aead_aes256gcm_KEYBYTES, 32);  // KEY-LEN
        assert_eq!(crypto_aead_aes256gcm_NPUBBYTES, 12); // NONCE-LEN
        assert_eq!(crypto_aead_aes256gcm_ABYTES, 16);    // TAG-LEN
        
        let key_ptr = key.as_mut_ptr();
        crypto_aead_aes256gcm_keygen(key_ptr);
    }

    unsafe fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let mut clen = plaintext_in_ciphertext_out.len() as u64;
        let c = plaintext_in_ciphertext_out.as_mut_ptr();
        
        let mlen = clen - 16;
        let m = plaintext_in_ciphertext_out.as_ptr();

        let ad   = aad.as_ptr();
        let alen = aad.len() as u64;
        
        let nsec = std::ptr::null();
        let npub = nonce.as_ptr();

        let k = key.as_ptr();

        assert_eq!(crypto_aead_aes256gcm_encrypt(c, &mut clen, m, mlen, ad, alen, nsec, npub, k), 0);
    }
    
    b.bytes = 16;
    b.iter(|| {
        let mut plaintext_in_ciphertext_out = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        unsafe {
            encrypt(&key, &nonce, &aad, &mut plaintext_in_ciphertext_out);
        }
        
        plaintext_in_ciphertext_out
    })
}

#[bench]
fn chacha20_poly1305(b: &mut test::Bencher) {
    sodium_init();

    let mut key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
        0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];
    
    unsafe {
        assert_eq!(crypto_aead_chacha20poly1305_IETF_KEYBYTES, 32);  // KEY-LEN
        assert_eq!(crypto_aead_chacha20poly1305_IETF_NPUBBYTES, 12); // NONCE-LEN
        assert_eq!(crypto_aead_chacha20poly1305_IETF_ABYTES, 16);    // TAG-LEN
        
        let key_ptr = key.as_mut_ptr();
        crypto_aead_chacha20poly1305_ietf_keygen(key_ptr);
    }
    
    unsafe fn encrypt(key: &[u8], nonce: &[u8], aad: &[u8], plaintext_in_ciphertext_out: &mut [u8]) {
        let mut clen = plaintext_in_ciphertext_out.len() as u64;
        let c = plaintext_in_ciphertext_out.as_mut_ptr();
        
        let mlen = clen - 16;
        let m = plaintext_in_ciphertext_out.as_ptr();

        let ad   = aad.as_ptr();
        let alen = aad.len() as u64;
        
        let nsec = std::ptr::null();
        let npub = nonce.as_ptr();

        let k = key.as_ptr();

        assert_eq!(crypto_aead_chacha20poly1305_ietf_encrypt(c, &mut clen, m, mlen, ad, alen, nsec, npub, k), 0);
    }

    b.bytes = 64;
    b.iter(|| {
        let mut plaintext_in_ciphertext_out = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        unsafe {
            encrypt(&key, &nonce, &aad, &mut plaintext_in_ciphertext_out);
        }
        
        plaintext_in_ciphertext_out
    })
}
