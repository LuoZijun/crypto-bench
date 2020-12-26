#![allow(non_camel_case_types, improper_ctypes, dead_code)]


pub type mbedtls_operation_t = i32;
pub const MBEDTLS_AES_ENCRYPT: i32 = 1; // AES encryption
pub const MBEDTLS_AES_DECRYPT: i32 = 0; // AES decryption
pub const MBEDTLS_GCM_ENCRYPT: i32 = 1;
pub const MBEDTLS_GCM_DECRYPT: i32 = 0;
pub const MBEDTLS_ENCRYPT: i32     = 1;
pub const MBEDTLS_DECRYPT: i32     = 0;

pub type mbedtls_cipher_id_t = u32;
pub const MBEDTLS_CIPHER_ID_AES: u32      = 2;
pub const MBEDTLS_CIPHER_ID_CAMELLIA: u32 = 5;
pub const MBEDTLS_CIPHER_ID_ARC4: u32     = 7;

pub type mbedtls_cipher_mode_t = u32;
pub const MBEDTLS_MODE_ECB: u32    = 1;
pub const MBEDTLS_MODE_CBC: u32    = 2;
pub const MBEDTLS_MODE_CFB: u32    = 3;
pub const MBEDTLS_MODE_OFB: u32    = 4;
pub const MBEDTLS_MODE_CTR: u32    = 5;
pub const MBEDTLS_MODE_GCM: u32    = 6;
pub const MBEDTLS_MODE_STREAM: u32 = 7;
pub const MBEDTLS_MODE_CCM: u32    = 8;

pub type mbedtls_cipher_type_t = u32;
pub const MBEDTLS_CIPHER_AES_128_ECB: u32 = 2;


#[allow(missing_copy_implementations)]
#[derive(Debug)]
pub enum mbedtls_cipher_base_t { }


#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_cipher_info_t {
    pub type_: mbedtls_cipher_type_t,
    pub mode: mbedtls_cipher_mode_t,
    pub key_bitlen: u32,
    pub name: *const u8,
    pub iv_size: u32,
    pub flags: i32,
    pub block_size: u32,
    pub base: *const mbedtls_cipher_base_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
#[derive(Debug)]
pub struct mbedtls_cipher_context_t {
    pub cipher_info: *const mbedtls_cipher_info_t,
    pub key_bitlen: i32,
    pub operation: mbedtls_operation_t,
    pub add_padding: Option<unsafe extern "C" fn(output: *mut u8, olen: usize, data_len: usize)>,
    pub get_padding: Option<unsafe extern "C" fn(input: *mut u8, ilen: usize, data_len: *mut usize) -> i32>,
    pub unprocessed_data: [u8; 16],
    pub unprocessed_len: usize,
    pub iv: [u8; 16],
    pub iv_size: usize,
    pub cipher_ctx: *mut (),
}


#[repr(C)]
pub struct mbedtls_aes_context {
    // The number of rounds
    nr: i32,
    // AES round keys
    rk: *const u32,
    // Unaligned data buffer. This buffer can
    // hold 32 extra Bytes, which can be used for
    // one of the following purposes:
    //      1. Alignment if VIA padlock is used.
    //      2. Simplifying key expansion in the 256-bit case by generating an extra round key.
    buf: [u32; 68],
}

#[repr(C)]
pub struct mbedtls_gcm_context {
    cipher_ctx: mbedtls_cipher_context_t,
    hl: [u64; 16],
    hh: [u64; 16],
    len: u64,
    add_len: u64,
    base_ectr: [u8; 16],
    y: [u8; 16],
    buf: [u8; 16],
    mode: i32,
}

#[repr(C)]
pub struct mbedtls_chachapoly_context {
    chacha20_ctx: mbedtls_chacha20_context,
    poly1305_ctx: mbedtls_poly1305_context,
    aad_len: u64,
    ciphertext_len: u64,
    state: i32,
    mode: i32,
}

#[repr(C)]
pub struct mbedtls_chacha20_context {
    state: [u32; 16],
    keystream8: [u8; 64],
    keystream_bytes_used: usize,
}

#[repr(C)]
pub struct mbedtls_poly1305_context {
    r: [u32; 4],
    s: [u32; 4],
    acc: [u32; 5],
    queue: [u8; 16],
    queue_len: usize,
}





// mbedcrypto
// #[link(name = "mbedtls")]
#[link(name = "mbedcrypto")]
extern "C" {
    // https://github.com/ARMmbed/mbedtls/blob/development/include/mbedtls/aes.h
    pub fn mbedtls_aes_init(ctx: *mut mbedtls_aes_context);
    pub fn mbedtls_aes_free(ctx: *mut mbedtls_aes_context);
    pub fn mbedtls_aes_setkey_enc(ctx: *mut mbedtls_aes_context, key: *const u8, keybits: u32) -> i32;
    pub fn mbedtls_aes_setkey_dec(ctx: *mut mbedtls_aes_context, key: *const u8, keybits: u32) -> i32;
    pub fn mbedtls_aes_crypt_ecb(ctx: *mut mbedtls_aes_context, mode: i32, input: *const u8, output: *mut u8) -> i32;

    // https://github.com/ARMmbed/mbedtls/blob/development/include/mbedtls/gcm.h
    pub fn mbedtls_gcm_init(ctx: *mut mbedtls_gcm_context);
    pub fn mbedtls_gcm_free(ctx: *mut mbedtls_gcm_context);
    pub fn mbedtls_gcm_setkey(ctx: *mut mbedtls_gcm_context, cipher: mbedtls_cipher_id_t, key: *const u8, keybits: u32) -> i32;
    pub fn mbedtls_gcm_crypt_and_tag(
        ctx: *mut mbedtls_gcm_context,
        mode: i32,
        length: usize,
        iv: *const u8, iv_len: usize,
        add: *const u8, add_len: usize,
        input: *const u8, output: *mut u8,
        tag_len: usize, tag: *mut u8,
    ) -> i32;
    pub fn mbedtls_gcm_auth_decrypt(
        ctx: *mut mbedtls_gcm_context,
        length: usize,
        iv: *const u8, iv_len: usize,
        add: *const u8, add_len: usize,
        tag: *mut u8, tag_len: usize, 
        input: *const u8, output: *mut u8,
    ) -> i32;
    pub fn mbedtls_gcm_starts(
        ctx: *mut mbedtls_gcm_context,
        mode: i32,
        iv: *const u8,
        iv_len: usize,
        add: *const u8,
        add_len: usize,
    ) -> i32;
    pub fn mbedtls_gcm_update(
        ctx: *mut mbedtls_gcm_context,
        length: usize,
        input: *const u8,
        output: *mut u8,
    ) -> i32;
    pub fn mbedtls_gcm_finish(
        ctx: *mut mbedtls_gcm_context,
        tag: *mut u8,
        tag_len: usize,
    ) -> i32;

    // https://github.com/ARMmbed/mbedtls/blob/development/include/mbedtls/chachapoly.h
    pub fn mbedtls_chachapoly_init(ctx: *mut mbedtls_chachapoly_context);
    pub fn mbedtls_chachapoly_free(ctx: *mut mbedtls_chachapoly_context);
    pub fn mbedtls_chachapoly_setkey(ctx: *mut mbedtls_chachapoly_context, key: *const u8) -> i32;
    pub fn mbedtls_chachapoly_encrypt_and_tag(
        ctx: *mut mbedtls_chachapoly_context,
        plen: usize,
        nonce: *const u8,
        aad: *const u8,
        add_len: usize,
        input: *const u8,
        output: *mut u8,
        tag: *mut u8,
    ) -> i32;
    pub fn mbedtls_chachapoly_auth_decrypt(
        ctx: *mut mbedtls_chachapoly_context,
        plen: usize,
        nonce: *const u8,
        aad: *const u8,
        add_len: usize,
        tag: *mut u8,
        input: *const u8,
        output: *mut u8,
    ) -> i32;
    pub fn mbedtls_chachapoly_starts(
        ctx: *mut mbedtls_chachapoly_context,
        nonce: *const u8,
        mode: i32,
    ) -> i32;
    pub fn mbedtls_chachapoly_update_aad(
        ctx: *mut mbedtls_chachapoly_context,
        aad: *const u8,
        aad_len: usize,
    ) -> i32;
    
    pub fn mbedtls_chachapoly_update(
        ctx: *mut mbedtls_chachapoly_context,
        plen: usize,
        input: *const u8,
        output: *mut u8,
    ) -> i32;
    pub fn mbedtls_chachapoly_finish(
        ctx: *mut mbedtls_chachapoly_context,
        tag: *mut u8,
    ) -> i32;

    // https://github.com/ARMmbed/mbedtls/blob/development/include/mbedtls/chacha20.h
    pub fn mbedtls_chacha20_init(ctx: *mut mbedtls_chacha20_context);
    pub fn mbedtls_chacha20_free(ctx: *mut mbedtls_chacha20_context);
    pub fn mbedtls_chacha20_setkey(ctx: *mut mbedtls_chacha20_context, key: *const u8) -> i32;
    pub fn mbedtls_chacha20_starts(
        ctx: *mut mbedtls_chacha20_context,
        nonce: *const u8,
        counter: u32,
    ) -> i32;
    pub fn mbedtls_chacha20_crypt(
        key: *const u8,
        nonce: *const u8,
        counter: u32,
        plen: usize,
        input: *const u8,
        output: *mut u8,
    ) -> i32;
    pub fn mbedtls_chacha20_update(
        ctx: *mut mbedtls_chacha20_context,
        plen: usize,
        input: *const u8,
        output: *mut u8,
    ) -> i32;
    
    // https://github.com/ARMmbed/mbedtls/blob/development/include/mbedtls/ccm.h
    // TODO: CCM
}


pub struct Aes128 {
    ctx: mbedtls_aes_context,
}

impl Aes128 {
    pub const KEY_LEN: usize   = 16;
    pub const BLOCK_LEN: usize = 16;


    pub fn new(key: &[u8]) -> Self {
        unsafe {
            let mut ctx = std::mem::zeroed();
            mbedtls_aes_init(&mut ctx);

            let key_ptr = key.as_ptr();
            let keybits = Self::KEY_LEN as u32 * 8;

            let ret = mbedtls_aes_setkey_enc(&mut ctx, key_ptr, keybits);
            assert_eq!(ret, 0);

            Self { ctx }
        }
    }

    pub fn encrypt(&mut self, block: &mut [u8]) {
        unsafe {
            let mode = MBEDTLS_AES_ENCRYPT;
            let input = block.as_ptr();
            let output = block.as_mut_ptr();

            let ret = mbedtls_aes_crypt_ecb(&mut self.ctx, mode, input, output);
            assert_eq!(ret, 0);
        }
    }
}

pub struct Aes256 {
    ctx: mbedtls_aes_context,
}

impl Aes256 {
    pub const KEY_LEN: usize   = 32;
    pub const BLOCK_LEN: usize = 16;


    pub fn new(key: &[u8]) -> Self {
        unsafe {
            let mut ctx = std::mem::zeroed();
            mbedtls_aes_init(&mut ctx);

            let key_ptr = key.as_ptr();
            let keybits = Self::KEY_LEN as u32 * 8;

            let ret = mbedtls_aes_setkey_enc(&mut ctx, key_ptr, keybits);
            assert_eq!(ret, 0);

            Self { ctx }
        }
    }

    pub fn encrypt(&mut self, block: &mut [u8]) {
        unsafe {
            let mode = MBEDTLS_AES_ENCRYPT;
            let input = block.as_ptr();
            let output = block.as_mut_ptr();

            let ret = mbedtls_aes_crypt_ecb(&mut self.ctx, mode, input, output);
            assert_eq!(ret, 0);
        }
    }
}


pub struct Aes128Gcm {
    ctx: mbedtls_gcm_context,
}

impl Aes128Gcm {
    pub const KEY_LEN: usize   = 16;
    pub const BLOCK_LEN: usize = 16;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize   = 16;


    pub fn new(key: &[u8]) -> Self {
        unsafe {
            let mut ctx = std::mem::zeroed();
            mbedtls_gcm_init(&mut ctx);

            let key_ptr = key.as_ptr();
            let keybits = Self::KEY_LEN as u32 * 8;

            let cipher_id = MBEDTLS_CIPHER_ID_AES;

            let ret = mbedtls_gcm_setkey(&mut ctx, cipher_id, key_ptr, keybits);
            assert_eq!(ret, 0);

            Self { ctx }
        }
    }

    pub fn encrypt_slice(&mut self, nonce: &[u8], aad: &[u8], in_out: &mut [u8]) {
        unsafe {
            let mode = MBEDTLS_GCM_ENCRYPT;
            let input = in_out.as_ptr();
            let plen = in_out.len() - Self::TAG_LEN;

            let tag_len = Self::TAG_LEN;
            let (output, tag) = in_out.split_at_mut(plen);

            let ret = mbedtls_gcm_crypt_and_tag(&mut self.ctx, mode, plen,
                nonce.as_ptr(), nonce.len(), 
                aad.as_ptr(), aad.len(), 
                input, output.as_mut_ptr(),
                tag_len, tag.as_mut_ptr()
            );
            assert_eq!(ret, 0);
        }
    }
}

pub struct Aes256Gcm {
    ctx: mbedtls_gcm_context,
}

impl Aes256Gcm {
    pub const KEY_LEN: usize   = 32;
    pub const BLOCK_LEN: usize = 16;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize   = 16;


    pub fn new(key: &[u8]) -> Self {
        unsafe {
            let mut ctx = std::mem::zeroed();
            mbedtls_gcm_init(&mut ctx);

            let key_ptr = key.as_ptr();
            let keybits = Self::KEY_LEN as u32 * 8;

            let cipher_id = MBEDTLS_CIPHER_ID_AES;

            let ret = mbedtls_gcm_setkey(&mut ctx, cipher_id, key_ptr, keybits);
            assert_eq!(ret, 0);

            Self { ctx }
        }
    }

    pub fn encrypt_slice(&mut self, nonce: &[u8], aad: &[u8], in_out: &mut [u8]) {
        unsafe {
            let mode = MBEDTLS_GCM_ENCRYPT;
            let plen = in_out.len() - Self::TAG_LEN;

            let tag_len = Self::TAG_LEN;
            let (output, tag) = in_out.split_at_mut(plen);

            let ret = mbedtls_gcm_crypt_and_tag(&mut self.ctx, mode, plen,
                nonce.as_ptr(), nonce.len(), 
                aad.as_ptr(), aad.len(), 
                output.as_ptr(), output.as_mut_ptr(),
                tag_len, tag.as_mut_ptr()
            );
            assert_eq!(ret, 0);
        }
    }
}

pub struct Chacha20 {
    ctx: mbedtls_chacha20_context,
}

impl Chacha20 {
    pub const KEY_LEN: usize   = 32;
    pub const BLOCK_LEN: usize = 64;
    pub const NONCE_LEN: usize = 12;


    pub fn new(key: &[u8]) -> Self {
        unsafe {
            let mut ctx = std::mem::zeroed();
            mbedtls_chacha20_init(&mut ctx);

            let key_ptr = key.as_ptr();

            let ret = mbedtls_chacha20_setkey(&mut ctx, key_ptr);
            assert_eq!(ret, 0);

            Self { ctx }
        }
    }

    pub fn encrypt_slice(&mut self, initial_counter: u32, nonce: &[u8], in_out: &mut [u8]) {
        unsafe {
            let plen = in_out.len();

            let input = in_out.as_ptr();
            let output = in_out.as_mut_ptr();
            
            let ret = mbedtls_chacha20_starts(&mut self.ctx, nonce.as_ptr(), initial_counter);
            assert_eq!(ret, 0);

            let ret = mbedtls_chacha20_update(&mut self.ctx, plen, input, output);
            assert_eq!(ret, 0);
        }
    }
}

pub struct Chacha20Poly1305 {
    ctx: mbedtls_chachapoly_context,
}

impl Chacha20Poly1305 {
    pub const KEY_LEN: usize   = 32;
    pub const BLOCK_LEN: usize = 64;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize   = 16;


    pub fn new(key: &[u8]) -> Self {
        unsafe {
            let mut ctx = std::mem::zeroed();
            mbedtls_chachapoly_init(&mut ctx);

            let key_ptr = key.as_ptr();

            let ret = mbedtls_chachapoly_setkey(&mut ctx, key_ptr);
            assert_eq!(ret, 0);

            Self { ctx }
        }
    }

    pub fn encrypt_slice(&mut self, nonce: &[u8], aad: &[u8], in_out: &mut [u8]) {
        unsafe {
            let plen = in_out.len() - Self::TAG_LEN;

            let (output, tag) = in_out.split_at_mut(plen);
    
            let ret = mbedtls_chachapoly_encrypt_and_tag(&mut self.ctx,
                plen,
                nonce.as_ptr(), 
                aad.as_ptr(), aad.len(), 
                output.as_ptr(),
                output.as_mut_ptr(),
                tag.as_mut_ptr(),
            );
            assert_eq!(ret, 0);
        }
    }
}

#[bench]
fn aes_128(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
    ];

    let mut cipher = Aes128::new(&key);

    b.bytes = Aes128::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 
        ]);
        cipher.encrypt(&mut ciphertext);
        ciphertext
    })
}

#[bench]
fn aes_256(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
    ];

    let mut cipher = Aes256::new(&key);

    b.bytes = Aes256::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        cipher.encrypt(&mut ciphertext);
        ciphertext
    })
}

#[bench]
fn aes_128_gcm(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];

    let mut cipher = Aes128Gcm::new(&key);

    b.bytes = Aes128Gcm::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
        ciphertext
    })
}


#[bench]
fn aes_256_gcm(b: &mut test::Bencher) {
    let key = [
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

    let mut cipher = Aes256Gcm::new(&key);

    b.bytes = Aes256Gcm::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
        ciphertext
    })
}

#[bench]
fn chacha20(b: &mut test::Bencher) {
    let key = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 
        0x00, 0x00, 0x00, 0x00
    ];

    let mut chacha20 = Chacha20::new(&key);
    
    b.bytes = Chacha20::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
        ]);
        chacha20.encrypt_slice(1, &nonce, &mut ciphertext);
        ciphertext
    })
}

#[bench]
fn chacha20_poly1305(b: &mut test::Bencher) {
    let key = [
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
    
    let mut cipher = Chacha20Poly1305::new(&key);

    b.bytes = Chacha20Poly1305::BLOCK_LEN as u64;
    b.iter(|| {
        let mut ciphertext = test::black_box([
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
        cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
        ciphertext
    })
}