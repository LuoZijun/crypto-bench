use crypto2::blockcipher::Aes128;
use crypto2::blockcipher::Aes256;
use crypto2::aeadcipher::Aes128Gcm;
use crypto2::aeadcipher::Aes256Gcm;
use crypto2::aeadcipher::Aes128Ccm;
use crypto2::aeadcipher::Aes128OcbTag128;
use crypto2::aeadcipher::Aes128GcmSiv;
use crypto2::aeadcipher::AesSivCmac256;
use crypto2::streamcipher::Chacha20;
use crypto2::aeadcipher::Chacha20Poly1305;


#[bench]
fn aes_128(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
    ];

    let cipher = Aes128::new(&key);

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

    let cipher = Aes256::new(&key);

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

    let cipher = Aes128Gcm::new(&key);

    b.bytes = Aes128Gcm::BLOCK_LEN as u64;
    b.iter(|| {
        let mut tag_out    = test::black_box([ 1u8; Aes128Gcm::TAG_LEN ]);
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        // cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
        cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
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

    let cipher = Aes256Gcm::new(&key);

    b.bytes = Aes256Gcm::BLOCK_LEN as u64;
    b.iter(|| {
        let mut tag_out    = test::black_box([ 1u8; Aes256Gcm::TAG_LEN ]);
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            // 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        // cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
        cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
        ciphertext
    })
}


#[bench]
fn aes_128_ccm(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];

    let cipher = Aes128Ccm::new(&key);

    b.bytes = Aes128Ccm::BLOCK_LEN as u64;
    b.iter(|| {
        // let mut tag_out    = test::black_box([ 1u8; Aes128Ccm::TAG_LEN ]);
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
        // cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
        ciphertext
    })
}

#[bench]
fn aes_128_ocb_tag_128(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];

    let cipher = Aes128OcbTag128::new(&key);

    b.bytes = Aes128OcbTag128::BLOCK_LEN as u64;
    b.iter(|| {
        // let mut tag_out    = test::black_box([ 1u8; Aes128OcbTag128::TAG_LEN ]);
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
        // cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
        ciphertext
    })
}

#[bench]
fn aes_128_gcm_siv(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];

    let cipher = Aes128GcmSiv::new(&key);

    b.bytes = Aes128GcmSiv::BLOCK_LEN as u64;
    b.iter(|| {
        // let mut tag_out    = test::black_box([ 1u8; Aes128GcmSiv::TAG_LEN ]);
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.encrypt_slice(&nonce, &aad, &mut ciphertext);
        // cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
        ciphertext
    })
}

#[bench]
fn aes_128_siv_cmac_256(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    
    let cipher = AesSivCmac256::new(&key);

    b.bytes = AesSivCmac256::BLOCK_LEN as u64;
    b.iter(|| {
        // let mut tag_out    = test::black_box([ 1u8; AesSivCmac256::TAG_LEN ]);
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.encrypt_slice(&[], &mut ciphertext);
        // cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
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

    let chacha20 = Chacha20::new(&key);
    
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
    
    let cipher = Chacha20Poly1305::new(&key);

    b.bytes = Chacha20Poly1305::BLOCK_LEN as u64;
    b.iter(|| {
        // let mut tag_out    = test::black_box([ 1u8; Chacha20Poly1305::TAG_LEN ]);
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
        // cipher.encrypt_slice_detached(&nonce, &aad, &mut ciphertext, &mut tag_out);
        ciphertext
    })
}