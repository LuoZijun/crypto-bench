use openssl::symm::Mode;
use openssl::symm::Cipher;
use openssl::symm::Crypter;
use openssl::symm::encrypt;
use openssl::symm::encrypt_aead;


#[bench]
fn aes_128(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];

    // NOTE: OpenSSL 库没有直接 暴露 AES-128 给用户使用，
    //       考虑到，ECB 模式几乎没有其它操作成本，所以我们使用它来代替 AES-128。
    let mut cipher = Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, &key, None).unwrap();

    b.bytes = 16;
    b.iter(|| {
        let plaintext = test::black_box([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
            0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        ]);
        let mut ciphertext = test::black_box([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        let _amt = cipher.update(&plaintext, &mut ciphertext).unwrap();
        ciphertext
    })
}

#[bench]
fn aes_128_gcm_stream(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];

    let mut cipher = Crypter::new(Cipher::aes_128_gcm(), Mode::Encrypt, &key, Some(&nonce)).unwrap();

    b.bytes = 16;
    b.iter(|| {
        let plaintext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
        ]);
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.update(&plaintext, &mut ciphertext).unwrap();
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

    let t = Cipher::aes_128_gcm();

    b.bytes = 16;
    b.iter(|| {
        let mut tag_out    = test::black_box([ 1u8; 16 ]);
        let plaintext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
        ]);
        let _ciphertext = encrypt_aead(t, &key, Some(&nonce), &aad, &plaintext, &mut tag_out).unwrap();

        tag_out
    })
}
// #[bench]
// fn aes_128_ccm(b: &mut test::Bencher) {
//     let key = [
//         0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
//         0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
//     ];
//     let nonce = [
//         0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
//         0x05, 0x06, 0x07, 0x08,
//     ];
//     let aad = [0u8; 0];

//     let t = Cipher::aes_128_ccm();

//     b.bytes = 16;
//     b.iter(|| {
//         let mut tag_out    = test::black_box([ 1u8; 16 ]);
//         let plaintext = test::black_box([
//             0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
//             0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
//         ]);
//         let _ciphertext = encrypt_aead(t, &key, Some(&nonce), &aad, &plaintext, &mut tag_out).unwrap();

//         tag_out
//     })
// }
#[bench]
fn aes_128_ocb_stream(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];

    let mut cipher = Crypter::new(Cipher::aes_128_ocb(), Mode::Encrypt, &key, Some(&nonce)).unwrap();

    b.bytes = 16;
    b.iter(|| {
        let plaintext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
        ]);
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.update(&plaintext, &mut ciphertext).unwrap();
        ciphertext
    })
}
#[bench]
fn aes_128_ocb(b: &mut test::Bencher) {
    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];

    let t = Cipher::aes_128_ocb();

    b.bytes = 16;
    b.iter(|| {
        let mut tag_out    = test::black_box([ 1u8; 16 ]);
        let plaintext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
        ]);
        let _ciphertext = encrypt_aead(t, &key, Some(&nonce), &aad, &plaintext, &mut tag_out).unwrap();

        tag_out
    })
}


#[bench]
fn chacha20(b: &mut test::Bencher) {
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

    let t = Cipher::chacha20();

    b.bytes = 64;
    b.iter(|| {
        let plaintext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
        ]);
        let ciphertext = encrypt(t, &key, Some(&nonce), &plaintext).unwrap();

        ciphertext
    })
}

#[bench]
fn chacha20_poly1305_stream(b: &mut test::Bencher) {
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

    let mut cipher = Crypter::new(Cipher::chacha20_poly1305(), Mode::Encrypt, &key, Some(&nonce)).unwrap();

    b.bytes = 64;
    b.iter(|| {
        let plaintext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
        ]);
        let mut ciphertext = test::black_box([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            // TAG
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        ]);
        cipher.update(&plaintext, &mut ciphertext).unwrap();
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

    let t = Cipher::chacha20_poly1305();

    b.bytes = 64;
    b.iter(|| {
        let mut tag_out    = test::black_box([ 1u8; 16 ]);
        let plaintext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
            0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 
            0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0,
        ]);
        let _ciphertext = encrypt_aead(t, &key, Some(&nonce), &aad, &plaintext, &mut tag_out).unwrap();

        tag_out
    })
}