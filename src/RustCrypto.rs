
#[bench]
fn aes_128(b: &mut test::Bencher) {
    use aes::Aes128;
    use aes::BlockCipher;
    use aes::NewBlockCipher;
    use aes::cipher::generic_array::GenericArray;
    // RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"

    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];

    let key   = GenericArray::from(key);

    let cipher = Aes128::new(&key);

    b.bytes = 16;
    b.iter(|| {
        let mut ciphertext = test::black_box(GenericArray::from([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
        ]));
        cipher.encrypt_block(&mut ciphertext);
        ciphertext
    })
}


#[bench]
fn aes_128_gcm(b: &mut test::Bencher) {
    use aes_gcm::Aes128Gcm;
    use aes_gcm::aead::{AeadInPlace, NewAead, generic_array::GenericArray};
    // RUSTFLAGS="-Ctarget-cpu=sandybridge -Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3"

    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];

    let key   = GenericArray::from(key);
    let nonce = GenericArray::from(nonce);

    let cipher = Aes128Gcm::new(&key);

    b.bytes = 16;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
        ]);
        let tag = cipher.encrypt_in_place_detached(&nonce, &aad, &mut ciphertext).unwrap();
        tag
    })
}

#[bench]
fn aes_128_ccm(b: &mut test::Bencher) {
    use aes::Aes128;
    use ccm::{Ccm, consts::{U12, U16}};
    use ccm::aead::{AeadInPlace, NewAead, generic_array::GenericArray};

    // AEAD_AES_128_CCM
    // NONCE-LEN=12, TAG-LEN=16, Q=3
    type Aes128Ccm = Ccm<Aes128, U16, U12>;

    let key = [
        0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
        0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
    ];
    let nonce = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 
        0x05, 0x06, 0x07, 0x08,
    ];
    let aad = [0u8; 0];

    let key   = GenericArray::from(key);
    let nonce = GenericArray::from(nonce);

    let cipher = Aes128Ccm::new(&key);

    b.bytes = 16;
    b.iter(|| {
        let mut ciphertext = test::black_box([
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 
            0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0, 
        ]);
        let tag = cipher.encrypt_in_place_detached(&nonce, &aad, &mut ciphertext).unwrap();
        tag
    })
}


#[bench]
fn chacha20(b: &mut test::Bencher) {
    use chacha20::{ChaCha20, Key, Nonce};
    use chacha20::cipher::{NewStreamCipher, StreamCipher};

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

    let key   = Key::from_slice(&key);
    let nonce = Nonce::from_slice(&nonce);

    let mut cipher = ChaCha20::new(key, nonce);

    b.bytes = 64;
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
        cipher.encrypt(&mut ciphertext);
        ciphertext
    })
}


#[bench]
fn chacha20_poly1305(b: &mut test::Bencher) {
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use chacha20poly1305::aead::{AeadInPlace, NewAead};
    // RUSTFLAGS="-Ctarget-feature=+avx2"
    // RUSTFLAGS="-Ctarget-cpu=haswell -Ctarget-feature=+avx2"

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

    let key   = Key::from_slice(&key);
    let nonce = Nonce::from_slice(&nonce);

    let cipher = ChaCha20Poly1305::new(key);

    b.bytes = 64;
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
        let tag = cipher.encrypt_in_place_detached(&nonce, &aad, &mut ciphertext).unwrap();
        tag
    })
}
