#![feature(test)]
#![allow(non_snake_case)]

extern crate ring;
extern crate openssl;
extern crate libsodium_sys;
extern crate crypto;
// RustCrypto
extern crate aes;
extern crate aes_gcm;
extern crate ccm;
extern crate aes_gcm_siv;
extern crate aes_siv;
extern crate chacha20;
extern crate chacha20poly1305;


#[cfg(test)]
extern crate test;

mod Ring;
mod OpenSSL;
mod RustCrypto;
mod Crypto;
mod Sodium;