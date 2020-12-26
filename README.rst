Crypto Bench
===================

.. contents::


Install libsodium and OpenSSL
---------------------------------------
.. code:: bash
    
    # macOS
    brew install libsodium openssl mbedtls
    
    # Debian
    apt install libsodium-dev libssl-dev libmbedtls-dev
    

Bench
--------------

`rustflags` config: `.cargo/config.toml`

.. code:: bash
    
    git clone https://github.com/LuoZijun/crypto-bench
    cd crypto-bench
    
    # macOS
    env OPENSSL_LIB_DIR /usr/local/opt/openssl/lib \
        SODIUM_LIB_DIR /usr/local/opt/libsodium/lib \
        SODIUM_SHARED 1 \
        cargo bench

    # Other System
    cargo bench



X86-64:

|        Cipher        |   OpenSSL  |    Ring    |   Sodium   | RustCrypto(org) |  Crypto2   |
| -------------------- | ---------- | ---------- | ---------- | --------------- | ---------- |
| AES-128              |  470 MB/s  |  N/A       |  N/A       |  615 MB/s       | 2666 MB/s  | 
| AES-128-CCM          |  N/A       |  N/A       |  N/A       |   81 MB/s       |  231 MB/s  | 
| AES-128-GCM          |   19 MB/s  |  158 MB/s  |  N/A       |  122 MB/s       |  250 MB/s  | 
| AES-128-GCM-SIV      |  N/A       |  N/A       |  N/A       |   55 MB/s       |  110 MB/s  | 
| AES-128-OCB-TAG128   |   15 MB/s  |  N/A       |  N/A       |  N/A            |  216 MB/s  | 
| AES-128-SIV-CMAC-256 |  N/A       |  N/A       |  N/A       |   35 MB/s       |  296 MB/s  | 
| AES-256              |  N/A       |  N/A       |  N/A       |  444 MB/s       | 1777 MB/s  | 
| AES-256-GCM          |  N/A       |  131 MB/s  |  61 MB/s   |  107 MB/s       |  170 MB/s  | 
| ChaCha20             |  N/A       |  N/A       |  N/A       |  695 MB/s       |  463 MB/s  | 
| ChaCha20-Poly1305    |   73 MB/s  |  210 MB/s  |  145 MB/s  |  126 MB/s       |  143 MB/s  | 

AArch64:

|        Cipher        |   OpenSSL  |    Ring    |   Sodium   | RustCrypto(org) |  Crypto2   |
| -------------------- | ---------- | ---------- | ---------- | --------------- | ---------- |
| AES-128              |  484 MB/s  |  N/A       |  N/A       |   36 MB/s       | 1600 MB/s  | 
| AES-128-CCM          |  N/A       |  N/A       |  N/A       |    6 MB/s       |  285 MB/s  | 
| AES-128-GCM          |   22 MB/s  |  210 MB/s  |  N/A       |   14 MB/s       |  213 MB/s  | 
| AES-128-GCM-SIV      |  N/A       |  N/A       |  N/A       |    4 MB/s       |   29 MB/s  | 
| AES-128-OCB-TAG128   |   18 MB/s  |  N/A       |  N/A       |  N/A            |  219 MB/s  | 
| AES-128-SIV-CMAC-256 |  N/A       |  N/A       |  N/A       |    3 MB/s       |  262 MB/s  | 
| AES-256              |  N/A       |  N/A       |  N/A       |   27 MB/s       | 1066 MB/s  | 
| AES-256-GCM          |  N/A       |  183 MB/s  |  N/A       |   11 MB/s       |  177 MB/s  | 
| ChaCha20             |  N/A       |  N/A       |  N/A       |  309 MB/s       |  390 MB/s  | 
| ChaCha20-Poly1305    |   73 MB/s  |  163 MB/s  |  128 MB/s  |  114 MB/s       |  132 MB/s  | 
