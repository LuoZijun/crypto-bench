Crypto Bench
===================

.. contents::


Install libsodium and OpenSSL
---------------------------------------
.. code:: bash
    
    # macOS
    brew install libsodium openssl

    # Debian
    apt install libsodium-dev libssl-dev


Run
--------------

`rustflags` config: `.cargo/config.toml`

.. code:: bash
    
    git clone https://github.com/LuoZijun/crypto-bench
    cd crypto-bench

    # macOS
    env OPENSSL_DIR=/usr/local/opt/openssl \
        OPENSSL_ROOT_DIR=/usr/local/opt/openssl \
        cargo bench

    # Other System
    cargo bench
