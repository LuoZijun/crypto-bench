Crypto Bench
===================

.. contents::


安装 libsodium 以及 OpenSSL
--------------------------------
macOS:

```bash
# macOS
brew install libsodium openssl

# Debian
apt install libsodium-dev libssl-dev
```

如果你使用的是 macOS 系统，为了确保 `openssl` crate 使用的是你从 Homebrew 安装的 OpenSSL，
你还需要设置两个环境变量：

```bash
OPENSSL_DIR=/usr/local/opt/openssl
OPENSSL_ROOT_DIR=/usr/local/opt/openssl
```


X86 以及 X86_64 平台
-----------------------------

```bash
env RUSTFLAGS="-C target-cpu=native -C target-feature=+aes,+pclmul,+sse,+sse2,+sse3,+ssse3,+sse4.1,+sse4.2,+avx,+avx2" cargo bench
```


AArch64 平台
--------------------

```bash
env RUSTFLAGS="-C target-cpu=native -C target-feature=+crypto,+neon,+aes,+pmull,+sha1,+sha2" cargo bench
```

