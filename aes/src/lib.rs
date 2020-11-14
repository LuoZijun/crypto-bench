#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
extern crate aesni;
extern crate aes_soft;


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    all(target_feature = "aes", target_feature = "sse2")
))]
pub use aesni::*;

#[cfg(not(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        all(target_feature = "aes", target_feature = "sse2")
    )
))]
pub use aes_soft::*;
