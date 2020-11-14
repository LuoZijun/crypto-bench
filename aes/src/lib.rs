extern crate aesni;
extern crate aes_soft;


#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    all(target_feature = "aes", target_feature = "sse2")
))]
pub use aesni::*;
// mod platform {
//     pub use aesni::{Aes128, Aes192, Aes256};
//     pub use aesni::cipher::{ NewBlockCipher, BlockCipher, NewStreamCipher, StreamCipher };
//     pub use aesni::cipher::generic_array::GenericArray;
// }

#[cfg(not(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        all(target_feature = "aes", target_feature = "sse2")
    )
))]
pub use aes_soft::*;

// mod platform {
//     pub use aes_soft::{Aes128, Aes192, Aes256};
//     pub use aes_soft::cipher::{ NewBlockCipher, BlockCipher, NewStreamCipher, StreamCipher };
//     pub use aes_soft::cipher::generic_array::GenericArray;
// }

// pub use self::platform::*;
