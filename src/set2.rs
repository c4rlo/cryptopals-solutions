use std;
use std::collections::HashSet;
use rand;
use rand::Rng;
use rand::distributions::{IndependentSample,Range};
use common::*;

struct EncryptionOracleDisclosure {
    ciphertext: Vec<u8>,
    is_ecb: bool
}

fn disclosing_encryption_oracle(plaintext: &[u8]) -> EncryptionOracleDisclosure {
    let mut rng = rand::thread_rng();
    let mut input = Vec::new();
    let between = Range::new(5, 11);
    let n1 = between.ind_sample(&mut rng);
    let n2 = between.ind_sample(&mut rng);
    input.extend(rng.gen_iter::<u8>().take(n1));
    input.extend(plaintext);
    input.extend(rng.gen_iter::<u8>().take(n2));
    let key = rng.gen::<[u8; 16]>();
    if rng.gen() {
        EncryptionOracleDisclosure {
            ciphertext: aes128_ecb_encrypt(&input, &key),
            is_ecb: true
        }
    }
    else {
        let iv = rng.gen::<[u8; 16]>();
        EncryptionOracleDisclosure {
            ciphertext: aes128_cbc_encrypt(&input, &key, &iv),
            is_ecb: false
        }
    }
}

fn is_ecb<F: FnMut(&[u8]) -> Vec<u8>>(mut oracle: F) -> bool {
    const BLOCKSIZE: usize = 16;
    let ciphertext = oracle(
        std::iter::repeat(0).take(3*BLOCKSIZE-1).collect::<Vec<u8>>().as_slice());
    let mut blocks = HashSet::new();
    for block in ciphertext.chunks(BLOCKSIZE) {
        if ! blocks.insert(block) {
            return true;
        }
    }
    false
}

fn challenge9() {
    let input = "YELLOW SUBMARINE".as_bytes();
    let padded = pkcs7_pad(input, 20);
    println!("Challenge 9: {}", escape_bytes(&padded));
}

fn challenge10(b64: &Base64Codec) {
    let ciphertext = b64.decode(file_bytes("10.txt"));
    let key = "YELLOW SUBMARINE".as_bytes();
    let iv = [0; 16];
    let plaintext = aes128_cbc_decrypt(&ciphertext, key, &iv);
    println!("Challenge 10:\n{}", String::from_utf8_lossy(&plaintext));
}

fn challenge11() {
    for _ in 1..500 {
        let mut is_ecb_really = false;
        let is_ecb_guess = is_ecb(|plaintext| {
            let disc = disclosing_encryption_oracle(plaintext);
            is_ecb_really = disc.is_ecb;
            disc.ciphertext
        });
        assert_eq!(is_ecb_really, is_ecb_guess);
    }
    println!("Challenge 11: Success");
}

pub fn run() {
    println!("=== SET 2 ===");
    let b64 = Base64Codec::new();
    challenge9();
    challenge10(&b64);
    challenge11();
}
