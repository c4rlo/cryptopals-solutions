use std::iter;
use std::collections::{HashMap,HashSet};
use rand;
use rand::Rng;
use rand::distributions::{IndependentSample,Range};
use common::*;

struct EncryptionOracleDisclosure {
    ciphertext: Vec<u8>,
    is_ecb: bool
}

fn disclosing_encryption_oracle(plaintext: &[u8])
        -> EncryptionOracleDisclosure {
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

fn oracle_with_key(prefix: &[u8], key: &[u8], b64: &Base64Codec) -> Vec<u8> {
    let secret_b64 =
            b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
              aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
              dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
              YnkK";
    //panic!("secret len = {}", b64.decode(secret_b64.iter().cloned()).len());
    let mut plaintext = prefix.to_vec();
    plaintext.append(&mut b64.decode(secret_b64.iter().cloned()));
    aes128_ecb_encrypt(&plaintext, key)
}

fn make_oracle<'a>(b64: &'a Base64Codec) -> Box<FnMut(&[u8]) -> Vec<u8> + 'a> {
    let key: [u8; 16] = rand::random();
    Box::new(move |prefix| oracle_with_key(prefix, &key, &b64))
}

fn is_ecb(oracle: &mut FnMut(&[u8]) -> Vec<u8>) -> bool {
    const BLOCKSIZE: usize = 16;
    let ciphertext = oracle(
        iter::repeat(0).take(3*BLOCKSIZE-1).collect::<Vec<u8>>().as_slice());
    let mut blocks = HashSet::new();
    for block in ciphertext.chunks(BLOCKSIZE) {
        if ! blocks.insert(block) {
            return true;
        }
    }
    false
}

fn crack_ecb_oracle(oracle: &mut FnMut(&[u8]) -> Vec<u8>,
                    blocksize: usize,
                    num_blocks: usize,
                    plainsize: usize) -> Vec<u8> {
    let mut plaintext = Vec::new();
    for blk_idx in 0..(num_blocks) {
        let mut pre = vec![0; blocksize];
        let mut blk_guess =
                if blk_idx == 0 { pre.clone() }
                else { plaintext[blocksize*(blk_idx-1)..].to_vec() };
        for i in 1..(blocksize+1) {
            pre.pop();
            let ciphertext = oracle(&pre);
            let block_i = &ciphertext[
                                    blocksize*blk_idx .. blocksize*(blk_idx+1)];
            blk_guess.remove(0);
            blk_guess.push(0);
            assert_eq!(blocksize, blk_guess.len());
            for b in 0..256 {
                let byte = b as u8;
                blk_guess[blocksize-1] = byte;
                let candidate = &oracle(&blk_guess)[0..blocksize];
                if candidate == block_i {
                    plaintext.push(byte);
                    break;
                }
            }
            if plaintext.len() == plainsize {
                return plaintext;
            }
            assert_eq!(blocksize*blk_idx + i, plaintext.len());
        }
        assert!(pre.is_empty());
    }
    unreachable!();
}

fn cookie_parse(s: &[u8]) -> HashMap<Vec<u8>, Vec<u8>> {
    let mut result = HashMap::new();
    for chunk in s.split(|&b| b == ('&' as u8)) {
        if let Some(idx) = chunk.iter().position(|&b| b == ('=' as u8)) {
            result.insert(chunk[0 .. idx].to_vec(), chunk[(idx+1) ..].to_vec());
        }
    }
    result
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
        let is_ecb_guess = is_ecb(&mut |plaintext| {
            let disc = disclosing_encryption_oracle(plaintext);
            is_ecb_really = disc.is_ecb;
            disc.ciphertext
        });
        assert_eq!(is_ecb_really, is_ecb_guess);
    }
    println!("Challenge 11: Success");
}

fn challenge12(b64: &Base64Codec) {
    let mut oracle = make_oracle(b64);

    let blocksize;
    let plainsize;
    let size1 = oracle(&[]).len();
    println!("Challenge 12: size1 = {}", size1);
    let mut prefix = Vec::new();
    loop {
        prefix.push(0);
        let size2 = oracle(&prefix).len();
        if size2 > size1 {
            blocksize = size2 - size1;
            plainsize = if prefix.len() > 1 { size1 - prefix.len() }
                        else                { size1 };
            break;
        }
    }

    println!("Challenge 12: Blocksize is {}, Plainsize is {}", blocksize,
             plainsize);

    {
        let oracle_ref = oracle.as_mut();
        // Not sure why the above and the extra scope here is necessary, but it
        // is (Rust 1.7.0).

        let is_ecb = is_ecb(oracle_ref);

        println!("Challenge 12: is_ecb is {}", is_ecb);

        let num_blocks = size1 / blocksize;

        let plaintext = crack_ecb_oracle(oracle_ref, blocksize, num_blocks,
                                         plainsize);

        println!("Challenge 12:\n{}", String::from_utf8_lossy(&plaintext));
    }
}

fn challenge13() {
    let m1 = cookie_parse(b"foo=bar&baz=qux&zap=zazzle");
    let mut e1 = HashMap::new();
    e1.insert(b"foo".to_vec(), b"bar".to_vec());
    e1.insert(b"baz".to_vec(), b"qux".to_vec());
    e1.insert(b"zap".to_vec(), b"zazzle".to_vec());
    assert_eq!(e1, m1);

    let m2 = cookie_parse(b"this=that&whatever&such=");
    let mut e2 = HashMap::new();
    e2.insert(b"this".to_vec(), b"that".to_vec());
    e2.insert(b"such".to_vec(), b"".to_vec());
    assert_eq!(e2, m2);

    println!("Challenge 13: Success (so far)");
}

pub fn run() {
    println!("=== SET 2 ===");
    let b64 = Base64Codec::new();
    challenge9();
    challenge10(&b64);
    challenge11();
    challenge12(&b64);
    challenge13();
}
