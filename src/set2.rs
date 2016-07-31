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
    input.extend_from_slice(plaintext);
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

const CHALLENGE12_SECRET: &'static [u8] =
        b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
          aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
          dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
          YnkK";

fn oracle_with_key(prefix: &[u8], key: &[u8], b64: &Base64Codec) -> Vec<u8> {
    let mut plaintext = prefix.to_vec();
    plaintext.append(&mut b64.decode(CHALLENGE12_SECRET.iter().cloned()));
    aes128_ecb_encrypt(&plaintext, key)
}

fn make_oracle<'a>(b64: &'a Base64Codec) -> Box<(FnMut(&[u8]) -> Vec<u8>) + 'a> {
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
    for blk_idx in 0..num_blocks {
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
    for chunk in s.split(|&b| b == b'&') {
        if let Some(idx) = chunk.iter().position(|&b| b == b'=') {
            result.insert(chunk[0 .. idx].to_vec(), chunk[(idx+1) ..].to_vec());
        }
    }
    result
}

fn profile_for(user: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    result.extend_from_slice(b"email=");
    result.extend(user.iter().filter(|&b| ! b"&=".contains(b)));
    result.extend_from_slice(b"&uid=10&role=user");
    result
}

fn forge_admin_cookie<'a, F: Fn(&'a [u8]) -> Vec<u8>>(f: &F) -> Vec<u8> {
    // 0000000000111111111122222222223333333333 \ byte count
    // 0123456789012345678901234567890123456789 /
    // [Block_0_______][Block_1_______][Block_2 - AES blocks
    // admin........... (. = 11 = 0x0b)         - what we want to encode (PKCS7 padding!)
    // email=aaaaaaaaaaadmin...........&uid=10& - how we are going to encode it
    // email=foo12@bar.com&uid=10&role=admin... - the end result

    let input1 = b"aaaaaaaaaaadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
    assert_eq!(32, b"email=".len() + input1.len());
    let output1 = f(input1);
    let adminblock = &output1[16..32];
    let input2 = b"foo12@bar.com";
    let output2 = f(input2);
    let mut result = Vec::new();
    result.extend_from_slice(&output2[0..32]);
    result.extend_from_slice(adminblock);
    assert_eq!(48, result.len());
    result
}

fn challenge9() {
    let input = b"YELLOW SUBMARINE";
    let padded = pkcs7_pad(input, 20);
    println!("Challenge 9: {}", escape_bytes(&padded));
}

fn challenge10(b64: &Base64Codec) {
    let ciphertext = b64.decode(file_bytes("10.txt"));
    let key = b"YELLOW SUBMARINE";
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
    assert_eq!(16, blocksize);

    let is_ecb = is_ecb(&mut *oracle);

    println!("Challenge 12: is_ecb is {}", is_ecb);
    assert!(is_ecb);

    let num_blocks = size1 / blocksize;

    let plaintext = crack_ecb_oracle(&mut *oracle, blocksize, num_blocks,
                                     plainsize);

    println!("Challenge 12:\n{}", String::from_utf8_lossy(&plaintext));
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

    let p = profile_for(b"foo@bar.com");
    assert_eq!(&b"email=foo@bar.com&uid=10&role=user"[..], &p[..]);

    let key: [u8; 16] = rand::random();

    let encrypted_profile_for = |user| aes128_ecb_encrypt(&profile_for(user), &key);

    let encrypted_admin_cookie = forge_admin_cookie(&encrypted_profile_for);
    let plain_admin_cookie = aes128_ecb_decrypt(&encrypted_admin_cookie, &key);
    println!("Challenge 13: Admin cookie: '{}' (len={})", escape_bytes(&plain_admin_cookie),
                plain_admin_cookie.len());
    let parsed_admin_cookie = cookie_parse(&plain_admin_cookie);
    assert_eq!(parsed_admin_cookie.get(&b"role".to_vec()), Some(&b"admin".to_vec()));

    println!("Challenge 13: Success");
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
