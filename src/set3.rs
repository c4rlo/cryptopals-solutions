use std::collections::HashSet;
use rand;
use rand::distributions::{IndependentSample,Range};
use common::*;
use items;

const CHALLENGE17_SECRETS: [ &'static [u8]; 10 ] = [
    b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" ];

#[derive(Clone)]
struct CbcEncryption {
    ciphertext: Vec<u8>,
    iv: [u8; AES_BLOCKSIZE]
}

impl CbcEncryption {
    fn new(ciphertext: Vec<u8>, iv: [u8; AES_BLOCKSIZE]) -> Self {
        CbcEncryption {
            ciphertext: ciphertext,
            iv: iv
        }
    }

    fn twiddle_at(&mut self, pos: usize) -> &mut u8 {
        assert!(pos < self.ciphertext.len());
        if pos < AES_BLOCKSIZE {
            &mut self.iv[pos]
        } else {
            &mut self.ciphertext[pos - AES_BLOCKSIZE]
        }
    }
}

struct Challenge17BlackBox<'a> {
    key: [u8; AES_BLOCKSIZE],
    b64: &'a Base64Codec
}

impl<'a> Challenge17BlackBox<'a> {
    fn new(b64: &'a Base64Codec) -> Self {
        Challenge17BlackBox {
            key: rand::random(),
            b64: b64
        }
    }

    fn gimme(&self) -> CbcEncryption {
        // Randomly select one of the 10 plaintexts
        let between = Range::new(0, CHALLENGE17_SECRETS.len());
        let mut rng = rand::thread_rng();
        let plaintext_b64 = &CHALLENGE17_SECRETS[between.ind_sample(&mut rng)];
        let plaintext = self.b64.decode(plaintext_b64.iter().cloned());

        let iv: [u8; AES_BLOCKSIZE] = rand::random();
        let ciphertext = aes128_cbc_encrypt(&plaintext, &self.key, &iv);

        CbcEncryption::new(ciphertext, iv)
    }

    fn gimme_test(&self) -> CbcEncryption {
        let iv: [u8; AES_BLOCKSIZE] = rand::random();
        let ciphertext = aes128_cbc_encrypt(b"1234567890abcdefghijklmnopqrstuvwxzy", &self.key,
                                            &iv);
        CbcEncryption::new(ciphertext, iv)
    }

    fn has_valid_padding(&self, enc: &CbcEncryption) -> bool {
        let plaintext = aes128_cbc_decrypt_raw(&enc.ciphertext, &self.key, &enc.iv);
        pkcs7_validated_padding(&plaintext).is_some()
    }
}

fn cbc_find_padding(enc: &CbcEncryption, blackbox: &Challenge17BlackBox) -> usize {
    let mut e = enc.clone();
    assert!(e.ciphertext.len() >= AES_BLOCKSIZE);
    let start = e.ciphertext.len() - AES_BLOCKSIZE;
    for i in 0..(AES_BLOCKSIZE-1) {
        *e.twiddle_at(start + i) ^= 127u8;
        if ! blackbox.has_valid_padding(&e) {
            return AES_BLOCKSIZE - i;
        }
    }
    1
}

// Decrypt the last AES block in encryption 'enc' using the given 'blackbox'.  'padding' must be
// the number of padding bytes that are known to occur at the end of 'enc'.  Return the resulting
// plaintext in reverse (happens to be convenient for both caller and callee), excluding any
// padding.
fn cbc_crack_last_block_rev(encryption: &CbcEncryption, padding: usize,
                            blackbox: &Challenge17BlackBox) -> Vec<u8> {
    let len = encryption.ciphertext.len();
    let mut result = vec![padding as u8; padding];

    for i in padding..AES_BLOCKSIZE {
        let mut enc = encryption.clone();
        let new_padding_u8 = (i + 1) as u8;
        for j in 0..i {
            *enc.twiddle_at(len - 1 - j) ^= result[j] ^ new_padding_u8;
        }
        let pos = len - 1 - i;
        let orig = *enc.twiddle_at(pos);
        let mut candidates = Vec::new();
        for guess in 0..256 {
            let guess_u8 = guess as u8;
            *enc.twiddle_at(pos) = orig ^ guess_u8;
            if blackbox.has_valid_padding(&enc) {
                // We know that (very likely) plaintext_byte ^ guess_u8 == new_padding_u8.
                // Therefore...
                let plaintext_byte = new_padding_u8 ^ guess_u8;
                candidates.push(plaintext_byte);
            }
        }
        assert_eq!(1, candidates.len());  // TODO: This need not necessarily hold true
        result.push(candidates[0]);
    }

    if padding == 0 {
        result
    } else {
        result.split_off(padding)
    }
}

fn cbc_crack(mut enc: CbcEncryption, blackbox: &Challenge17BlackBox) -> Vec<u8> {
    let ciphertext_len = enc.ciphertext.len();
    let num_blocks = ciphertext_len / AES_BLOCKSIZE;

    assert_eq!(0, ciphertext_len % AES_BLOCKSIZE);

    let mut padding = cbc_find_padding(&enc, blackbox);
    let mut plaintext_rev = Vec::new();

    for _ in 0..num_blocks {
        let mut cracked_block_rev =
            cbc_crack_last_block_rev(&enc, padding, blackbox);
        plaintext_rev.append(&mut cracked_block_rev);
        let new_len = enc.ciphertext.len() - AES_BLOCKSIZE;
        enc.ciphertext.truncate(new_len);
        padding = 0;
    }

    plaintext_rev.reverse();
    plaintext_rev
}

fn challenge17(b64: &Base64Codec) {
    let blackbox = Challenge17BlackBox::new(b64);

    let mut enc = blackbox.gimme();
    assert!(blackbox.has_valid_padding(&enc));

    let ciphertext_len = enc.ciphertext.len();
    *enc.twiddle_at(ciphertext_len - 1) ^= 127u8;
    assert!(!blackbox.has_valid_padding(&enc));

    let enc = blackbox.gimme_test();
    let cracked = cbc_crack(enc, &blackbox);
    println!("Challenge 17 (warmup): {}", escape_bytes(&cracked));

    let mut all = HashSet::new();
    while all.len() < 10 {
        let enc = blackbox.gimme();
        let cracked = cbc_crack(enc, &blackbox);
        all.insert(cracked);
    }

    println!("Challenge 17:");
    let mut all_sorted = all.iter().collect::<Vec<_>>();
    all_sorted.sort();
    let mut i = 0;
    for cracked in all_sorted {
        println!("  {}", escape_bytes(cracked));
        let actual = b64.decode(CHALLENGE17_SECRETS[i].iter().cloned());
        assert_eq!(actual, *cracked);
        i += 1;
    }
}

pub fn run(spec: &items::ItemsSpec) {
    let b64 = Base64Codec::new();
    ch!(spec, challenge17, &b64);
}
