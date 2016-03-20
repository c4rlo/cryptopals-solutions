use std;
use std::fmt;
use std::ascii;
use std::io::{BufReader,BufRead,Read};
use std::fs::File;
use crypto::aessafe;
use crypto::symmetriccipher::{BlockEncryptor,BlockDecryptor};

fn hexdigit_decode(d: u8) -> u8 {
    if '0' as u8 <= d && d <= '9' as u8 {
        d - '0' as u8
    } else if 'a' as u8 <= d && d <= 'f' as u8 {
        d - 'a' as u8 + 0xau8
    } else if 'A' as u8 <= d && d <= 'F' as u8 {
        d - 'A' as u8 + 0xau8
    } else {
        panic!("Illegal hex digit")
    }
}

pub fn hex_decode(h: &[u8]) -> Vec<u8> {
    // We want to write the below, but as of Rust 1.7, slice pattern syntax is
    // unstable.  h.chunks(2).map(|[a, b]| 16 * hexdigit_decode(a) +
    // hexdigit_decode(b)).collect()
    h.chunks(2).map(
        |pair| 16 * hexdigit_decode(pair[0]) + hexdigit_decode(pair[1]))
        .collect()
}

pub struct IterChunker<I: Iterator> {
    inner: I,
    chunk_size: usize
}

impl<I: Iterator> Iterator for IterChunker<I> {
    type Item = Vec<I::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next() {
            None => None,
            Some(x) => {
                let mut result = vec![x];
                for _ in 1..self.chunk_size {
                    match self.inner.next() {
                        None => break,
                        Some(y) => result.push(y)
                    }
                }
                Some(result)
            }
        }
    }
}

pub trait Chunkable<I: Iterator> {
    fn chunks(self, chunk_size: usize) -> IterChunker<I>;
}

impl<I: Iterator> Chunkable<I> for I {
    fn chunks(self, chunk_size: usize) -> IterChunker<I> {
        IterChunker { inner: self, chunk_size: chunk_size }
    }
}

const BASE64CHARS: &'static str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                   abcdefghijklmnopqrstuvwxyz\
                                   0123456789+/";

pub struct Base64Codec {
    enc_map: &'static [u8],
    dec_map: Vec<u8>
}

impl Base64Codec {
    pub fn new() -> Self {
        let base64bytes = BASE64CHARS.as_bytes();
        let mut dec_map = Vec::new();
        dec_map.resize(256, 0u8);
        for (i, b) in base64bytes.iter().enumerate() {
            dec_map[*b as usize] = i as u8;
        }
        Base64Codec {
            enc_map: base64bytes,
            dec_map: dec_map
        }
    }

    pub fn encode(&self, b: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        for triple in b.chunks(3) {
            let len = triple.len();
            let t0 = triple[0];
            let t1 = if len >= 2 { triple[1] } else { 0u8 };
            let t2 = if len >= 3 { triple[2] } else { 0u8 };
            result.push(self.enc_map[(t0 >> 2) as usize]);
            result.push(self.enc_map[
                        (((t0 & 0x03u8) << 4) | (t1 >> 4)) as usize]);
            result.push(
                if len >= 2 {
                    self.enc_map[(((t1 & 0x0fu8) << 2) | (t2 >> 6)) as usize]
                } else {
                    '=' as u8
                });
            result.push(
                if len >= 3 {
                    self.enc_map[(t2 & 0x3f) as usize]
                } else {
                    '=' as u8
                });
        }
        result
    }

    pub fn decode<I: Iterator<Item=u8>>(&self, b: I) -> Vec<u8> {
        let mut result = Vec::new();
        for quad in b.filter(|&b| b != ('\n' as u8)).chunks(4) {
            let len = quad.iter().cloned().take_while(|&b| b != ('=' as u8)).count();
            let q0 = self.dec_map[quad[0] as usize];
            let q1 = self.dec_map[quad[1] as usize];
            let q2 = if len >= 3 { self.dec_map[quad[2] as usize] } else { 0u8 };
            let q3 = if len >= 4 { self.dec_map[quad[3] as usize] } else { 0u8 };
            result.push((q0 << 2) | (q1 >> 4));
            if len >= 3 {
                result.push((q1 << 4) | (q2 >> 2));
            }
            if len >= 4 {
                result.push((q2 << 6) | q3);
            }
        }
        result
    }
}

pub struct EscapedBytes<'a> {
    v: &'a [u8]
}

impl<'a> fmt::Display for EscapedBytes<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for &b in self.v {
            for e in ascii::escape_default(b) {
                f.write_str(std::str::from_utf8(&[e]).unwrap()).unwrap();
            }
        }
        Ok(())
    }
}

pub fn escape_bytes(v: &[u8]) -> EscapedBytes {
    EscapedBytes { v: v }
}

fn open_file_buf(filename: &str) -> BufReader<File> {
    BufReader::new(File::open("inputs/".to_owned() + filename).unwrap())
}

pub type FileBytes =
        std::iter::Map<std::io::Bytes<BufReader<File>>, fn(std::io::Result<u8>)
                                                            -> u8>;

pub fn file_bytes(filename: &str) -> FileBytes {
    open_file_buf(filename).bytes().map(std::io::Result::unwrap)
}

pub type FileLines = std::io::Lines<BufReader<File>>;

pub fn file_lines(filename: &str) -> FileLines {
    open_file_buf(filename).lines()
}

pub fn xor<I1: Iterator<Item=u8>, I2: Iterator<Item=u8>>(x1: I1, x2: I2)
            -> Vec<u8> {
    x1.zip(x2).map(|(a, b)| a ^ b).collect()
}

pub fn xor_crypt<I1: Iterator<Item=u8>, I2: Iterator<Item=u8> + Clone>(
            content: I1, key: I2) -> Vec<u8> {
    xor(content, key.cycle())
}

pub fn pkcs7_pad(b: &[u8], blocksize: usize) -> Vec<u8> {
    let num = blocksize - (b.len() % blocksize);
    assert!(num < 256, "num={}", num);
    let mut result = b.to_vec();
    result.extend(std::iter::repeat(num as u8).take(num));
    result
}

pub fn pkcs7_unpad(b: &mut Vec<u8>) {
    if let Some(&last) = b.last() {
        let len = b.len();
        b.truncate(len - last as usize);
    }
}

#[allow(dead_code)]
fn aes128_block_encrypt(plaintext: &[u8], key: &[u8]) -> [u8; 16] {
    let encryptor = aessafe::AesSafe128Encryptor::new(key);
    let mut result = [0; 16];
    encryptor.encrypt_block(plaintext, &mut result);
    result
}

fn aes128_block_decrypt(ciphertext: &[u8], key: &[u8]) -> [u8; 16] {
    let decryptor = aessafe::AesSafe128Decryptor::new(key);
    let mut result = [0; 16];
    decryptor.decrypt_block(ciphertext, &mut result);
    result
}

pub fn aes128_ecb_encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for block in pkcs7_pad(plaintext, 16).as_slice().chunks(16) {
        result.extend(&aes128_block_encrypt(block, key));
    }
    result
}

#[allow(dead_code)]
pub fn aes128_ecb_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for block in ciphertext.chunks(16) {
        result.extend(&aes128_block_decrypt(block, key));
    }
    pkcs7_unpad(&mut result);
    result
}

pub fn aes128_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8; 16])
            -> Vec<u8> {
    let mut x = *iv;
    let mut result = Vec::new();
    for plainblock in pkcs7_pad(plaintext, 16).chunks(16) {
        x = aes128_block_encrypt(
            xor(plainblock.iter().cloned(), x.iter().cloned()).as_slice(),
            key);
        result.extend(&x);
    }
    result
}

pub fn aes128_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8; 16])
            -> Vec<u8> {
    let mut x: &[u8] = iv;
    let mut result = Vec::new();
    for cipherblock in ciphertext.chunks(16) {
        result.extend(xor(
                aes128_block_decrypt(cipherblock, key).iter().cloned(),
                x.iter().cloned()));
        x = cipherblock;
    }
    pkcs7_unpad(&mut result);
    result
}
