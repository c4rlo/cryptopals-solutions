use std::io::{BufReader,BufRead,Read,Write};
use std::fs::File;

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

fn hex_decode(h: &[u8]) -> Vec<u8> {
    // We want to write the below, but as of Rust 1.7, slice pattern syntax is unstable.
    // h.chunks(2).map(|[a, b]| 16 * hexdigit_decode(a) + hexdigit_decode(b)).collect()
    h.chunks(2).map(|pair| 16 * hexdigit_decode(pair[0]) + hexdigit_decode(pair[1])).collect()
}

struct IterChunker<I: Iterator> {
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

trait Chunkable<I: Iterator> {
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

struct Base64Codec {
    enc_map: &'static [u8],
    dec_map: Vec<u8>
}

impl Base64Codec {
    fn new() -> Self {
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

    fn encode(&self, b: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        for triple in b.chunks(3) {
            let len = triple.len();
            let t0 = triple[0];
            let t1 = if len >= 2 { triple[1] } else { 0u8 };
            let t2 = if len >= 3 { triple[2] } else { 0u8 };
            result.push(self.enc_map[(t0 >> 2) as usize]);
            result.push(self.enc_map[(((t0 & 0x03u8) << 4) | (t1 >> 4)) as usize]);
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

    fn decode<I: Iterator<Item=u8>>(&self, b: I) -> Vec<u8> {
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

fn print_data(v: &[u8]) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(v).unwrap();
    out.write_all(&[ '\n' as u8 ]).unwrap();
}

fn xor<I1: Iterator<Item=u8>, I2: Iterator<Item=u8>>(x1: I1, x2: I2) -> Vec<u8> {
    x1.zip(x2).map(|(a, b)| a ^ b).collect()
}

fn xor_crypt<I1: Iterator<Item=u8>, I2: Iterator<Item=u8> + Clone>(content: I1, key: I2)
            -> Vec<u8> {
    xor(content, key.cycle())
}

fn chardist<I: Iterator<Item=u8>>(bytes: I) -> [f64; 256] {
    let mut counts = [0u64; 256];
    let mut total = 0u64;
    for b in bytes { 
        counts[b as usize] += 1;
        total += 1;
    }
    let totalf = total as f64;
    let mut result = [0f64; 256];
    for i in 0..256 {
        result[i] = (counts[i] as f64) / totalf;
    }
    result
}

fn chardist_diff(a: &[f64; 256], b: &[f64; 256]) -> f64 {
    a.iter().zip(b.iter()).fold(0f64, |acc, (x, y)| acc + (x - y).powi(2))
}

fn corpus_chardist() -> [f64; 256] {
    let file = BufReader::new(File::open("corpus.txt").unwrap());
    let bytes = file.bytes().map(|r| r.unwrap());
    let filtered_bytes = bytes.filter(|&b| b != ('\n' as u8));
    chardist(filtered_bytes)
}

struct SingleXorCandidate {
    badness: f64,
    key_byte: u8,
    decryption: Vec<u8>
}

impl SingleXorCandidate {
    fn new() -> Self {
        SingleXorCandidate {
            badness: std::f64::INFINITY,
            key_byte: 0u8,
            decryption: Vec::new()
        }
    }
}

fn crack_single_xor(ciphertext: &[u8], corpus_cd: &[f64; 256]) -> SingleXorCandidate {
    let mut best = SingleXorCandidate::new();
    for i in 0..256 {
        let key_byte = i as u8;
        let decryption = xor(ciphertext.iter().cloned(), std::iter::repeat(key_byte));
        let badness = chardist_diff(&chardist(decryption.iter().cloned()), &corpus_cd);
        if badness < best.badness {
            best = SingleXorCandidate {
                badness: badness, key_byte: key_byte, decryption: decryption };
        }
    }
    best
}

fn edit_distance(a: &[u8], b: &[u8]) -> usize {
    // We want to write the below, but as of Rust 1.7, the 'sum()' method is unstable
    // a.iter().zip(b.iter()).map(|(&x, &y)| (x ^ y).count_ones()).sum::<u32>() as usize

    let mut result = 0usize;
    for n in a.iter().zip(b.iter()).map(|(&x, &y)| (x ^ y).count_ones()) {
        result += n as usize;
    }
    result
}

fn challenge1() {
    let input = "49276d206b696c6c696e6720796f7572\
                 20627261696e206c696b65206120706f\
                 69736f6e6f7573206d757368726f6f6d".as_bytes();
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs\
                    aWtlIGEgcG9pc29ub3VzIG11c2hyb29t".as_bytes();
    let raw = hex_decode(input);
    let b64 = Base64Codec::new().encode(&raw);
    // print_data(&b64);
    assert_eq!(expected, b64.as_slice());
    println!("Challenge 1: Success.");
}

fn challenge2() {
    let input1 = "1c0111001f010100061a024b53535009181c".as_bytes();
    let input2 = "686974207468652062756c6c277320657965".as_bytes();
    let expected = "746865206b696420646f6e277420706c6179".as_bytes();
    let result = xor(
        hex_decode(input1).iter().cloned(),
        hex_decode(input2).iter().cloned());
    assert_eq!(hex_decode(expected), result);
    println!("Challenge 2: Success.");
}

fn challenge3() {
    let input = hex_decode("1b37373331363f78151b7f2b783431333d\
                            78397828372d363c78373e783a393b3736".as_bytes());
    let cracked = crack_single_xor(&input, &corpus_chardist());
    print!("Challenge 3: key={}; ", cracked.key_byte);
    print_data(&cracked.decryption);
}

fn challenge4() {
    let corpus_cd = corpus_chardist();
    let mut best = SingleXorCandidate::new();
    for line in BufReader::new(File::open("4.txt").unwrap()).lines() {
        let ciphertext = hex_decode(line.unwrap().as_bytes());
        let cracked = crack_single_xor(&ciphertext, &corpus_cd);
        if cracked.badness < best.badness {
            best = cracked;
        }
    }
    print!("Challenge 4: ");
    print_data(&best.decryption);
}

fn challenge5() {
    let input = "Burning 'em, if you ain't quick and nimble\n\
                 I go crazy when I hear a cymbal".as_bytes();
    let expected = hex_decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263\
                               24272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028\
                               3165286326302e27282f".as_bytes());
    let output = xor_crypt(input.iter().cloned(), "ICE".as_bytes().iter().cloned());
    assert_eq!(expected, output);
    println!("Challenge 5: Success.");
}

fn challenge6() {
    assert_eq!(37, edit_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()));
    println!("Challenge 6: Edit distance works.");

    let file = BufReader::new(File::open("6.txt").unwrap());
    let bytes = file.bytes().map(|r| r.unwrap());
    let ciphertext = Base64Codec::new().decode(bytes);

    for keysize in 2..41 {
    }
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
    challenge4();
    challenge5();
    challenge6();
}
