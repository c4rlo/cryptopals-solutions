use std;
use std::collections::HashSet;
use crypto;
use crypto::{aes,blockmodes};
use crypto::buffer::{ReadBuffer,WriteBuffer};
use common::*;
use items;

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
    let filtered_bytes = file_bytes("corpus.txt").filter(|&b| b != b'\n');
    chardist(filtered_bytes)
}

struct SingleXorCandidate {
    pub badness: f64,
    pub key_byte: u8,
    pub decryption: Vec<u8>
}

impl SingleXorCandidate {
    pub fn new() -> Self {
        SingleXorCandidate {
            badness: std::f64::INFINITY,
            key_byte: 0u8,
            decryption: Vec::new()
        }
    }
}

fn crack_single_xor(ciphertext: &[u8], corpus_cd: &[f64; 256])
            -> SingleXorCandidate {
    let mut best = SingleXorCandidate::new();
    for i in 0..256 {
        let key_byte = i as u8;
        let decryption = xor(ciphertext, std::iter::repeat(key_byte));
        let badness = chardist_diff(&chardist(decryption.iter().cloned()),
                    &corpus_cd);
        if badness < best.badness {
            best = SingleXorCandidate {
                badness: badness, key_byte: key_byte, decryption: decryption };
        }
    }
    best
}

fn edit_distance(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).map(|(&x, &y)| (x ^ y).count_ones()).sum::<u32>()
        as usize
}

fn crack_repeating_xor(ciphertext: &[u8], corpus_cd: &[f64; 256]) -> Vec<u8> {
    struct ScoredKeysize {
        keysize: usize,
        badness: f64
    }

    let mut scored_keysizes = Vec::new();

    for keysize in 2..41 {
        const N: usize = 10;
        let mut ed_sum = 0f64;
        for i in 0..N {
            let chunk1 = &ciphertext[(keysize*i) .. (keysize*(i+1))];
            let chunk2 = &ciphertext[(keysize*(i+1)) .. (keysize*(i+2))];
            ed_sum += edit_distance(chunk1, chunk2) as f64;
        }
        scored_keysizes.push(ScoredKeysize {
            keysize: keysize,
            badness: ed_sum / N as f64 / keysize as f64 });
    }

    scored_keysizes.sort_by(|a, b| a.badness.partial_cmp(&b.badness).unwrap());

    let mut best_key = Vec::new();

    for sk in scored_keysizes.iter().take(5) {
        let keysize = sk.keysize;
        let mut key = Vec::new();
        for i in 0..keysize {
            let cracked = crack_single_xor(
                ciphertext.iter().enumerate().filter_map(
                    |(j, c)| if j % sk.keysize == i { Some(*c) } else { None })
                .collect::<Vec<u8>>().as_slice(),
                &corpus_cd);
            key.push(cracked.key_byte);
        }
        println!("  Keysize {} has badness {}, key \"{}\"", sk.keysize,
                 sk.badness, escape_bytes(&key));
        if best_key.is_empty() {
            best_key = key;
        }
    }

    xor_crypt(ciphertext, best_key)
}

fn challenge1(b64: &Base64Codec) {
    let input = b"49276d206b696c6c696e6720796f7572\
                  20627261696e206c696b65206120706f\
                  69736f6e6f7573206d757368726f6f6d";
    let expected = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs\
                     aWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let raw = hex_decode(input);
    let b64 = b64.encode(&raw);
    assert_eq!(&expected[..], &b64[..]);
    println!("Challenge 1: Success.");
}

fn challenge2() {
    let input1 = b"1c0111001f010100061a024b53535009181c";
    let input2 = b"686974207468652062756c6c277320657965";
    let expected = b"746865206b696420646f6e277420706c6179";
    let result = xor(hex_decode(input1), hex_decode(input2));
    assert_eq!(hex_decode(expected), result);
    println!("Challenge 2: Success.");
}

fn challenge3() {
    let input = hex_decode(b"1b37373331363f78151b7f2b783431333d\
                             78397828372d363c78373e783a393b3736");
    let cracked = crack_single_xor(&input, &corpus_chardist());
    println!("Challenge 3: key={}; {}", cracked.key_byte,
             escape_bytes(&cracked.decryption));
}

fn challenge4(corpus_cd: &[f64; 256]) {
    let mut best = SingleXorCandidate::new();
    for line in file_lines("4.txt") {
        let ciphertext = hex_decode(line.unwrap().as_bytes());
        let cracked = crack_single_xor(&ciphertext, &corpus_cd);
        if cracked.badness < best.badness {
            best = cracked;
        }
    }
    println!("Challenge 4: {}", escape_bytes(&best.decryption));
}

fn challenge5() {
    let input = b"Burning 'em, if you ain't quick and nimble\n\
                  I go crazy when I hear a cymbal";
    let expected = hex_decode(b"0b3637272a2b2e63622c2e69692a2369\
                                3a2a3c6324202d623d63343c2a262263\
                                24272765272a282b2f20430a652e2c65\
                                2a3124333a653e2b2027630c692b2028\
                                3165286326302e27282f");
    let output = xor_crypt(&input[..], b"ICE");
    assert_eq!(expected, output);
    println!("Challenge 5: Success.");
}

fn challenge6(b64: &Base64Codec, corpus_cd: &[f64; 256]) {
    assert_eq!(37, edit_distance(b"this is a test", b"wokka wokka!!!"));
    println!("Challenge 6: Edit distance works.");

    let ciphertext = b64.decode(file_bytes("6.txt"));
    let cracked = crack_repeating_xor(&ciphertext, corpus_cd);
    print!("Challenge 6:\n{}", String::from_utf8_lossy(&cracked));
}

fn challenge7(b64: &Base64Codec) {
    let key = b"YELLOW SUBMARINE";
    let ciphertext = b64.decode(file_bytes("7.txt"));
    let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, key,
                                           blockmodes::PkcsPadding);
    let mut inbuf = crypto::buffer::RefReadBuffer::new(&ciphertext);
    let mut outbuf_storage = [0; 8192];
    let mut outbuf = crypto::buffer::RefWriteBuffer::new(&mut outbuf_storage);
    let mut decrypted = Vec::new();
    loop {
        let result = decryptor.decrypt(&mut inbuf, &mut outbuf, true).unwrap();
        decrypted.extend(outbuf.take_read_buffer().take_remaining());
        if let crypto::buffer::BufferResult::BufferUnderflow = result {
            break;
        }
    }
    print!("Challenge 7:\n{}", String::from_utf8_lossy(&decrypted));
}

fn challenge8() {
    const SIZE: usize = 16;
    for (line_no, line) in file_lines("8.txt").enumerate() {
        let ciphertext = hex_decode(line.unwrap().as_bytes());
        let mut chunk_set = HashSet::new();
        for chunk in ciphertext.chunks(SIZE) {
            chunk_set.insert(chunk);
        }
        if chunk_set.len() < ciphertext.len() / SIZE {
            println!("Challenge 8: Line {} is ECB", line_no + 1);
        }
    }
}

pub fn run(spec: &items::ItemsSpec) {
    let b64 = Base64Codec::new();
    let corpus_cd = corpus_chardist();
    ch!(spec, challenge1, &b64);
    ch!(spec, challenge2);
    ch!(spec, challenge3);
    ch!(spec, challenge4, &corpus_cd);
    ch!(spec, challenge5);
    ch!(spec, challenge6, &b64, &corpus_cd);
    ch!(spec, challenge7, &b64);
    ch!(spec, challenge8);
}
