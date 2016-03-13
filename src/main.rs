use std::iter;
use std::borrow::Borrow;
use std::io::{BufReader,Read,Write};
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
    let mut result = Vec::new();
    for pair in h.chunks(2) {
        result.push(16 * hexdigit_decode(pair[0]) + hexdigit_decode(pair[1]));
    }
    result
}

fn b64_encode(b: &[u8]) -> Vec<u8> {
    let b64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                  abcdefghijklmnopqrstuvwxyz\
                  0123456789+/".as_bytes();
    let mut result = Vec::new();
    for triple in b.chunks(3) {
        let len = triple.len();
        let t0 = triple[0];
        let t1 = if len >= 2 { triple[1] } else { 0u8 };
        let t2 = if len >= 3 { triple[2] } else { 0u8 };
        result.push(b64map[(t0 >> 2) as usize]);
        result.push(b64map[(((t0 & 0x03u8) << 4) | (t1 >> 4)) as usize]);
        result.push(
            if len >= 2 {
                b64map[(((t1 & 0x0fu8) << 2) | (t2 >> 6)) as usize]
            } else {
                '=' as u8
            });
        result.push(
            if len >= 3 {
                b64map[(t2 & 0x3f) as usize]
            } else {
                '=' as u8
            });
    }
    result
}

#[allow(dead_code)]
fn print_data(v: &[u8]) {
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(v).unwrap();
    out.write_all(&[ '\n' as u8 ]).unwrap();
}

fn challenge1() {
    let input = "49276d206b696c6c696e6720796f7572\
                 20627261696e206c696b65206120706f\
                 69736f6e6f7573206d757368726f6f6d".as_bytes();
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs\
                    aWtlIGEgcG9pc29ub3VzIG11c2hyb29t".as_bytes();
    let raw = hex_decode(input);
    let b64 = b64_encode(&raw);
    // print_data(&b64);
    assert_eq!(expected, b64.as_slice());
    println!("Challenge 1: Success.");
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(a.len(), b.len());
    a.iter().zip(b).map(|x| x.0 ^ x.1).collect()
}

fn challenge2() {
    let input1 = "1c0111001f010100061a024b53535009181c".as_bytes();
    let input2 = "686974207468652062756c6c277320657965".as_bytes();
    let expected = "746865206b696420646f6e277420706c6179".as_bytes();
    let result = xor(
        hex_decode(input1).as_slice(),
        hex_decode(input2).as_slice());
    assert_eq!(hex_decode(expected).as_slice(), result.as_slice());
    println!("Challenge 2: Success.");
}

fn corpus_chardist() -> [f64; 256] {
    let file = BufReader::new(File::open("corpus.txt").unwrap());
    let bytes = file.bytes().map(|r| r.unwrap());
    let mut filtered_bytes = bytes.filter(|&b| b != ('\n' as u8));
    chardist(&mut filtered_bytes)
}

fn chardist<B, I: Iterator<Item=B>>(bytes: &mut I) -> [f64; 256]
            where B: Borrow<u8> {
    let mut counts = [0u64; 256];
    let mut total = 0u64;
    for b in bytes { 
        counts[*b.borrow() as usize] += 1;
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
    a.iter().zip(b.iter()).fold(0f64, |acc, x| acc + (x.0 - x.1).powi(2))
}

fn challenge3() {
    let input = hex_decode("1b37373331363f78151b7f2b783431333d\
                            78397828372d363c78373e783a393b3736".as_bytes());
    let input_len = input.len();
    let corpus_cd = corpus_chardist();
    let mut best_dist = std::f64::INFINITY;
    let mut best_key = 0u8;
    let mut best_plaintext = Vec::new();
    for i in 0..256 {
        let b = i as u8;
        let key: Vec<u8> = iter::repeat(b).take(input_len).collect();
        let cand = xor(input.as_slice(), key.as_slice());
        let dist = chardist_diff(&chardist(&mut cand.iter()), &corpus_cd);
        if dist < best_dist {
            // println!("Best dist now {}", dist);
            best_dist = dist;
            best_key = b;
            best_plaintext = cand;
        }
    }
    print!("Challenge 3: key={}; ", best_key);
    print_data(best_plaintext.as_slice());
}

fn main() {
    challenge1();
    challenge2();
    challenge3();
}
