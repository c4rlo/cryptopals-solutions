use std::io::Write;

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
fn print_vec(v: &[u8]) {
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
    // print_vec(&b64);
    assert_eq!(expected, b64.as_slice());
    println!("Challenge 1: Success.");
}

fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
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

fn main() {
    challenge1();
    challenge2();
}
