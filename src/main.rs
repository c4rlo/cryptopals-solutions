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

fn challenge1() {
    let input = "49276d206b696c6c696e6720796f7572\
                 20627261696e206c696b65206120706f\
                 69736f6e6f7573206d757368726f6f6d".as_bytes();
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs\
                    aWtlIGEgcG9pc29ub3VzIG11c2hyb29t".as_bytes();
    let raw = hex_decode(input);
    let b64 = b64_encode(&raw);
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(&b64).unwrap();
    out.write_all(&[ '\n' as u8 ]).unwrap();
    assert_eq!(expected, b64.as_slice());
    println!("Challenge 1: Success.");
}

fn main() {
    challenge1();
}
