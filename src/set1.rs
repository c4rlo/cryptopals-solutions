use std::collections::HashSet;
use crypto;
use crypto::{aes,blockmodes};
use crypto::buffer::{ReadBuffer,WriteBuffer};
use crypto::symmetriccipher::Decryptor;
use common::*;

fn challenge1(b64: &Base64Codec) {
    let input = "49276d206b696c6c696e6720796f7572\
                 20627261696e206c696b65206120706f\
                 69736f6e6f7573206d757368726f6f6d".as_bytes();
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBs\
                    aWtlIGEgcG9pc29ub3VzIG11c2hyb29t".as_bytes();
    let raw = hex_decode(input);
    let b64 = b64.encode(&raw);
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
    println!("Challenge 3: key={}; {}", cracked.key_byte, escape_bytes(&cracked.decryption));
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
    let input = "Burning 'em, if you ain't quick and nimble\n\
                 I go crazy when I hear a cymbal".as_bytes();
    let expected = hex_decode("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a262263\
                               24272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b2028\
                               3165286326302e27282f".as_bytes());
    let output = xor_crypt(input.iter().cloned(), "ICE".as_bytes().iter().cloned());
    assert_eq!(expected, output);
    println!("Challenge 5: Success.");
}

fn challenge6(b64: &Base64Codec, corpus_cd: &[f64; 256]) {
    assert_eq!(37, edit_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()));
    println!("Challenge 6: Edit distance works.");

    let bytes = file_bytes("6.txt");
    let ciphertext = b64.decode(bytes);
    let cracked = crack_repeating_xor(&ciphertext, corpus_cd);
    print!("Challenge 6:\n{}", String::from_utf8_lossy(&cracked));
}

fn challenge7(b64: &Base64Codec) {
    let key = "YELLOW SUBMARINE".as_bytes();
    let ciphertext = b64.decode(file_bytes("7.txt"));
    let mut decryptor = aes::ecb_decryptor(aes::KeySize::KeySize128, key, blockmodes::PkcsPadding);
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

pub fn run() {
    println!("=== SET 1 ===");
    let b64 = Base64Codec::new();
    let corpus_cd = corpus_chardist();
    challenge1(&b64);
    challenge2();
    challenge3();
    challenge4(&corpus_cd);
    challenge5();
    challenge6(&b64, &corpus_cd);
    challenge7(&b64);
    challenge8();
}
