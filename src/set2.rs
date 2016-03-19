use common::*;

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

pub fn run() {
    println!("=== SET 2 ===");
    let b64 = Base64Codec::new();
    challenge9();
    challenge10(&b64);
}
