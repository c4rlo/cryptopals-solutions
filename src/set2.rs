use std::iter;
use std::collections::{HashMap,HashSet};
use rand;
use rand::Rng;
use rand::distributions::{IndependentSample,Range};
use common::*;
use items;

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
    } else {
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

fn oracle_with_key(arg: &[u8], key: &[u8], b64: &Base64Codec) -> Vec<u8> {
    let mut plaintext = arg.to_vec();
    plaintext.append(&mut b64.decode(CHALLENGE12_SECRET.iter().cloned()));
    aes128_ecb_encrypt(&plaintext, key)
}

fn randpfx_oracle_with_key(randpfx: &[u8], arg: &[u8], key: &[u8],
                           b64: &Base64Codec) -> Vec<u8> {
    let mut plaintext = randpfx.to_vec();
    plaintext.extend_from_slice(arg);
    oracle_with_key(&plaintext, key, b64)
}

fn make_oracle<'a>(b64: &'a Base64Codec) -> Box<(FnMut(&[u8]) -> Vec<u8>) + 'a> {
    let key: [u8; 16] = rand::random();
    Box::new(move |arg| oracle_with_key(arg, &key, &b64))
}

fn make_randpfx_oracle<'a>(b64: &'a Base64Codec)
                                        -> Box<(FnMut(&[u8]) -> Vec<u8>) + 'a> {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    let randpfx_len = rng.gen_range(10, 200);
    let randpfx = rng.gen_iter::<u8>().take(randpfx_len).collect::<Vec<u8>>();
    Box::new(move |arg| randpfx_oracle_with_key(&randpfx, arg, &key, &b64))
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
                    pfxlen: usize) -> Vec<u8> {
    let pfxrem = pfxlen % blocksize;
    let pfxfill = if pfxrem == 0 { 0 } else { blocksize - pfxrem };
    let pfxblocks = (pfxlen + blocksize - 1) / blocksize;
    let full_pad_block = &oracle(&vec![blocksize as u8; pfxfill + blocksize])
                            [blocksize*pfxblocks .. blocksize*(pfxblocks+1)];
    let mut plaintext = Vec::new();
    for i in 0.. {  // iterate over blocks
        let mut pre = vec![0; pfxfill + blocksize];
        let mut aligned_blk_guess;
        if i == 0 {
            aligned_blk_guess = vec![0; pfxfill + blocksize];
        } else {
            aligned_blk_guess = vec![0; pfxfill];
            aligned_blk_guess.extend_from_slice(
                &plaintext[blocksize*(i-1)..]);
        }
        for j in 0..blocksize {  // iterate over bytes within block
            pre.pop();
            let ciphertext = oracle(&pre);
            let block_i_begin = blocksize*(pfxblocks + i);
            let block_i_end = block_i_begin + blocksize;
            let block_i = &ciphertext[block_i_begin .. block_i_end];
            aligned_blk_guess.remove(pfxfill);
            aligned_blk_guess.push(0);
            assert_eq!(pfxfill + blocksize, aligned_blk_guess.len());
            for b in 0..256 {  // iterate over possible byte values
                let byte = b as u8;
                *aligned_blk_guess.last_mut().unwrap() = byte;
                let guess_ciphertext = oracle(&aligned_blk_guess);
                let candidate =
                    &guess_ciphertext[ pfxblocks    * blocksize ..
                                      (pfxblocks+1) * blocksize];
                if candidate == block_i {
                    plaintext.push(byte);
                    break;
                }
            }
            // are we done?
            if block_i_end == ciphertext.len() - blocksize
                && &ciphertext[block_i_end .. block_i_end+blocksize]
                    == full_pad_block
            {
                return plaintext;
            }
            assert_eq!(blocksize*i + j + 1, plaintext.len());
        }
        assert_eq!(pfxfill, pre.len());
    }
    unreachable!();
}

fn determine_randpfx_len(oracle: &mut FnMut(&[u8]) -> Vec<u8>,
                         blocksize: usize) -> usize {
    let mut probe = vec![0; 2*blocksize];
    for i in 0..blocksize {
        let result = oracle(&probe);
        let mut chunks = result.chunks(blocksize);
        let chunk0 = chunks.next().unwrap();
        let twinpos = chunks.scan(chunk0, |prev, curr| {
            let is_twin = prev == &curr;
            *prev = curr;
            Some(is_twin)
        }).position(|item| item);
        if let Some(n) = twinpos {
            return blocksize*n - i;
        }
        probe.push(0);
    }
    unreachable!();
}

fn crack_randpfx_oracle(oracle: &mut FnMut(&[u8]) -> Vec<u8>,
                        blocksize: usize) -> Vec<u8> {
    let randpfx_len = determine_randpfx_len(oracle, blocksize);
    crack_ecb_oracle(oracle, blocksize, randpfx_len)
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

struct Challenge16 {
    key: [u8; 16]
}

impl Challenge16 {
    fn new() -> Self {
        Challenge16 {
            key: rand::random()
        }
    }

    fn construct_commentstring(&self, userdata: &[u8]) -> Vec<u8> {
        let userdata_esc = userdata.iter().flat_map(|&b|
                                 match b {
                                     b';' => b"%3b".to_vec(),
                                     b'=' => b"%3d".to_vec(),
                                     _    => vec![b]
                                 });
        let mut result = b"comment1=cooking%20MCs;userdata=".to_vec();
        result.extend(userdata_esc);
        result.extend_from_slice(b";comment2=%20like%20a%20pound%20of%20bacon");
        result
    }

    fn construct_encrypted_commentstring(&self, userdata: &[u8]) -> Vec<u8> {
        aes128_cbc_encrypt(&self.construct_commentstring(userdata), &self.key,
                           &[0u8; 16])
    }

    fn is_admin(&self, encrypted_commentstring: &[u8]) -> bool {
        let dec = aes128_cbc_decrypt(encrypted_commentstring, &self.key,
                                     &[0u8; 16]);
        println!("Challenge 16: decryption = {}", escape_bytes(&dec));
        dec.windows(12).any(|w| w == b";admin=true;")
    }
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
    let size1 = oracle(&[]).len();
    let mut arg = Vec::new();
    loop {
        arg.push(0);
        let size2 = oracle(&arg).len();
        if size2 > size1 {
            blocksize = size2 - size1;
            break;
        }
    }

    assert_eq!(16, blocksize);

    let is_ecb = is_ecb(&mut *oracle);

    println!("Challenge 12: is_ecb is {}", is_ecb);
    assert!(is_ecb);

    let plaintext = crack_ecb_oracle(&mut *oracle, blocksize, 0);

    println!("Challenge 12:\n{}", String::from_utf8_lossy(&plaintext));
}

fn challenge13() {
    macro_rules! hashmap {
        ($( $key:expr => $val:expr ),* ) => {{
            let mut map = HashMap::new();
            $(map.insert($key.to_vec(), $val.to_vec());)*
            map
        }}
    }

    assert_eq!(
        hashmap!(b"foo" => b"bar", b"baz" => b"qux", b"zap" => b"zazzle"),
        cookie_parse(b"foo=bar&baz=qux&zap=zazzle")
    );

    assert_eq!(
        hashmap!(b"this" => b"that", b"such" => b""),
        cookie_parse(b"this=that&whatever&such=")
    );

    let p = profile_for(b"foo@bar.com");
    assert_eq!(&b"email=foo@bar.com&uid=10&role=user"[..], &p[..]);

    let key: [u8; 16] = rand::random();

    let encrypted_profile_for =
        |user| aes128_ecb_encrypt(&profile_for(user), &key);

    let encrypted_admin_cookie = forge_admin_cookie(&encrypted_profile_for);
    let plain_admin_cookie = aes128_ecb_decrypt(&encrypted_admin_cookie, &key);
    println!("Challenge 13: Admin cookie: '{}' (len={})",
            escape_bytes(&plain_admin_cookie), plain_admin_cookie.len());
    let parsed_admin_cookie = cookie_parse(&plain_admin_cookie);
    assert_eq!(parsed_admin_cookie.get(&b"role".to_vec()),
            Some(&b"admin".to_vec()));

    println!("Challenge 13: Success");
}

fn challenge14(b64: &Base64Codec) {
    let mut oracle = make_randpfx_oracle(b64);
    let blocksize = 16;
    let plaintext = crack_randpfx_oracle(&mut *oracle, blocksize);
    println!("Challenge 14:\n{}", String::from_utf8_lossy(&plaintext));
}

fn challenge15() {
    let mut test1 = b"ICE ICE BABY\x04\x04\x04\x04".to_vec();
    assert!(pkcs7_unpad_if_valid(&mut test1));
    assert_eq!(b"ICE ICE BABY".as_ref(), test1.as_slice());

    let mut test2 = b"ICE ICE BABY\x05\x05\x05\x05".to_vec();
    assert!(! pkcs7_unpad_if_valid(&mut test2));
    assert_eq!(b"ICE ICE BABY\x05\x05\x05\x05".as_ref(), test2.as_slice());

    let mut test3 = b"ICE ICE BABY\x01\x02\x03\x04".to_vec();
    assert!(! pkcs7_unpad_if_valid(&mut test3));
    assert_eq!(b"ICE ICE BABY\x01\x02\x03\x04".as_ref(), test3.as_slice());
}

fn challenge16() {
    let c = Challenge16::new();
    println!("Challenge 16: {}", &escape_bytes(
            &c.construct_commentstring(b"oh_hi")));
    println!("Challenge 16: {}", &escape_bytes(
            &c.construct_commentstring(b"oh;my")));
    assert!(
        ! c.is_admin(&c.construct_encrypted_commentstring(b";admin=true;")));

    let plain = b"aaaaaaaaaaaaaaaaKadminMtrueKaaaa";
    assert_eq!(32, plain.len());

    let mut enc = c.construct_encrypted_commentstring(plain);
    assert!(! c.is_admin(&enc));

    enc[32] ^= 0x70u8;
    enc[38] ^= 0x70u8;
    enc[43] ^= 0x70u8;

    assert!(c.is_admin(&enc));

    println!("Challenge 16: Success");
}

pub fn run(spec: &items::ItemsSpec) {
    let b64 = Base64Codec::new();
    ch!(spec, challenge9);
    ch!(spec, challenge10, &b64);
    ch!(spec, challenge11);
    ch!(spec, challenge12, &b64);
    ch!(spec, challenge13);
    ch!(spec, challenge14, &b64);
    ch!(spec, challenge15);
    ch!(spec, challenge16);
}
