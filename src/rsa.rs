use std::{
    fmt::Debug,
    io::{BufRead, Write},
};

use num_bigint::{BigInt, BigUint};
use num_integer::{ExtendedGcd, Integer};
use num_traits::{One, Signed};

use crate::{constant::e, prime_number, rsa};

#[derive(Debug)]
pub struct PrivateKey {
    pub n: BigUint,
    pub d: BigUint,
}

#[derive(Debug)]
pub struct PublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

#[derive(Debug)]
pub struct KeyPair {
    private: PrivateKey,
    public: PublicKey,
}

impl KeyPair {
    pub fn new(n: BigUint, e: BigUint, d: BigUint) -> Self {
        let private = PrivateKey { n: n.clone(), d };
        let public = PublicKey { n: n.clone(), e };
        Self { private, public }
    }

    pub fn private(self: &Self) -> &PrivateKey {
        return &self.private;
    }

    pub fn public(self: &Self) -> &PublicKey {
        return &self.public;
    }
}

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        (self.private.n == other.private.n && self.private.d == other.private.d)
            && (self.public.n == other.public.n && self.public.e == other.public.e)
    }
}

fn mod_inverse(e: &BigUint, phi: &BigUint) -> Option<BigUint> {
    let e_int: BigInt = BigInt::from(e.clone());
    let phi_int: BigInt = BigInt::from(phi.clone());

    let ExtendedGcd { gcd, x, .. } = e_int.extended_gcd(&phi_int);

    if gcd != BigInt::one() {
        return None;
    }

    let mut d = x % &phi_int;
    if d.is_negative() {
        d += &phi_int;
    }

    d.to_biguint()
}

pub fn keygen(bits: u64) -> KeyPair {
    loop {
        let p = prime_number::generate_prime(bits);
        let q = prime_number::generate_prime(bits);
        let n = &p * &q;
        let phi = (&p - BigUint::one()) * (&q - BigUint::one());

        let s = e().gcd(&phi);
        if s != BigUint::one() {
            continue;
        }

        if let Some(d) = mod_inverse(&e(), &phi) {
            let key: KeyPair = KeyPair::new(n, e(), d);
            break key;
        }
    }
}

pub fn encrypt(buf: &[u8], key: &PublicKey) -> BigUint {
    let m = BigUint::from_bytes_be(buf);
    m.modpow(&key.e, &key.n)
}

pub fn decrypt(buf: &BigUint, key: &PrivateKey) -> Vec<u8> {
    let m = buf.modpow(&key.d, &key.n);
    m.to_bytes_be()
}

pub fn process_encrypt(
    input: &mut impl BufRead,
    output: &mut impl Write,
    key: &PublicKey,
) -> std::io::Result<()> {
    let k: usize = ((key.n.bits() + 7) / 8) as usize;
    let max_chunk = k - 2; // Reserve 1 byte for the 0x01 padding marker
    let mut buf: Vec<u8> = vec![0u8; max_chunk];

    loop {
        buf.fill(0u8);
        let n: usize = input.read(&mut buf)?;
        if n == 0 {
            break;
        }

        // Simple Padding: Prepend 0x01 to preserve leading zeroes
        let mut padded_plain = vec![0x01];
        padded_plain.extend_from_slice(&buf[..n]);

        let c: BigUint = rsa::encrypt(&padded_plain, key);
        let mut cipher: Vec<u8> = c.to_bytes_be();
        if cipher.len() < k {
            let mut padded: Vec<u8> = vec![0u8; k - cipher.len()];
            padded.extend(cipher);
            cipher = padded;
        }
        output.write_all(&cipher)?;
    }
    output.flush()?;
    Ok(())
}

pub fn process_decrypt(
    input: &mut impl BufRead,
    output: &mut impl Write,
    key: &PrivateKey,
) -> std::io::Result<()> {
    let k: usize = ((key.n.bits() + 7) / 8) as usize;
    let mut buf: Vec<u8> = vec![0u8; k];
    loop {
        match input.read_exact(&mut buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let cipher: BigUint = BigUint::from_bytes_be(&buf);
        let mut msg: Vec<u8> = rsa::decrypt(&cipher, key);

        // Remove the 0x01 padding marker
        if !msg.is_empty() && msg[0] == 0x01 {
            msg.remove(0);
        } else if !msg.is_empty() {
            // Fallback if decryption succeeded but marker is wrong (corrupted)
            msg.remove(0);
        }

        output.write_all(&msg)?;
    }
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::{BufReader, Cursor};

    use super::*;

    #[test]
    fn test_core_encrypt_decrypt() {
        let key = keygen(256);
        let msg = b"hello rsa";
        let cipher = encrypt(msg, key.public());
        let decrypted = decrypt(&cipher, key.private());
        assert_eq!(msg, decrypted.as_slice());
    }

    #[test]
    pub fn test_process_encrypt_decrypt() {
        let key = keygen(512);

        let original_msg =
            b"This is a secret message to test the process_encrypt and process_decrypt functions.";

        let mut input = BufReader::new(Cursor::new(original_msg));
        let mut chiper_msg = Vec::new();
        process_encrypt(&mut input, &mut chiper_msg, &key.public()).unwrap();

        let mut chiper_input = BufReader::new(Cursor::new(&mut chiper_msg));
        let mut output = Vec::new();
        process_decrypt(&mut chiper_input, &mut output, key.private()).unwrap();

        assert_eq!(original_msg, output.as_slice());
    }
}
