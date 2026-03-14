use std::fmt::Debug;

use num_bigint::{BigInt, BigUint};
use num_integer::{ExtendedGcd, Integer};
use num_traits::{One, Signed};

use crate::{
    constant::e,
    file, prime_number, rsa,
};

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
    input_path: Option<&str>,
    output_path: Option<&str>,
    key: &PublicKey,
) -> std::io::Result<()> {
    let mut input = file::open_input(input_path)?;
    let mut output = file::open_output(output_path)?;

    let k: usize = ((key.n.bits() + 7) / 8) as usize;
    let mut buf: Vec<u8> = vec![0u8; k - 1];

    loop {
        buf.fill(0u8);
        let n: usize = input.read(&mut buf)?;
        if n == 0 {
            break;
        }
        let c: BigUint = rsa::encrypt(&buf[..n], key);
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
    input_path: Option<&str>,
    output_path: Option<&str>,
    key: &PrivateKey,
) -> std::io::Result<()> {
    let mut input = file::open_input(input_path)?;
    let mut output = file::open_output(output_path)?;

    let k: usize = ((key.n.bits() + 7) / 8) as usize;
    let mut buf: Vec<u8> = vec![0u8; k];
    loop {
        match input.read_exact(&mut buf) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
        let cipher: BigUint = BigUint::from_bytes_be(&buf);
        let msg: Vec<u8> = rsa::decrypt(&cipher, key);
        output.write_all(&msg)?;
    }
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read};

    use super::*;

    fn file_eq(a: &str, b: &str) -> std::io::Result<bool> {
        let mut f1 = File::open(a)?;
        let mut f2 = File::open(b)?;

        let mut buf1 = Vec::new();
        let mut buf2 = Vec::new();

        f1.read_to_end(&mut buf1)?;
        f2.read_to_end(&mut buf2)?;

        Ok(buf1 == buf2)
    }

    #[test]
    pub fn test_encrypt_decrypt() {
        let pub_key = file::read_public_key("/tmp/test.pub").unwrap();
        let priv_key = file::read_private_key("/tmp/test").unwrap();
        rsa::process_encrypt(Some("lorem.txt"), Some("/tmp/msg.enc"), &pub_key).unwrap();
        rsa::process_decrypt(Some("/tmp/msg.enc"), Some("/tmp/msg.txt"), &priv_key).unwrap();
        let same = file_eq("lorem.txt", "/tmp/msg.txt").unwrap();
        assert!(same, "files are different");
    }
}
