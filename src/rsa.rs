use std::fmt::Debug;

use num_bigint::{BigInt, BigUint};
use num_integer::{ExtendedGcd, Integer};
use num_traits::{One, Signed};

use crate::{constant::e, prime_number};

#[derive(Debug)]
pub struct KeyPair {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
}

impl PartialEq for KeyPair {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.e == other.e && self.d == other.d
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
            let key = KeyPair { n, d, e: e() };
            break key;
        }
    }
}
