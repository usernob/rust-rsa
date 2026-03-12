use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero};
use rand::{RngExt, rng};

use crate::constant::{SMALL_PRIMES, e};

fn random_bits(bits: u64) -> BigUint {
    let mut rng = rng();

    let bytes: u64 = bits.div_ceil(8);
    let mut buf: Vec<u8> = vec![0u8; bytes as usize];
    rng.fill(&mut buf[..]);

    let mut n: BigUint = BigUint::from_bytes_be(&buf);

    // force highest bit
    n.set_bit(bits - 1, true);

    // force odd
    n.set_bit(0, true);

    return n;
}

fn random_bits_range(low: &BigUint, high: &BigUint) -> BigUint {
    assert!(low < high);

    let range: BigUint = high - low;
    loop {
        let candidate: BigUint = random_bits(range.bits());

        if candidate < range {
            return candidate + low;
        }
    }
}

fn trial_division(n: &BigUint) -> bool {
    for p in SMALL_PRIMES {
        if &BigUint::from(p) == n {
            return true;
        }

        if n % p == BigUint::zero() {
            return false;
        }
    }
    return true;
}

/// expect odd value only
/// ref: https://cp-algorithms.com/algebra/primality_tests.html#miller-rabin-primality-test
/// with slightly adjustment
fn miller_rabin(n: &BigUint, iter: u32) -> bool {
    if n <= &BigUint::from(4u8) {
        return *n == BigUint::from(2u8) || *n == BigUint::from(3u8);
    }

    let one: BigUint = BigUint::one();
    let two: BigUint = BigUint::from(2u8);

    let mut s: i32 = 0;
    let mut d: BigUint = n - &one;

    // check if d is odd
    while &d % 2u8 == BigUint::zero() {
        d >>= 1;
        s += 1;
    }

    'outer: for _ in 0..iter {
        let a: BigUint = random_bits_range(&two, &(n - &two));

        let mut x: BigUint = a.modpow(&d, n);

        if x == one || x == n - &one {
            continue;
        }

        for _ in 0..s - 1 {
            x = x.modpow(&two, n);

            if x == n - &one {
                continue 'outer;
            }
        }

        return false;
    }

    true
}

pub fn generate_prime(bits: u64) -> BigUint {
    let mut candidate: BigUint = random_bits(bits);
    loop {
        candidate += BigUint::from(2u8);
        if !trial_division(&candidate) {
            continue;
        }

        if !miller_rabin(&candidate, 4) {
            continue;
        }

        let p_minus_1 = &candidate - BigUint::one();
        if p_minus_1.gcd(&e()) != BigUint::one() {
            continue;
        }
        return candidate;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn miller_rabin_true() {
        let a = BigUint::from(SMALL_PRIMES[999]);
        let b = BigUint::from(SMALL_PRIMES[100]);
        assert_eq!(miller_rabin(&a, 40), true);
        assert_eq!(miller_rabin(&b, 40), true);
    }

    #[test]
    fn miller_rabin_false() {
        let a = BigUint::from(10u8);
        let b = BigUint::from(2048u32);
        assert_eq!(miller_rabin(&a, 40), false);
        assert_eq!(miller_rabin(&b, 40), false);
    }
}
