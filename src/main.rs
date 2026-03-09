mod constant;
mod prime_number;

fn main() {
    let p = prime_number::generate_prime(1024);
    let q = prime_number::generate_prime(1024);
    let n = &p * &q;
    println!("p: {p}");
    println!("q: {q}");
    println!("n: {n}");
}
