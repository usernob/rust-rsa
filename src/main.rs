mod constant;
mod prime_number;
mod rsa;
mod file;

fn main() {
    let keypair = rsa::keygen::generate(1024);
    println!("{keypair:#?}");
}
