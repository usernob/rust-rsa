# rust-rsa

A small command-line tool implementing a **basic RSA encryption/decryption workflow** written in Rust.

The goal of this project is educational: demonstrating how RSA works internally, including:

* RSA key generation
* block-based encryption
* streaming file processing
* binary ciphertext format

> [!WARNING]
> This implementation is **not meant for real-world security**. It does **not implement modern padding schemes such as OAEP or PSS** and should only be used for learning purposes.

---

## Build

Requirements:

* Rust toolchain (install using `rustup`)

Clone the repository:

```bash
git clone <repo-url>
cd rust-rsa
```

Build the project:

```bash
cargo build --release
```

The compiled binary will be located at:

```text
target/release/rust-rsa
```

You can optionally install it globally:

```bash
cargo install --path .
```

---

## Command Overview

```text
rust-rsa keygen
rust-rsa encrypt
rust-rsa decrypt
```

---

## Key Generation

Generate a new RSA keypair.

```bash
rust-rsa keygen -o mykey
```

Output files:

```text
mykey.pub
mykey
```

Default key size:

```text
2048 bits
```

You can specify a different key size:

```bash
rust-rsa keygen -o mykey -b 4096
```

---

## Encryption

Encrypt a file using a **public key**.

```bash
rust-rsa encrypt message.txt -k mykey.pub -o message.enc
```

Explanation:

```text
message.txt   plaintext input
mykey.pub     public key
message.enc   encrypted output
```

---

## Decryption

Decrypt a ciphertext using the **private key**.

```bash
rust-rsa decrypt message.enc -k mykey -o message.txt
```

---

## Using Pipes (stdin / stdout)

The program supports UNIX pipes.

Encrypt:

```bash
cat message.txt | rust-rsa encrypt -k mykey.pub > message.enc
```

Decrypt:

```bash
cat message.enc | rust-rsa decrypt -k mykey > message.txt
```

---

## Ciphertext File Format

Ciphertext is stored as a **binary stream of fixed-size RSA blocks**.

Each ciphertext block size:

```text
k = ceil(bits(n) / 8)
```

Example block sizes:

| RSA Key Size | Block Size (k) |
| ------------ | -------------- |
| 1024 bit     | 128 bytes      |
| 2048 bit     | 256 bytes      |
| 4096 bit     | 512 bytes      |

Ciphertext file layout:

```text
[cipher block 1 : k bytes]
[cipher block 2 : k bytes]
[cipher block 3 : k bytes]
...
```

Because ciphertext blocks always have a fixed size, decryption simply reads `k` bytes repeatedly.

---

## How Encryption Works

Steps performed by the program:

1. Read plaintext stream
2. Split into blocks of size:

```text
k - 1 bytes
```

3. Convert each block into a big integer
4. Perform the RSA operation:

```text
c = m^e mod n
```

5. Convert the result to exactly `k` bytes
6. Write ciphertext block

Flow:

```text
plaintext
↓
split into blocks
↓
BigUint
↓
m^e mod n
↓
fixed-size ciphertext block
↓
output
```

---

## How Decryption Works

Steps:

1. Read `k` bytes
2. Convert to a big integer
3. Perform RSA operation:

```text
m = c^d mod n
```

4. Convert result back to bytes
5. Write plaintext block

Flow:

```text
ciphertext block
↓
BigUint
↓
c^d mod n
↓
plaintext block
↓
output
```

---

## RSA Key Structure

RSA uses two keys.

Public key:

```text
(n, e)
```

Private key:

```text
(n, d)
```

Where:

* `n = p × q`
* `e` = public exponent (commonly `65537`)
* `d` = modular inverse of `e` modulo `φ(n)`

Encryption:

```text
c = m^e mod n
```

Decryption:

```text
m = c^d mod n
```

---

## Limitations

This implementation intentionally keeps RSA simple.

Missing features compared to production cryptographic systems:

* No OAEP padding
* No ciphertext integrity verification
* No authenticated encryption
* No hybrid encryption (RSA + AES)

Real-world systems typically use:

```text
RSA-OAEP
Hybrid encryption (RSA + AES)
Digital signatures (RSA-PSS)
```

---

## Example Workflow

Generate a keypair:

```bash
rust-rsa keygen -o testkey
```

Encrypt a file:

```bash
rust-rsa encrypt file.txt -k testkey.pub -o file.enc
```

Decrypt the file:

```bash
rust-rsa decrypt file.enc -k testkey -o file.txt
```

---


## Purpose of the Project

This project is designed to demonstrate:

* implementing RSA from scratch
* big integer arithmetic
* streaming encryption
* CLI application design
* binary file formats

It is intended purely for **learning and experimentation**.
