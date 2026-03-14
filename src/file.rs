use std::{
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Read, Write},
};

use num_bigint::BigUint;

use crate::{
    constant::{CHUNK_WITDH, PRIVATE_HEADER, PUBLIC_HEADER, SEPARATOR},
    rsa,
};

fn wrap_write<W: Write>(writer: &mut W, s: &str) -> io::Result<()> {
    let mut tmp = s.as_bytes().chunks(CHUNK_WITDH);
    while let Some(chunk) = tmp.next() {
        writer.write_all(chunk)?;
        writer.write_all(b"\n")?;
    }
    Ok(())
}

fn write(path: &str, header: &str, a: &BigUint, b: &BigUint) -> io::Result<()> {
    let file: File = File::create(path)?;
    let mut writer: BufWriter<File> = BufWriter::new(file);

    // convert to hexadecimal
    let a_str: String = a.to_str_radix(16);
    let b_str: String = b.to_str_radix(16);

    writer.write_all(header.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.write_all(SEPARATOR.as_bytes())?;
    writer.write_all(b"\n")?;

    wrap_write(&mut writer, &a_str.to_uppercase())?;
    writer.write_all(SEPARATOR.as_bytes())?;
    writer.write_all(b"\n")?;

    wrap_write(&mut writer, &b_str.to_uppercase())?;
    writer.write_all(SEPARATOR.as_bytes())?;
    writer.flush()?;
    Ok(())
}

fn expect_line<I>(lines: &mut I, expected: &str) -> io::Result<()>
where
    I: Iterator<Item = io::Result<String>>,
{
    let line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "UnexpectedEof"))??;

    if line != expected {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid format"));
    }

    Ok(())
}

fn read_biguint<I>(lines: &mut I) -> io::Result<BigUint>
where
    I: Iterator<Item = io::Result<String>>,
{
    let mut buf: String = String::with_capacity(1024);
    for line in lines {
        let line = line?;
        if &line == SEPARATOR {
            return BigUint::parse_bytes(buf.as_bytes(), 16)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid BigUint"));
        }
        buf.push_str(&line);
    }
    Err(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "Missing separator",
    ))
}

fn read(path: &str, header: &str) -> io::Result<(BigUint, BigUint)> {
    let file: File = File::open(path)?;
    let reader: BufReader<File> = BufReader::new(file);
    let mut lines = reader.lines();

    expect_line(&mut lines, header)?;
    expect_line(&mut lines, SEPARATOR)?;
    let a: BigUint = read_biguint(&mut lines)?;
    let b: BigUint = read_biguint(&mut lines)?;

    Ok((a, b))
}

pub fn save_key(filename: &str, key: &rsa::KeyPair) -> io::Result<()> {
    let public_path: String = format!("{}.pub", filename);
    let private_path: &str = filename;
    let private_key: &rsa::PrivateKey = key.private();
    let public_key: &rsa::PublicKey = key.public();
    write(&public_path, PUBLIC_HEADER, &public_key.n, &public_key.e)?;
    write(
        &private_path,
        PRIVATE_HEADER,
        &private_key.n,
        &private_key.d,
    )?;
    Ok(())
}

pub fn read_public_key(filename: &str) -> io::Result<rsa::PublicKey> {
    let (n, e) = read(filename, PUBLIC_HEADER)?;
    Ok(rsa::PublicKey { n, e })
}

pub fn read_private_key(filename: &str) -> io::Result<rsa::PrivateKey> {
    let (n, d) = read(filename, PRIVATE_HEADER)?;
    Ok(rsa::PrivateKey { n, d })
}

pub fn read_key(filename: &str) -> io::Result<rsa::KeyPair> {
    let pub_path = format!("{}.pub", filename);
    let public: rsa::PublicKey = read_public_key(&pub_path)?;
    let private: rsa::PrivateKey = read_private_key(filename)?;
    Ok(rsa::KeyPair::new(public.n, public.e, private.d))
}

pub fn open_input(path: Option<&str>) -> io::Result<Box<dyn Read>> {
    match path {
        Some(p) => Ok(Box::new(BufReader::new(File::open(p)?))),
        None => Ok(Box::new(BufReader::new(io::stdin()))),
    }
}

pub fn open_output(path: Option<&str>) -> io::Result<Box<dyn Write>> {
    match path {
        Some(p) => Ok(Box::new(BufWriter::new(File::create(p)?))),
        None => Ok(Box::new(BufWriter::new(io::stdout()))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn save_read_key() {
        let generated_key = rsa::keygen(1024);
        save_key("/tmp/test", &generated_key).unwrap();
        let loaded_key = read_key("/tmp/test").unwrap();
        assert_eq!(generated_key, loaded_key);
    }
}
