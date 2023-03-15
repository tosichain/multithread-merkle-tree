use std::process;
use std::io::{BufReader, Read};
use sha3::Digest;
use std::fs::File;

type HashType = Box<Vec<u8>>;
type HasherType = sha3::Keccak256;

fn stringval(pre: String, strl: String, val: &mut String) -> bool {
    if pre.starts_with(&strl){
            let res = strl.clone();
            *val = res[pre.len()..strl.len()].to_string();
        return true;
    }
    return false;
}

fn intval(pre: &String, strl: &mut String, val: &mut isize) -> bool{
    if pre.starts_with(&strl.to_string()) {
        let mut res = strl.clone();
        *strl = res[pre.len()..strl.len()].to_string();
        let end: isize = 0;
        let parsed = sscanf::sscanf!(strl, "{str}{isize}");
        return matches!(parsed, Err(sscanf::Error::MatchFailed));
    }
    return false;
}

pub fn print_hash(hash: &HashType) {
    for b in hash.iter() {
        print!("{}", hex::encode(vec![*b]));
    }
    println!()
}

fn read_hash(f: File) -> Option<HashType> {
    let mut hex_hash: Vec<char> = Vec::with_capacity(HasherType::output_size()*2);

    let mut buffer = String::new();
    let mut reader = BufReader::with_capacity(hex_hash.capacity(), f);
    reader.read_to_string(&mut buffer).unwrap();
    if  buffer.len() != hex_hash.capacity() {
        return None;
    }
    hex_hash = buffer.chars().collect();
    
    let mut h: HashType = Default::default();
    for  i in 0..HasherType::output_size() {
        let hex_c: [char; 3] = [hex_hash[2 * i], hex_hash[2 * i + 1], '\0'];
        let c: u8 = 0;

        for i in hex_c.iter() {
            if !i.is_ascii_hexdigit() {
                return None;
            }
        }
        h[i] = c;
    }
    return Some(h);
}

pub fn error(fmt: String) {
    eprintln!("{}",fmt);
    process::exit(1);
}

fn get_word_hash(h: &mut HasherType, word: *mut u8, hash: &mut HashType) {
    h.reset();

    unsafe {
        h.update(std::slice::from_raw_parts(word, 8));

    }
    *hash = Box::new(h.clone().finalize().to_vec());

}

fn get_leaf_hash_hasher(h: &mut HasherType, leaf_data: *mut u8, log2_leaf_size: isize, log2_word_size: isize) -> HashType {
    assert!(log2_leaf_size >= log2_word_size);
    if log2_leaf_size > log2_word_size {
        let mut left: HashType = get_leaf_hash_hasher(h, leaf_data, log2_leaf_size - 1, log2_word_size);
        unsafe {
            let right: HashType = get_leaf_hash_hasher(h, leaf_data.add(1 << (log2_leaf_size - 1)),log2_leaf_size - 1, log2_word_size);
            h.reset();
            h.update(left.as_slice());
            h.update(right.as_slice());
            left = Box::new(h.clone().finalize().to_vec());
        }
        return left;
    } else {
        let mut leaf: HashType = Default::default();
        get_word_hash(h,leaf_data, &mut leaf);
        //print_hash(&leaf);

        return leaf;
    }
    
}

pub fn get_leaf_hash(leaf_data: *mut u8, log2_leaf_size: isize, log2_word_size: isize) -> HashType {
    let mut h: HasherType = Default::default(); 
    return get_leaf_hash_hasher(&mut h, leaf_data, log2_leaf_size, log2_word_size);
}

fn help(name: &mut str) {
    eprintln!("(Usage:

  {:#?} --log2-root-size=<integer> [options]

Computes the Merkle tree root hash of 2^log2_root_size bytes read from
a file. If the file contains fewer than 2^log2_root_size bytes, it is
ostensibly padded with zeros to 2^log2_root_size bytes.

Each node hash corresponding to a data range with 2^log2_node_size bytes
is the hash of the concatenation of the node hashes of its two subranges
with 2^(log2_node_size-1) bytes.

The node hash corresponding to word with 2^log2_word_size bytes is simply
the hash of the data in the range.

The Merkle tree root hash is simply the node hash corresponding to the
entire 2^log2_root_size range.

The hash function used is Keccak-256.

Options:

  --input=<filename>                    default: reads from standard input
  Gives the input filename.

  --log2-word-size=<integer>            default: 3
  (> 0 and <= 64)
  Number of bytes subintended by each word, i.e., the number of bytes in the
  input data from which each hash is computed.

  --log2-leaf-size=<integer>            default: 12
  (> 0 and <= log2_root_size)
  The granularity in which bytes are read from the input file.

  --help
  Prints this message and returns.
)",
        name);
    process::exit(0);
}