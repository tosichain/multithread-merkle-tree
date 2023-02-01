use crate::back_merkle_tree::BackMerkleTree;
use crate::merkle_tree_proof::MerkleTreeProof;

use std::process;
use std::io::{BufReader, Read};
use std::fs;
use std::io;
use std::io::BufRead;
use sha3::Digest;
use std::fs::File;
use std::io::Write;

type AddressType = u64;
type HashType = Box<Vec<u8>>;
type HasherType = sha3::Keccak256;
type ProofType = MerkleTreeProof;

fn stringval(pre: String, strl: String, mut val: &mut String) -> bool {
    if pre.starts_with(&strl){
            let mut res = strl.clone();
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

fn print_hash(hash: &HashType, f: &mut File) {
    for b in hash.iter() {
        f.write_all(format!(" {:0>2}", b).as_bytes());
    }
    f.write_all(b"\n");
}

fn read_hash(f: File) -> Option<HashType> {
    let mut hex_hash: Vec<char> = Vec::with_capacity(HasherType::output_size()*2);

    let mut buffer = String::new();
    let mut reader = BufReader::with_capacity(hex_hash.capacity(), f);
    reader.read_to_string(&mut buffer);
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

fn error(fmt: String) {
    eprintln!("{}",fmt);
    process::exit(1);
}

fn get_word_hash(h: &mut HasherType, word: &mut Vec<u8>, log2_word_size: isize, hash: &mut HashType) {
    h.reset();
    h.update(word);
    *hash = Box::new(h.clone().finalize().to_vec());
}

fn get_leaf_hash_hasher(h: &mut HasherType, leaf_data: &mut Vec<u8>, log2_leaf_size: isize, log2_word_size: isize) -> HashType {
    assert!(log2_leaf_size >= log2_word_size);
    if log2_leaf_size > log2_word_size {
        let mut left: HashType = get_leaf_hash_hasher(h, leaf_data, log2_leaf_size - 1, log2_word_size);
        leaf_data.push(1 << (log2_leaf_size - 1));
        let right: HashType = get_leaf_hash_hasher(h, leaf_data, log2_leaf_size - 1, log2_word_size);
        h.reset();
        h.update(left.as_slice());
        h.update(right.as_slice());
        left = Box::new(h.clone().finalize().to_vec());
        return left;
    } else {
        let mut leaf: HashType = Default::default();
        get_word_hash(h, leaf_data, log2_word_size, &mut leaf);
        return leaf;
    }
}

fn get_leaf_hash(leaf_data: &mut Vec<u8>, log2_leaf_size: isize, log2_word_size: isize) -> HashType {
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

fn main(argc: isize, argv: &mut Vec<&mut String>) -> isize {
    let mut input_name: String = String::new();
    let mut log2_word_size: isize = 3;
    let mut log2_leaf_size: isize = 12;
    let mut log2_root_size: isize = 0;

    for i in 1..argc {
        if argv[i as usize].eq(&"--help") {
            help(argv[0]);
        } else if stringval(String::from("--input="), argv[i as usize].to_string(), &mut input_name) {
        } else if intval(&String::from("--log2-word-size="), argv[i as usize], &mut log2_word_size) {
        } else if intval(&String::from("--log2-leaf-size="), argv[i as usize], &mut log2_leaf_size) {
        } else if intval(&String::from("--log2-root-size="), argv[i as usize], &mut log2_root_size) {
        } else if intval(&String::from("--page-log2-size="), argv[i as usize], &mut log2_leaf_size) {
            println!("--page-log2-size is deprecated. ");
            println!("use --log2-leaf-size instead");
        } else if intval(&String::from("--tree-log2-size="), argv[i as usize], &mut log2_root_size) {
            println!("--tree-log2-size is deprecated. ");
            println!("use --log2-root-size instead");
        } else {
            error(format!("unrecognized option {}", argv[i as usize]));
        }
    }
    if log2_leaf_size < log2_word_size || log2_leaf_size >= 64 || log2_root_size >= 64 ||
        log2_leaf_size > log2_root_size {
        error(format!("invalid word size {} / invalid leaf size {} / root size {} combination", log2_word_size,
            log2_leaf_size, log2_root_size));
        return 1;
    }
    let mut input_file: Box<dyn BufRead> = Box::new(BufReader::new(io::stdin()));
    if !input_name.is_empty() {
        unsafe {
            if !fs::File::open(&input_name).is_ok() {
                error(format!("unable to open input file {}", &input_name));
                return 1;
            }
        
            match fs::File::open(&input_name) {
                Ok(input) => input_file = Box::new(BufReader::new(input)),
                Err(_)    => error(format!("error reading input")),
            
            }
        }
    }

    let leaf_size: u8 = (1u64 << log2_leaf_size) as u8;

    let mut leaf_buf: Vec<u8> = Vec::with_capacity(leaf_size as usize);

    let mut back_tree: BackMerkleTree = BackMerkleTree {
        m_log2_root_size: log2_root_size,
        m_log2_leaf_size: log2_leaf_size,
        m_leaf_count: log2_word_size as u64,
        m_max_leaves: Default::default(),
        m_context: Default::default(),
        m_pristine_hashes: Default::default(),
    };

    let max_leaves: u64 = 1u64 << (log2_root_size - log2_leaf_size);
    let mut leaf_count: u64 = 0;

    while true {

            let mut buffer: String = String::new();
            let mut reader = BufReader::with_capacity(1, fs::File::open(&input_name).unwrap());
            reader.read_to_string(&mut buffer);
            for c in buffer.chars() {
                leaf_buf.push(c.to_digit(10).unwrap() as u8);
            }

            if leaf_count >= max_leaves {
                error(format!("too many leaves for tree"));
            }

            let to = leaf_size as usize - leaf_buf.len() as usize;
            leaf_buf[0..to].fill(0);

            let leaf_hash = get_leaf_hash(&mut leaf_buf, log2_leaf_size, log2_word_size);

            back_tree.push_back(&leaf_hash);

            leaf_count += 1;
        }
        print!("{:#?}", back_tree.get_root_hash());
        return 0;
    }
