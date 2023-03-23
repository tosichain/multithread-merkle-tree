mod back_merkle_tree;
mod complete_merkle_tree;
mod full_merkle_tree;
mod machine_merkle_tree;
mod merkle_tree_hash;
mod merkle_tree_proof;
mod pristine_merkle_tree;

use crate::back_merkle_tree::*;
use crate::complete_merkle_tree::*;
use crate::full_merkle_tree::*;
use crate::machine_merkle_tree::MachineMerkleTree;
use crate::merkle_tree_hash::*;
use clap::{value_parser, Arg, Command};
use fmmap::sync::MmapFile;
use fmmap::MmapFileExt;
use std::sync::{Arc, Mutex};
use std::thread;

type HashType = Box<Vec<u8>>;
type HasherType = sha3::Keccak256;

fn main() {
    let matches = Command::new("prog")
        .arg(
            Arg::new("input")
                .long("input")
                .required(true)
                .help("input file"),
        )
        .arg(
            Arg::new("log2-word-size")
                .long("log2-word-size")
                .value_parser(value_parser!(isize))
                .required(true)
                .help("value for log2-word-size"),
        )
        .arg(
            Arg::new("log2-leaf-size")
                .long("log2-leaf-size")
                .value_parser(value_parser!(isize))
                .required(true)
                .help("value for log2-leaf-size"),
        )
        .arg(
            Arg::new("log2-root-size")
                .long("log2-root-size")
                .value_parser(value_parser!(isize))
                .required(true)
                .help("value for log2-root-size"),
        )
        .get_matches();

    use std::time::Instant;
    let now = Instant::now();

    let log2_word_size: isize = matches.get_one::<isize>("log2-word-size").unwrap().clone();
    let log2_leaf_size: isize = matches.get_one::<isize>("log2-leaf-size").unwrap().clone();
    let log2_root_size: isize = matches.get_one::<isize>("log2-root-size").unwrap().clone();

    if log2_leaf_size < log2_word_size
        || log2_leaf_size >= 64
        || log2_root_size >= 64
        || log2_leaf_size > log2_root_size
    {
        error(format!(
            "invalid word size {} / invalid leaf size {} / root size {} combination",
            log2_word_size, log2_leaf_size, log2_root_size
        ));
        panic!();
    }

    let mut input_name: String = matches.get_one::<String>("input").unwrap().clone();
    let mut file = Arc::new(MmapFile::open(input_name.clone()).unwrap());
    let leaf_size = 1u64 << log2_leaf_size;

    let back_tree: Arc<Mutex<BackMerkleTree>> = Arc::new(Mutex::new(Default::default()));
    {
        back_tree
            .lock()
            .unwrap()
            .back_merkle_tree(log2_root_size, log2_leaf_size, log2_word_size);
    }

    let back_tree = Arc::clone(&back_tree);
    let mut handles = vec![];
    let queued_hashes: Arc<Mutex<Vec<(u64, Box<Vec<u8>>)>>> =
        Arc::new(Mutex::new(Default::default()));
    for thread_index in 0..thread::available_parallelism().unwrap().get() as u64 {
        let file = Arc::clone(&file);
        let queued_hashes = Arc::clone(&queued_hashes);
        let back_tree = Arc::clone(&back_tree);
        let handle = thread::spawn(move || {
            let buffer_len = file.len() as u64;
            let start = leaf_size * thread_index;
            for i in (start..buffer_len).step_by(
                (leaf_size * thread::available_parallelism().unwrap().get() as u64) as usize,
            ) {
                let mut leaf_slice: Vec<u8> = Vec::new();
                let file = Arc::clone(&file);
                if (i + leaf_size) < buffer_len {
                    leaf_slice = file.bytes(i as usize, leaf_size as usize).unwrap().to_vec();
                } else if i < buffer_len {
                    leaf_slice = file
                        .bytes(i as usize, (buffer_len - i) as usize)
                        .unwrap()
                        .to_vec();
                    while leaf_size as usize - leaf_slice.len() as usize > 0 {
                        leaf_slice.push(0);
                    }
                }
                let mut leaf_hash: Box<Vec<u8>>;
                if leaf_slice.to_vec().into_iter().all(|b| b == 0) {
                    let back_tree = back_tree.lock().unwrap();

                    leaf_hash = back_tree.m_pristine_hashes.get_hash(log2_leaf_size).clone();
                    std::mem::drop(back_tree);
                } else {
                    leaf_hash = get_leaf_hash(leaf_slice.as_ptr(), log2_leaf_size, log2_word_size);
                }

                let mut queued_hashes = queued_hashes.lock().unwrap();
                queued_hashes.push((i, leaf_hash));
                std::mem::drop(queued_hashes);
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    let mut queued_hashes = queued_hashes.lock().unwrap();
    let mut back_tree = back_tree.lock().unwrap();

    queued_hashes.sort();
    for (_, value) in &*queued_hashes {
        back_tree.push_back(value.clone());
    }
    std::mem::drop(queued_hashes);
    print_hash(&back_tree.get_root_hash());
    std::mem::drop(back_tree);
}
