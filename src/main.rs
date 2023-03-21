#![feature(thread_id_value)]
mod back_merkle_tree;
mod complete_merkle_tree;
mod full_merkle_tree;
mod machine_merkle_tree;
mod merkle_tree_hash;
mod merkle_tree_proof;
mod pristine_merkle_tree;

use std::fs::*;
use std::io::BufRead;
use std::io::*;
use std::thread::ThreadId;

use crate::back_merkle_tree::*;
use crate::complete_merkle_tree::*;
use crate::full_merkle_tree::*;
use crate::machine_merkle_tree::MachineMerkleTree;
use crate::merkle_tree_hash::*;
use std::sync::{Arc, Mutex};
use std::thread;

type HashType = Box<Vec<u8>>;
type HasherType = sha3::Keccak256;

fn main() {
    use std::time::Instant;
    let now = Instant::now();

    let log2_word_size: isize = 3;
    let log2_leaf_size: isize = 12;
    let log2_root_size: isize = 30;

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

    let mut input_name: String = String::from("test-merkle-tree-hash");

    let mut input_file: Box<dyn BufRead> = Box::new(BufReader::new(stdin()));
    if !input_name.is_empty() {
        if !File::open(&input_name).is_ok() {
            error(format!("unable to open input file {}", &input_name));
            panic!();
        }

        match File::open(&input_name) {
            Ok(input) => input_file = Box::new(BufReader::new(input)),
            Err(_) => error(format!("error reading input")),
        }
    }

    let leaf_size = 1u64 << log2_leaf_size;

    let back_tree: Arc<Mutex<BackMerkleTree>> = Arc::new(Mutex::new(Default::default()));
    {
        back_tree
            .lock()
            .unwrap()
            .back_merkle_tree(log2_root_size, log2_leaf_size, log2_word_size);
    }

    let mut buffer_value: Vec<u8> = Vec::new();
    let mut reader = BufReader::new(File::open(&input_name).unwrap());

    reader.read_to_end(&mut buffer_value).unwrap();
    let buffer: Arc<Vec<u8>> = Arc::new(buffer_value);

    let back_tree = Arc::clone(&back_tree);
    let mut handles = vec![];
    let queued_hashes :Arc<Mutex<Vec<(u64 , Box<Vec<u8>>)>>> = Arc::new(Mutex::new(Default::default()));
    let total_threads = 17;
    for thread_index in 0..total_threads {
        let buffer = Arc::clone(&buffer);
        //let back_tree = Arc::clone(&back_tree);
        let queued_hashes = Arc::clone(&queued_hashes);

        let handle = thread::spawn(move || {
            let buffer_len = buffer.len() as u64;
            let start = leaf_size * thread_index;

            for i in (start..buffer_len).step_by((leaf_size * total_threads) as usize) {
                let mut leaf_slice: Vec<u8> = Vec::new();
                let buffer = Arc::clone(&buffer);

                if (i + leaf_size) < buffer_len {
                    leaf_slice = buffer[i as usize..(i + leaf_size) as usize].to_vec();
                } else if i < buffer_len {
                    leaf_slice = buffer[i as usize..buffer_len as usize].to_vec();
                    while leaf_size as usize - leaf_slice.len() as usize > 0 {
                        leaf_slice.push(0);
                    }
                }
                let leaf_hash = get_leaf_hash(leaf_slice.as_ptr(), log2_leaf_size, log2_word_size);

                let mut queued_hashes = queued_hashes.lock().unwrap();
                queued_hashes.push((i, leaf_hash));
                std::mem::drop(buffer);
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

    println!("Back Tree Root Hash:");

    print_hash(&back_tree.get_root_hash());
    std::mem::drop(back_tree);
    let elapsed = now.elapsed();

    println!("Elapsed: {:.2?}", elapsed);
}
