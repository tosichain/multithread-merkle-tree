mod back_merkle_tree;
mod complete_merkle_tree;
mod full_merkle_tree;
mod machine_merkle_tree;
mod merkle_tree_hash;
mod merkle_tree_proof;
mod pristine_merkle_tree;

use std::io::BufRead;
use std::io::*;
use std::fs::*;

use crate::complete_merkle_tree::*;
use crate::machine_merkle_tree::MachineMerkleTree;
use crate::merkle_tree_hash::*;
use crate::back_merkle_tree::*;
use crate::full_merkle_tree::*;
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

    if log2_leaf_size < log2_word_size || log2_leaf_size >= 64 || log2_root_size >= 64 ||
        log2_leaf_size > log2_root_size {
        error(format!("invalid word size {} / invalid leaf size {} / root size {} combination", log2_word_size,
            log2_leaf_size, log2_root_size));
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
                Err(_)    => error(format!("error reading input")),
            
            }
    }

    let leaf_size = 1u64 << log2_leaf_size;
    let back_tree: Arc<Mutex<BackMerkleTree>> = Arc::new(Mutex::new(Default::default()));
    {back_tree.lock().unwrap().back_merkle_tree(log2_root_size, log2_leaf_size, log2_word_size);}

    let complete_tree: Arc<Mutex<CompleteMerkleTree>> = Arc::new(Mutex::new(Default::default()));
    {complete_tree.lock().unwrap().complete_merkle_tree(log2_root_size, log2_leaf_size, log2_word_size);}

    let machine_merkle_tree: Arc<Mutex<MachineMerkleTree>> = Arc::new(Mutex::new(Default::default()));
    {machine_merkle_tree.lock().unwrap().machine_merkle_tree_initialization();}

    let leaf_hashes: Arc<Mutex<Vec<HashType>>> = Arc::new(Mutex::new(Vec::new()));
    {machine_merkle_tree.lock().unwrap().begin_update();}

    let leaf_count: Arc<Mutex<u64>> = Arc::new(Mutex::new(0));
    let h: Arc<Mutex<HasherType>> = Arc::new(Mutex::new(Default::default()));
    let buffer: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let mut reader = BufReader::new(File::open(&input_name).unwrap());

    reader.read_to_end(&mut buffer.lock().unwrap()).unwrap();
        let back_tree = Arc::clone(&back_tree);
        let complete_tree = Arc::clone(&complete_tree);
        let h = Arc::clone(&h);
        let mut handles = vec![];
        let mut loop_to = 0;
        let mut iterations: usize;

        for index in 0..4 {
            let machine_merkle_tree = Arc::clone(&machine_merkle_tree);
            let buffer = Arc::clone(&buffer);
            let leaf_hashes = Arc::clone(&leaf_hashes);
            let complete_tree = Arc::clone(&complete_tree);
            let back_tree = Arc::clone(&back_tree);
            let buffer_ = buffer.lock().unwrap();

            let buffer_len = buffer_.len();
            let mut extra = 0;
            if index == 3 {
                extra = 1;
                //loop_to+= buffer_len % 4;
            }
            iterations =  buffer_len / leaf_size as usize / 4 * leaf_size as usize ; 

            std::mem::drop(buffer_);
            loop_to +=  buffer_len / leaf_size as usize / 4 * leaf_size as usize; 
            let handle = thread::spawn(move || {
            for i in (loop_to-iterations..loop_to+extra).step_by(leaf_size as usize) {
                println!("index {:?}, thread {:?}", i, thread::current().id());
                let mut hash_machine2 = HashType::default();
                let mut leaf_buf: Vec<u8> = Vec::new();
                let buffer = buffer.lock().unwrap();

                    if (i + leaf_size as usize) < buffer.len() {
                        leaf_buf = buffer[i..(i + leaf_size as usize ) as usize].to_vec();
                    }
                    else if i < buffer.len() {
                        leaf_buf = buffer[i..buffer.len()].to_vec();

                        while leaf_size as usize - leaf_buf.len() as usize > 0 {
                            leaf_buf.push(0);
                        }
                    }
                    std::mem::drop(buffer);
                    let leaf_hash = get_leaf_hash(leaf_buf.as_mut_ptr(), log2_leaf_size, log2_word_size);
                    let mut leaf_hashes = leaf_hashes.lock().unwrap();
                    leaf_hashes.push(leaf_hash.clone());
                    //let mut tree_from_scratch = FullMerkleTree::full_merkle_tree_with_leaves(log2_root_size, log2_leaf_size, log2_word_size, &leaf_hashes);
                    let mut tree_from_scratch: FullMerkleTree = Default::default();

                    tree_from_scratch.full_merkle_tree_with_leaves(log2_root_size, log2_leaf_size, log2_word_size, &leaf_hashes);
                    let mut complete_tree = complete_tree.lock().unwrap();
                    complete_tree.push_back(&leaf_hash);
                    print_hash(&complete_tree.get_root_hash());

                    std::mem::drop(leaf_hashes);
                    /*if &complete_tree.get_root_hash() != tree_from_scratch.get_root_hash() {
                        error(format!("mismatch in root hash for complete tree and tree from scratch\n"));
                        panic!();
                    }*/
                    std::mem::drop(complete_tree);

                    let mut back_tree = back_tree.lock().unwrap();
                    let mut back_leaf_proof = back_tree.get_next_leaf_proof();

                    back_tree.push_back(&leaf_hash);

                    //let mut tree_from_scratch_compare = Arc::clone(&tree_from_scratch);
                    //let mut tree_from_scratch_compare = tree_from_scratch.lock().unwrap();

                    /*if &back_tree.get_root_hash() != tree_from_scratch.get_root_hash() {
                        error(format!("root hash = {:?}\n tree from scratch hash = {:?}\n", &back_tree.get_root_hash(), &tree_from_scratch.get_root_hash()));
                        panic!();
                    }*/

                    
                    //std::mem::drop(tree_from_scratch_compare);

                    //std::mem::drop(tree_from_scratch);
                    std::mem::drop(back_tree);
                    let mut machine_merkle_tree = machine_merkle_tree.lock().unwrap();
                    machine_merkle_tree.update_page_node_hash(i as u64, &leaf_hash);
                    machine_merkle_tree.get_page_node_hash_address(i as u64, &mut hash_machine2);
                    std::mem::drop(machine_merkle_tree);
            }

        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
    println!("finish");

    let mut hash_root = HashType::default();
    let mut machine_merkle_tree = machine_merkle_tree.lock().unwrap();

    machine_merkle_tree.get_root_hash(&mut hash_root);
    let mut h = h.lock().unwrap();
    //machine_merkle_tree.end_update(&mut h);
    std::mem::drop(h);
    println!("finish");

    println!("machine tree verification: {:?}", machine_merkle_tree.verify_tree());
    std::mem::drop(machine_merkle_tree);
    let elapsed = now.elapsed();
    
    println!("Elapsed: {:.2?}", elapsed);
}