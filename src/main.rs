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


type HashType = Box<Vec<u8>>;
type HasherType = sha3::Keccak256;


fn main(){

    let  log2_word_size: isize = 3;
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
    let mut back_tree: BackMerkleTree = Default::default();
    back_tree.back_merkle_tree(log2_root_size, log2_leaf_size, log2_word_size);

    let mut complete_tree: CompleteMerkleTree = Default::default();
    complete_tree.complete_merkle_tree(log2_root_size, log2_leaf_size, log2_word_size);

    let mut machine_merkle_tree: MachineMerkleTree = Default::default();
    machine_merkle_tree.machine_merkle_tree_initialization();

    let mut leaf_hashes: Vec<HashType> = Vec::new();
    machine_merkle_tree.begin_update();

    let max_leaves: u64 = 1u64 << (log2_root_size - log2_leaf_size);
    let mut leaf_count: u64 = 0;
    let mut h: HasherType = Default::default();
    let mut buffer = Vec::new();
    let mut reader = BufReader::new(File::open(&input_name).unwrap());

    reader.read_to_end(&mut buffer).unwrap();

    let mut buffer_index: usize = 0;  
    while true {

        if leaf_count >= max_leaves {
            error(format!("too many leaves for tree"));
        }
        let mut leaf_buf: Vec<u8> = Vec::new();
        if (buffer_index + leaf_size as usize) < buffer.len() {
            leaf_buf = buffer[buffer_index..(buffer_index + leaf_size as usize ) as usize].to_vec();
        }
        else if buffer_index < buffer.len() {
            leaf_buf = buffer[buffer_index..buffer.len()].to_vec();

            while leaf_size as usize - leaf_buf.len() as usize > 0 {
                leaf_buf.push(0);
            }
        }
        else {
            break;
        }

        let mut leaf_hash = get_leaf_hash(leaf_buf.as_mut_ptr(), log2_leaf_size, log2_word_size);

        leaf_hashes.push(leaf_hash.clone());
        print_hash(&leaf_hash);


        let mut back_leaf_proof = back_tree.get_next_leaf_proof();

        back_tree.push_back(&leaf_hash);

        machine_merkle_tree.update_page_node_hash(buffer_index as u64, &leaf_hash);
        let mut hash_machine2 = HashType::default();

        machine_merkle_tree.get_page_node_hash_address(buffer_index as u64, &mut hash_machine2);
        println!("get_page_node_hash_address = ");
        print_hash(&hash_machine2);

        let mut tree_from_scratch: FullMerkleTree = Default::default();

        tree_from_scratch.full_merkle_tree_with_leaves(log2_root_size, log2_leaf_size, log2_word_size, &leaf_hashes);

        if &back_tree.get_root_hash() != tree_from_scratch.get_root_hash() {
            error(format!("mismatch in root hash for back tree and tree from scratch\n"));
            panic!();
        }


        back_leaf_proof.set_root_hash(&back_leaf_proof.bubble_up(&mut h, &mut leaf_hash));

        back_leaf_proof.set_target_hash(&leaf_hash);


        if !back_leaf_proof.verify(&mut h) {
            error(format!("updated back leaf proof failed verification\n"));
            panic!();
        }

        let from_scratch_leaf_proof = tree_from_scratch.get_proof(leaf_count.clone() << log2_leaf_size, log2_leaf_size);

        if back_leaf_proof != from_scratch_leaf_proof {
            error(format!("mismatch in leaf proofs for back tree and tree from scratch\n"));
        }

        complete_tree.push_back(&leaf_hash);

        assert_eq!(&complete_tree.get_root_hash(), tree_from_scratch.get_root_hash());

        if &complete_tree.get_root_hash() != tree_from_scratch.get_root_hash() {
            error(format!("mismatch in root hash for complete tree and tree from scratch\n"));
            panic!();
        }
 
        let complete_leaf_proof = complete_tree.get_proof(leaf_count.clone() << log2_leaf_size, log2_leaf_size);
        assert_eq!(complete_leaf_proof.m_root_hash, from_scratch_leaf_proof.m_root_hash);
        if from_scratch_leaf_proof != complete_leaf_proof {
            error(format!("mismatch in leaf proofs for full tree and tree from scratch\n"));
        }
        leaf_count += 1;
        buffer_index += leaf_size as usize;
    }
    let mut hash_root = HashType::default();
    machine_merkle_tree.get_root_hash(&mut hash_root);
    machine_merkle_tree.end_update(&mut h);
    println!("machine tree verification: {:?}", machine_merkle_tree.verify_tree());
    print_hash(&back_tree.get_root_hash());
}