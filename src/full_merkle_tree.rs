use crate::pristine_merkle_tree::PristineMerkleTree;
use crate::merkle_tree_proof::MerkleTreeProof;

use std::cmp;
use sha3::Digest;

type AddressType = u64;
type HasherType = sha3::Keccak256;
type HashType = Box<Vec<u8>>;
type ProofType = MerkleTreeProof;
use std::thread;
use std::sync::Arc;
use std::sync::Mutex;
use rayon::{Scope, ThreadPool};
use rayon::ThreadPoolBuilder;
#[derive(Default, Debug, Clone)]
pub struct FullMerkleTree {

    m_log2_root_size: isize,      
    m_log2_leaf_size: isize,
    m_max_leaves: AddressType,
    pub m_tree: Vec<HashType>,

}

impl FullMerkleTree {

    pub fn full_merkle_tree(&mut self, log2_root_size: isize, log2_leaf_size: isize, log2_word_size: isize) {
        self.m_log2_root_size = log2_root_size;
        self.m_log2_leaf_size = log2_leaf_size;
        self.m_max_leaves = (1 as AddressType) << cmp::max(0, log2_root_size - log2_leaf_size);
        FullMerkleTree::check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
        self.m_tree = vec![Box::new(vec![]); 2 * self.m_max_leaves as usize];
        let mut m_pristine_hashes = PristineMerkleTree::default();
        m_pristine_hashes.pristine_merkle_tree(log2_root_size, log2_word_size);
        self.init_pristine_subtree(&m_pristine_hashes, 1, log2_root_size);
    }

    /*pub fn full_merkle_tree_with_leaves(log2_root_size: isize, log2_leaf_size: isize, log2_word_size: isize, leaves: &Vec<HashType>) -> FullMerkleTree{
        let mut tree_from_scratch: FullMerkleTree = Default::default();
        tree_from_scratch.m_log2_root_size = log2_root_size;
        tree_from_scratch.m_log2_leaf_size = log2_leaf_size;
        tree_from_scratch.m_max_leaves = (1 as AddressType) << cmp::max(0, log2_root_size - log2_leaf_size);
        FullMerkleTree::check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
        if leaves.len() > tree_from_scratch.m_max_leaves as usize {
            panic!("too many leaves");
        }
        tree_from_scratch.m_tree = vec![Box::new(vec![]); 2 * tree_from_scratch.m_max_leaves as usize];
        let mut m_pristine_hashes = PristineMerkleTree::default();
        m_pristine_hashes.pristine_merkle_tree(log2_root_size, log2_word_size);
        let arc_mut_full = Arc::new(Mutex::new(tree_from_scratch));
        //let result = Arc::clone(&arc_mut_full);
        FullMerkleTree::init_tree(Arc::clone(&arc_mut_full), &m_pristine_hashes, leaves);
        let result = arc_mut_full.lock().unwrap().clone();
        println!("999999999999999999999999999999 {:?}", result.m_tree.get(1));
        result

    }*/

    pub fn full_merkle_tree_with_leaves(&mut self, log2_root_size: isize, log2_leaf_size: isize, log2_word_size: isize, leaves: &Vec<HashType>){
        self.m_log2_root_size = log2_root_size;
        self.m_log2_leaf_size = log2_leaf_size;
        self.m_max_leaves = (1 as AddressType) << cmp::max(0, log2_root_size - log2_leaf_size);
        FullMerkleTree::check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
        if leaves.len() > self.m_max_leaves as usize {
            panic!("too many leaves");
        }
        self.m_tree = vec![Box::new(vec![]); 2 * self.m_max_leaves as usize];
        let mut m_pristine_hashes = PristineMerkleTree::default();
        m_pristine_hashes.pristine_merkle_tree(log2_root_size, log2_word_size);
        self.init_tree(&m_pristine_hashes, leaves);
        //println!("999999999999999999999999999999 {:?}", self.m_tree[self.get_node_index(0, self.get_log2_root_size()) as usize]);

    }

    const fn get_log2_leaf_size(&self) -> isize {
        return self.m_log2_leaf_size;
    }

    const fn get_log2_root_size(&self) -> isize {
        return self.m_log2_root_size;
    }

    pub fn get_root_hash(&self) -> &HashType {
        return self.get_node_hash( 0, self.get_log2_root_size());
    }

    fn get_node_hash(&self, address: AddressType, log2_size: isize) -> &HashType {
        return &self.m_tree[self.get_node_index(address, log2_size) as usize];
    }

    const fn left_child_index(index: isize) -> isize {
        return 2 * index;
    }

    const fn right_child_index(index: isize) -> isize{
        return 2 * index + 1;
    }

    pub fn get_proof(&self, address: AddressType, log2_size: isize) -> ProofType {
        if log2_size < self.get_log2_leaf_size() || log2_size > self.get_log2_root_size() {
            panic!("log2_size is out of bounds");
        }
        let aligned_address = (address >> log2_size) << log2_size;
        if address != aligned_address {
            panic!("address is misaligned");
        }
        let mut proof: ProofType = Default::default();
        proof.merkle_tree_proof(self.get_log2_root_size(), log2_size);

        proof.set_root_hash(self.get_root_hash());
        proof.set_target_address(address);
        proof.set_target_hash(self.get_node_hash(address, log2_size));

        for log2_sibling_size in log2_size..self.get_log2_root_size() {
            let sibling_address = address ^ ((1 as AddressType) << log2_sibling_size);
            proof.set_sibling_hash(self.get_node_hash(sibling_address, log2_sibling_size), log2_sibling_size);
        }

        #[cfg(not(feature = "ndebug"))] {
            if !proof.verify(&mut HasherType::new()) {
                panic!("produced invalid proof");
            }
        }

        return proof;
    }

    fn check_log2_sizes(log2_root_size: isize, log2_leaf_size: isize, log2_word_size: isize) {
        if log2_root_size < 0 {
            panic!("log2_root_size is negative");
        }
        if log2_leaf_size < 0 {
            panic!("log2_leaf_size is negative");
        }
        if log2_word_size < 0 {
            panic!("log2_word_size is negative");
        }
        if log2_leaf_size > log2_root_size {
            panic!("log2_leaf_size is greater than log2_root_size");
        }
        if log2_word_size > log2_leaf_size {
            panic!("log2_word_size is greater than log2_word_size");
        }
        if log2_root_size >= AddressType::BITS as isize {
            panic!("tree is too large for address type");
        }
    }

    fn init_pristine_subtree(&mut self, pristine: &PristineMerkleTree, index: isize, log2_size: isize) {
        if log2_size >= self.get_log2_leaf_size() {
            self.m_tree[index as usize] = Box::new(*pristine.get_hash(log2_size).clone());
            self.init_pristine_subtree(pristine, FullMerkleTree::left_child_index(index), log2_size - 1);
            self.init_pristine_subtree(pristine, FullMerkleTree::right_child_index(index), log2_size - 1);
        }
    }

    /*fn init_subtree(self_instance: Arc<Mutex<FullMerkleTree>>, h: Arc<Mutex<HasherType>>, index: isize, log2_size: isize) {
        let self_instance_clone = Arc::clone(&self_instance);
        let h_clone = Arc::clone(&h);
        let self_instance_clone2 = Arc::clone(&self_instance);
        let h_clone2 = Arc::clone(&h);
        if log2_size > self_instance.lock().unwrap().get_log2_leaf_size() {

           rayon::join(|| FullMerkleTree::init_subtree(self_instance_clone, h_clone,FullMerkleTree::left_child_index(index), log2_size - 1),
            || FullMerkleTree::init_subtree( self_instance_clone2, h_clone2, FullMerkleTree::right_child_index(index), log2_size - 1)); // runs simultaneously, but practically successively 
        
        //FullMerkleTree::init_subtree(Arc::clone(&self_instance_clone), Arc::clone(&h_clone),FullMerkleTree::left_child_index(index), log2_size - 1);
        //FullMerkleTree::init_subtree( Arc::clone(&self_instance_clone2), Arc::clone(&h_clone2), FullMerkleTree::right_child_index(index), log2_size - 1);
  
            let h_clone3 = Arc::clone(&h);
            let mut h = h_clone3.lock().unwrap();
            h.reset();
            let self_instance_clone3 = Arc::clone(&self_instance);
            let mut self_instance = self_instance_clone3.lock().unwrap();
            h.update(self_instance.m_tree[FullMerkleTree::left_child_index(index) as usize].as_slice());
            h.update(self_instance.m_tree[FullMerkleTree::right_child_index(index) as usize].as_slice());
            (*self_instance).m_tree[index as usize] = Box::new(h.clone().finalize().to_vec());
            std::mem::drop(h);
            std::mem::drop(self_instance); 
        }

        
    }*/
    fn init_subtree(&mut self, h: &mut HasherType, index: isize, log2_size: isize) {
        if log2_size > self.get_log2_leaf_size() {
            self.init_subtree(h, FullMerkleTree::left_child_index(index), log2_size - 1);
            self.init_subtree(h, FullMerkleTree::right_child_index(index), log2_size - 1);
            h.reset();
            h.update(self.m_tree[FullMerkleTree::left_child_index(index) as usize].as_slice());
            h.update(self.m_tree[FullMerkleTree::right_child_index(index) as usize].as_slice());
            self.m_tree[index as usize] = Box::new(h.clone().finalize().to_vec());

        }
    }
    
    /*fn init_tree(self_instance: Arc<Mutex<FullMerkleTree>>, pristine: &PristineMerkleTree, leaves: &Vec<HashType>) {
        let self_instance_clone = Arc::clone(&self_instance);
        let self_instance_clone2 = Arc::clone(&self_instance);

        let mut self_instance = self_instance_clone.lock().unwrap();

        for v in 0..leaves.len() as usize{
            let m_max = self_instance.m_max_leaves as usize + v;
            (*self_instance).m_tree[m_max] = leaves[v].clone();
        }

        let hash_value = pristine.get_hash(self_instance.get_log2_leaf_size());
        for v in self_instance.m_max_leaves + (leaves.len() as u64)..2*(self_instance.m_max_leaves){
            (*self_instance).m_tree[v as usize] = Box::new(*hash_value.clone());
        }
        let mut h = Arc::new(Mutex::new(HasherType::default()));
        let log2_size = self_instance.get_log2_root_size();
        std::mem::drop(self_instance);
        FullMerkleTree::init_subtree( self_instance_clone2, h, 1, log2_size);

    }*/

    fn init_tree(&mut self, pristine: &PristineMerkleTree, leaves: &Vec<HashType>) {

        for v in 0..leaves.len() as usize{
            self.m_tree[self.m_max_leaves as usize + v] = leaves[v].clone();
        }

        let hash_value = pristine.get_hash(self.get_log2_leaf_size());
        for v in self.m_max_leaves + (leaves.len() as u64)..2*(self.m_max_leaves){
            self.m_tree[v as usize] = Box::new(*hash_value.clone());
        }
        //println!("966666666 {:?}", self.m_tree.get(1));

        let mut h: HasherType = Default::default();
        self.init_subtree(&mut h, 1, self.get_log2_root_size());
    }

    fn get_node_index(&self, address: AddressType, log2_size: isize) -> AddressType {
        if log2_size < self.get_log2_leaf_size() || log2_size > self.get_log2_root_size() {
            panic!("log2_size is out of bounds");
        }
        let base: AddressType = (1 as AddressType) << (self.get_log2_root_size() - log2_size);
        let mut address = address.clone();
        address >>= log2_size;
        if address >= base {
            panic!("address is out of bounds");
        }
        return base + address;
    }
}