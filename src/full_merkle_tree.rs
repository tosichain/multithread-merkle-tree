use crate::pristine_merkle_tree::PristineMerkleTree;
use crate::merkle_tree_proof::MerkleTreeProof;

use std::cmp;
use sha3::Digest;

type AddressType = u64;
type HasherType = sha3::Keccak256;
type HashType = Box<Vec<u8>>;
type ProofType = MerkleTreeProof;

#[derive(Default)]
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
    
    fn init_tree(&mut self, pristine: &PristineMerkleTree, leaves: &Vec<HashType>) {

        for v in 0..leaves.len() as usize{
            self.m_tree[self.m_max_leaves as usize + v] = leaves[v].clone();
        }

        let hash_value = pristine.get_hash(self.get_log2_leaf_size());
        for v in self.m_max_leaves + (leaves.len() as u64)..2*(self.m_max_leaves){
            self.m_tree[v as usize] = Box::new(*hash_value.clone());
        }
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