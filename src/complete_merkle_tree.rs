use crate::pristine_merkle_tree::PristineMerkleTree;
use crate::merkle_tree_proof::MerkleTreeProof;

use std::cmp;
use sha3::Digest;

type AddressType = u64;
type HasherType = sha3::Keccak256;
type HashType = Box<Vec<u8>>;
type ProofType = MerkleTreeProof;
type LevelType = Vec<HashType>;

#[derive(Default)]
pub struct CompleteMerkleTree {
    pub m_log2_root_size: isize,        
    pub m_log2_leaf_size: isize,
    pub m_pristine: PristineMerkleTree,
    pub m_tree: Vec<LevelType>,
}

impl CompleteMerkleTree {
    pub fn complete_merkle_tree(&mut self, log2_root_size: isize, log2_leaf_size: isize, log2_word_size: isize) {
        self.m_log2_root_size = log2_root_size;
        self.m_log2_leaf_size = log2_leaf_size;
        self.m_pristine = PristineMerkleTree::default();
        self.m_pristine.pristine_merkle_tree(log2_root_size, log2_word_size);
        let len = cmp::max(0, log2_root_size - log2_leaf_size + 1) as usize;
        self.m_tree = vec![vec![Box::new(vec![])]; len];
        CompleteMerkleTree::check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
    }

    const fn get_log2_root_size(&self) -> isize {
        return self.m_log2_root_size;
    }

    pub fn get_root_hash(&mut self) -> HashType {
        return self.get_node_hash( 0, self.get_log2_root_size());
    }

    const fn get_log2_leaf_size(&self) -> isize {
        return self.m_log2_leaf_size;
    }

    pub fn get_proof(&mut self, address: AddressType, log2_size: isize) -> ProofType {

        if log2_size < self.get_log2_leaf_size() || log2_size > self.get_log2_root_size() {
            panic!("log2_size is out of bounds");
        }
        let aligned_address = (address >> log2_size) << log2_size;
        if address != aligned_address {
            panic!("address is misaligned");
        }

        let mut proof: ProofType = Default::default();
        proof.merkle_tree_proof(self.get_log2_root_size(), log2_size);

        proof.set_root_hash(&self.get_root_hash());
        proof.set_target_address(address);
        proof.set_target_hash(&self.get_node_hash(address, log2_size));
        for log2_sibling_size in log2_size..self.get_log2_root_size() {
            let sibling_address = address ^ ((1 as AddressType) << log2_sibling_size);
            proof.set_sibling_hash(&self.get_node_hash(sibling_address, log2_sibling_size), log2_sibling_size);
        }
        return proof;
    }

    pub fn push_back(&mut self, hash: &HashType) {
        let leaves = self.get_level(self.get_log2_leaf_size());
            if leaves.len() >= ((1 as AddressType) << (self.get_log2_root_size() - self.get_log2_leaf_size())) as usize {
                panic!("tree is full");
            }
            if *self.m_tree[(self.m_log2_root_size - self.m_log2_leaf_size) as usize][0] == vec![]{
                self.m_tree[(self.m_log2_root_size - self.m_log2_leaf_size) as usize] = vec![(Box::new(*hash.clone()))];
            }
            else {
                self.m_tree[(self.m_log2_root_size - self.m_log2_leaf_size) as usize].push((Box::new(*hash.clone())));
            }
            self.bubble_up();
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

    fn get_node_hash(&mut self, address: AddressType, log2_size: isize) -> HashType {
            let level = &*self.get_level(log2_size).clone();
            let mut address = address.clone();
            address >>= log2_size;
            if address >= ((1 as AddressType) << (self.get_log2_root_size() - log2_size)) {
                panic!("log2_size is out of bounds");
            }
            if address < level.clone().len() as u64{
                return level[address as usize].clone();
            } else {
                return Box::new(*self.m_pristine.get_hash(log2_size).clone());
            }
    }

    fn bubble_up(&mut self) {
        let mut h: HasherType = Default::default();

        for log2_next_size in (self.get_log2_leaf_size() + 1)..(self.get_log2_root_size()+1) {
            let log2_prev_size = log2_next_size - 1;
            let prev = self.get_level(log2_prev_size);
            let next = self.get_level(log2_next_size);
            let mut first_entry = if !next.is_empty() {
                next.len() - 1

            } else {
                next.len()
                
            };
            self.get_level_mut(log2_next_size).resize((prev.len() + 1) / 2, Box::new(Vec::new()));    
            assert!(first_entry <= self.get_level_mut(log2_next_size).len());
            let last_safe_entry = prev.len() / 2;
            while first_entry < last_safe_entry {
                h.reset();
                h.update(self.get_level_mut(log2_prev_size)[2 * first_entry].as_slice());
                h.update(self.get_level_mut(log2_prev_size)[2 * first_entry + 1].as_slice());
                self.get_level_mut(log2_next_size)[first_entry] = Box::new(h.clone().finalize().to_vec());
                first_entry += 1;
            }
            if self.get_level_mut(log2_prev_size).len() > 2 * last_safe_entry {
                h.reset();
                h.update( *self.get_level_mut(log2_prev_size).last().unwrap().clone());
                h.update(self.m_pristine.get_hash(log2_prev_size).as_slice());
                self.get_level_mut(log2_next_size)[last_safe_entry] = Box::new(h.clone().finalize().to_vec());
            }
        }
    }

    fn get_level(&self, log2_size: isize) -> LevelType {
        if log2_size < self.get_log2_leaf_size() || log2_size > self.get_log2_root_size() {
            panic!("log2_size is out of bounds");
        }
        return self.m_tree[(self.m_log2_root_size - log2_size) as usize].clone();
    }

    fn get_level_mut(&mut self, log2_size: isize) -> &mut LevelType {
        if log2_size < self.get_log2_leaf_size() || log2_size > self.get_log2_root_size() {
            panic!("log2_size is out of bounds");
        }
        return &mut self.m_tree[(self.m_log2_root_size - log2_size) as usize];
    }
}