use crate::pristine_merkle_tree::PristineMerkleTree;
use crate::merkle_tree_proof::MerkleTreeProof;

use std::cmp;
use sha3::Digest;

type AddressType = u64;
type HasherType = sha3::Keccak256;
type HashType = Box<Vec<u8>>;
type ProofType = MerkleTreeProof;
type LevelType = Vec<HashType>;

pub struct CompleteMerkleTree {
    m_log2_root_size: isize,        
    m_log2_leaf_size: isize,
    m_pristine: PristineMerkleTree,
    m_tree: Vec<LevelType>,
}

impl CompleteMerkleTree {
    fn complete_merkle_tree(&mut self, log2_root_size: isize, log2_leaf_size: isize, log2_word_size: isize) {
        self.m_log2_root_size = log2_root_size;
        self.m_log2_leaf_size = log2_leaf_size;
        self.m_pristine = PristineMerkleTree {
            m_log2_root_size: log2_root_size,
            m_log2_word_size: log2_word_size,
            m_hashes: Default::default(),
        };
        self.m_tree = vec![vec![Box::new(vec![cmp::max(0, log2_root_size - log2_leaf_size + 1) as u8])]];
        CompleteMerkleTree::check_log2_sizes(log2_root_size, log2_leaf_size, log2_word_size);
    }

    const fn get_log2_root_size(&self) -> isize {
        return self.m_log2_root_size;
    }

    fn get_root_hash(&self) -> HashType {
        return self.get_node_hash(&mut 0, self.get_log2_root_size());
    }

    const fn get_log2_leaf_size(&self) -> isize {
        return self.m_log2_leaf_size;
    }

    fn get_proof(&self, address: &mut AddressType, log2_size: isize) -> ProofType {
        if log2_size < self.get_log2_leaf_size() || log2_size > self.get_log2_root_size() {
            panic!("log2_size is out of bounds");
        }
        let aligned_address = (*address >> log2_size) << log2_size;
        if *address != aligned_address {
            panic!("address is misaligned");
        }

        let mut proof: ProofType = Default::default();
        proof.merkle_tree_proof(self.get_log2_root_size(), log2_size);

        proof.set_root_hash(&self.get_root_hash());
        proof.set_target_address(*address);
        proof.set_target_hash(&self.get_node_hash(address, log2_size));
        for log2_sibling_size in log2_size..self.get_log2_root_size() {
            let mut sibling_address = *address ^ ((1 as AddressType) << log2_sibling_size);
            proof.set_sibling_hash(&self.get_node_hash(&mut sibling_address, log2_sibling_size), log2_sibling_size);
        }
        return proof;
    }

    fn push_back(&self, hash: &HashType) {
        let mut leaves = self.get_level(self.get_log2_leaf_size());
        if leaves.len() >= ((1 as AddressType) << (self.get_log2_root_size() - self.get_log2_leaf_size())) as usize {
            panic!("tree is full");
        }
        leaves.push(Box::new(*hash.clone()));
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

    fn get_node_hash(&self, address: &mut AddressType, log2_size: isize) -> HashType {
        let level = self.get_level(log2_size);
        *address >>= log2_size;
        if *address >= ((1 as AddressType) << (self.get_log2_root_size() - log2_size)) {
            panic!("log2_size is out of bounds");
        }
        if *address < level.clone().len() as u64{
            return level[*address as usize].clone();
        } else {
            return Box::new(*self.m_pristine.get_hash(log2_size).clone());
        }
    }

    fn bubble_up(&self) {
        let mut h: HasherType = Default::default();

        for log2_next_size in (self.get_log2_leaf_size() + 1)..(self.get_log2_root_size()+1) {
            let log2_prev_size = log2_next_size - 1;
            let prev = self.get_level(log2_prev_size);
            let mut next = self.get_level(log2_next_size);
            let mut first_entry = if !next.is_empty() {
                next.len() - 1
            } else {
                next.len()
            };
            next.resize((prev.len() + 1) / 2, Box::new(Vec::new()));
            assert!(first_entry <= next.len());
            let last_safe_entry = prev.len() / 2;
            while first_entry < last_safe_entry {
                h.reset();
                h.update(prev[2 * first_entry].as_slice());
                h.update(prev[2 * first_entry + 1].as_slice());
                next[first_entry] = Box::new(h.clone().finalize().to_vec());
                first_entry += 1;
            }
            if prev.len() > 2 * last_safe_entry {
                h.reset();
                h.update( *prev.last().unwrap().clone());
                h.update(self.m_pristine.get_hash(log2_prev_size).as_slice());
                next[last_safe_entry] = Box::new(h.clone().finalize().to_vec());
            }
        }
    }

    fn get_level(&self, log2_size: isize) -> LevelType {
        if log2_size < self.get_log2_leaf_size() || log2_size > self.get_log2_root_size() {
            panic!("log2_size is out of bounds");
        }
        return self.m_tree[(self.m_log2_root_size - log2_size) as usize].clone();
    }
}