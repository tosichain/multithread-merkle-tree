use crate::pristine_merkle_tree::PristineMerkleTree;
use crate::merkle_tree_proof::MerkleTreeProof;

use sha3::Digest;
use std::cmp;

type AddressType = u64;
type HasherType = sha3::Keccak256;
type HashType = Box<Vec<u8>>;
type ProofType = MerkleTreeProof;

#[derive(Default)]
pub struct BackMerkleTree {

    pub m_log2_root_size: isize,                   
    pub m_log2_leaf_size: isize,                   
    pub m_leaf_count: AddressType,           
    pub m_max_leaves: AddressType,              
    pub m_context: Vec<HashType>,       
    pub m_pristine_hashes: PristineMerkleTree,

}

impl BackMerkleTree {
    pub fn back_merkle_tree(&mut self, log2_root_size: isize, log2_leaf_size: isize, log2_word_size: isize) {
        self.m_log2_root_size = log2_root_size;
        self.m_log2_leaf_size = log2_leaf_size;
        self.m_leaf_count = 0;
        self.m_max_leaves = (1 as AddressType) << (log2_root_size - log2_leaf_size);
        let len = cmp::max(1 as isize, log2_root_size - log2_leaf_size + 1) as usize;
        self.m_context = vec![Box::new(vec![]); len];
        self.m_pristine_hashes = PristineMerkleTree::default();
        self.m_pristine_hashes.pristine_merkle_tree(log2_root_size, log2_word_size);

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
        if log2_root_size >= AddressType::BITS as isize{
            panic!("tree is too large for address type");
        }
        
    }

    pub fn push_back(&mut self, leaf_hash: &HashType) {
        let mut h: HasherType = Default::default();
        let mut right = leaf_hash.clone();
        if self.m_leaf_count >= self.m_max_leaves {
            panic!("too many leaves");
        }
        let depth: isize = self.m_log2_root_size - self.m_log2_leaf_size;
        for i in 0..depth+1 {
            if (self.m_leaf_count & ((1 as AddressType) << i)) != 0 {
                let left = &self.m_context[i as usize];
                h.reset();
                h.update(left.as_slice());
                h.update(right.as_slice());
                right = Box::new(h.clone().finalize().to_vec());
            } else {
                self.m_context[i as usize] = Box::new(*right.clone());
                break;
            }
        }
        self.m_leaf_count += 1;
    }

    pub fn get_root_hash(&self) -> HashType{
        let mut h: HasherType = Default::default();
        assert!(self.m_leaf_count <= self.m_max_leaves);
        let depth = self.m_log2_root_size - self.m_log2_leaf_size;
        if self.m_leaf_count < self.m_max_leaves {
            let mut root = self.m_pristine_hashes.get_hash(self.m_log2_leaf_size).clone();
            for i in 0..depth {
                if (self.m_leaf_count & ((1 as AddressType) << i)) != 0 {
                    let left = self.m_context[i as usize].clone();
                    h.reset();
                    h.update(left.as_slice());
                    h.update(root.as_slice());
                    root = Box::new(h.clone().finalize().to_vec());
                } else {
                    let right = self.m_pristine_hashes.get_hash(self.m_log2_leaf_size + i);
                    h.reset();
                    h.update(root.as_slice());
                    h.update(right.as_slice());
                    root = Box::new(h.clone().finalize().to_vec());
                }
            }
            return root;
        } else {
            return self.m_context[depth as usize].clone();
        }
    }

    pub fn get_next_leaf_proof(&self) -> ProofType {
        let depth = self.m_log2_root_size - self.m_log2_leaf_size;
        if self.m_leaf_count >= self.m_max_leaves {
            panic!("tree is full");
        }
        let mut h: HasherType = Default::default();
        let mut proof: ProofType = Default::default();
        proof.merkle_tree_proof(self.m_log2_root_size, self.m_log2_leaf_size);
        proof.set_target_address(self.m_leaf_count << self.m_log2_leaf_size);
        proof.set_target_hash(self.m_pristine_hashes.get_hash(self.m_log2_leaf_size));
        let mut hash: HashType = self.m_pristine_hashes.get_hash(self.m_log2_leaf_size).clone();
        for i in 0..depth {
            if (self.m_leaf_count & ((1 as AddressType) << i)) != 0  {
                let left = self.m_context[i as usize].clone();
                proof.set_sibling_hash(&left, self.m_log2_leaf_size + i);
                h.reset();
                h.update(left.as_slice());
                h.update(hash.as_slice());
                hash = Box::new(h.clone().finalize().to_vec());
            } else {
                let right = self.m_pristine_hashes.get_hash(self.m_log2_leaf_size + i);
                proof.set_sibling_hash(right, self.m_log2_leaf_size + i);
                h.reset();
                h.update(hash.as_slice());
                h.update(right.as_slice());
                hash = Box::new(h.clone().finalize().to_vec());
            }
        }
        proof.set_root_hash(&hash);

        #[cfg(not(feature = "ndebug"))]
        if !proof.verify(&mut h) {
            panic!("produced invalid proof");
        }

        return proof;
    }
}