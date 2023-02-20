use std::cmp;
use sha3::Digest;

type HasherType = sha3::Keccak256;
type HashType = Box<Vec<u8>>;

#[derive(Default)]
pub struct PristineMerkleTree {
    pub m_log2_root_size: isize,            
    pub m_log2_word_size: isize,           
    pub m_hashes: Vec<HashType>,
}

impl PristineMerkleTree {

    pub fn pristine_merkle_tree(&mut self, log2_root_size: isize, log2_word_size: isize) {
        self.m_log2_root_size = log2_root_size;
        self.m_log2_word_size = log2_word_size; 
        let len = cmp::max(0, log2_root_size - log2_word_size + 1) as usize;
        self.m_hashes = vec![Box::new(vec![]); len];
        if log2_root_size < 0 {
            panic!("log2_root_size is negative");
        }
        if log2_word_size < 0 {
            panic!("log2_word_size is negative");
        }
        if log2_word_size > log2_root_size {
            panic!("log2_word_size is greater than log2_root_size");
        }
        let word: Vec<u8> = vec![0;1 << log2_word_size];
        assert!(word.len() == (1u64 << log2_word_size) as usize);
        let mut h: HasherType = Default::default();
        h.reset();
        h.update(word);
        self.m_hashes[0] = Box::new(h.clone().finalize().to_vec());
        for i in 1..self.m_hashes.len() {
            h.reset();
            h.update(self.m_hashes[i - 1].to_vec());
            h.update(self.m_hashes[i - 1].to_vec());
            self.m_hashes[i] = Box::new(h.clone().finalize().to_vec());
        }
    }

    pub fn get_hash(&self, log2_size: isize) -> &HashType {
        if log2_size < self.m_log2_word_size || log2_size > self.m_log2_root_size {
            panic!("log2_size is out of range");
        }
        return &self.m_hashes[(log2_size - self.m_log2_word_size) as usize];
    }
}