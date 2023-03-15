use std::cmp;
use sha3::Digest;

type AddressType = u64;
type HashType = Box<Vec<u8>>;
type HasherType = sha3::Keccak256;


#[derive(Default, Debug)]
pub struct MerkleTreeProof{
    m_target_address: AddressType,
    m_log2_target_size: isize,           
    m_target_hash: HashType,
    m_log2_root_size: isize,                 
    pub m_root_hash: HashType,              
    pub m_sibling_hashes: Vec<HashType>,
}    

impl MerkleTreeProof{

    pub fn merkle_tree_proof(&mut self, log2_root_size: isize, log2_target_size: isize) {
        self.m_target_address = Default::default();
        self.m_log2_target_size = log2_target_size;
        self.m_target_hash  = Default::default();
        self.m_log2_root_size = log2_root_size;
        self.m_root_hash = Default::default();
        let len = cmp::max(0, (log2_root_size - log2_target_size) as u8);
        self.m_sibling_hashes = vec![Box::new(vec![]); len as usize];
        if log2_root_size <= 0 {
            panic!("log2_root_size is not positive");
        }
        if log2_target_size < 0 {
            panic!("log2_target_size is negative");
        }
        if log2_target_size > log2_root_size {
            panic!("log2_target_size is greater than log2_root_size");
        }
    }

    const fn get_log2_root_size(&self) -> isize {
        return self.m_log2_root_size;
    }

    pub const fn get_log2_target_size(&self) -> isize {
        return self.m_log2_target_size;
    }

    pub fn set_target_address(&mut self, target_address: AddressType) {
        self.m_target_address = target_address;
    }

    fn get_target_address(&self) -> &AddressType {
        return &self.m_target_address;
    }

    pub fn set_target_hash(&mut self, hash: &HashType) {
        self.m_target_hash = Box::new(*hash.clone());
    }

    pub fn get_target_hash(&self) -> &HashType {
        return &self.m_target_hash;
    }

    pub fn set_root_hash(&mut self, hash: &HashType) {
        self.m_root_hash = Box::new(*hash.clone());
    }

    fn get_root_hash(&self) -> &HashType {
        return &self.m_root_hash;
    }

    fn get_sibling_hash(&self, log2_size: isize) -> &HashType {
        return &self.m_sibling_hashes[self.log2_size_to_index(log2_size) as usize];
    }

    pub fn set_sibling_hash(&mut self, hash: &HashType, log2_size: isize) {
        let index = self.log2_size_to_index(log2_size) as usize;
        self.m_sibling_hashes[index] = Box::new(*hash.clone());
    }

    pub fn verify(&mut self, h: &mut HasherType) -> bool {
        return self.bubble_up(h, &self.get_target_hash().clone()) == self.get_root_hash().clone();
    }

    pub fn bubble_up(&self, h: &mut HasherType, new_target_hash: &HashType) -> HashType {
        let mut hash: HashType = new_target_hash.clone();
        for log2_size in self.get_log2_target_size()..self.get_log2_root_size() {
            let bit: bool = (self.get_target_address() & ((1 as AddressType) << log2_size as u64)) != 0;

            if (bit) {
                h.reset();
                h.update(self.get_sibling_hash(log2_size).as_slice());
                h.update(hash.as_slice());
                hash = Box::new(h.clone().finalize().as_slice().to_vec());
            } else {
                h.reset();
                h.update(hash.as_slice());
                h.update(self.get_sibling_hash(log2_size).as_slice());
                hash = Box::new(h.clone().finalize().as_slice().to_vec());
            }
        }
        return hash.clone();
    }

    pub fn bubble_up_self(&mut self, h: &mut HasherType) -> HashType {
        for log2_size in self.get_log2_target_size()..self.get_log2_root_size() {
            let bit: bool = (self.get_target_address() & ((1 as AddressType) << log2_size as u64)) != 0;
            if (bit) {
                h.reset();
                h.update(self.get_sibling_hash(log2_size).as_slice());
                h.update(self.m_target_hash.as_slice());
                self.m_target_hash = Box::new(h.clone().finalize().as_slice().to_vec());
            } else {
                h.reset();
                h.update(self.m_target_hash.as_slice());
                h.update(self.get_sibling_hash(log2_size).as_slice());
                self.m_target_hash = Box::new(h.clone().finalize().as_slice().to_vec());
            }
        }
        return self.m_target_hash.clone();
    }

    fn slice(&mut self, h: &mut HasherType, new_log2_root_size: isize,
        new_log2_target_size: isize) -> MerkleTreeProof {
        if new_log2_root_size <= 0 {
            panic!("log2_root_size is not positive");
        }
        if new_log2_target_size < 0 {
            panic!("log2_target_size is negative");
        }
        if new_log2_target_size > new_log2_root_size {
            panic!("log2_target_size is greater than log2_root_size");
        }
        if new_log2_root_size > self.get_log2_root_size() {
            panic!("log2_root_size is too large");
        }
        if new_log2_target_size < self.get_log2_target_size() {
            panic!("log2_taget_size is too small");
        }
        let mut sliced: MerkleTreeProof = Default::default();
        sliced.merkle_tree_proof(new_log2_root_size, new_log2_target_size);
        let mut hash: HashType = Box::new(*self.get_target_hash().clone());
        for log2_size in self.get_log2_target_size()..new_log2_target_size {
            let bit: bool  = (self.get_target_address() & ((1 as AddressType) << log2_size)) != 0;
            if bit {
                h.reset();
                h.update(self.get_sibling_hash(log2_size).as_slice());
                h.update(hash.as_slice());
                hash = Box::new(h.clone().finalize().as_slice().to_vec());
            } else {
                h.reset();
                h.update(hash.as_slice());
                h.update(self.get_sibling_hash(log2_size).as_slice());
                hash = Box::new(h.clone().finalize().as_slice().to_vec());
            }
        }
        sliced.set_target_hash(&hash);
        for log2_size in new_log2_target_size..new_log2_root_size {
            let bit: bool = (self.get_target_address() & ((1 as AddressType) << log2_size)) != 0;
            let sibling_hash: &HashType = self.get_sibling_hash(log2_size);
            if bit {
                h.reset();
                h.update(sibling_hash.as_slice());
                h.update(hash.as_slice());
                hash = Box::new(h.clone().finalize().as_slice().to_vec());
            } else {
                h.reset();
                h.update(hash.as_slice());
                h.update(sibling_hash.as_slice());
                hash = Box::new(h.clone().finalize().as_slice().to_vec());
            }
            sliced.set_sibling_hash(sibling_hash, log2_size);
        }
        sliced.set_root_hash(&hash);
        sliced.set_target_address((self.get_target_address() >> new_log2_target_size) << new_log2_target_size);
        if !sliced.verify(h) {
            panic!("produced invalid sliced proof");
        }
        return sliced;
    }

    fn log2_size_to_index(&self, log2_size: isize) -> isize {
        let index: isize = self.m_log2_root_size - 1 - log2_size;
        if index < 0 || index >= self.m_sibling_hashes.len() as isize {
            panic!("log2_size is out of range");
        }
        return index;
    }

}

impl PartialEq for MerkleTreeProof {
    fn eq(&self, other: &Self) -> bool {
        if self.get_log2_target_size() != other.get_log2_target_size() {
            return false;
        }
        if self.get_log2_root_size() != other.get_log2_root_size() {
            return false;
        }
        if self.get_target_address() != other.get_target_address() {
            return false;
        }
        if self.get_root_hash() != other.get_root_hash() {
            return false;
        }
        if self.get_target_hash() != other.get_target_hash() {
            return false;
        }
        if self.m_sibling_hashes != other.m_sibling_hashes {
            return false;
        }
        return true;
    }
}