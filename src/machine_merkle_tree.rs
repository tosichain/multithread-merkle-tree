use crate::pristine_merkle_tree::PristineMerkleTree;
use crate::merkle_tree_proof::MerkleTreeProof;

use std::ops::{DerefMut, Deref};
use std::sync::{Arc, Mutex};

use std::{cmp, ptr};
use std::collections:: VecDeque;
use std::alloc::{dealloc, Layout};
use sha3::Digest;
use std::collections::BTreeMap;

type AddressType = u64;
type HashType = Box<Vec<u8>>;
type HasherType = sha3::Keccak256;
type ProofType = MerkleTreeProof;


const LOG2_ROOT_SIZE: isize = 64;
const LOG2_WORD_SIZE: isize = 3;
const LOG2_PAGE_SIZE: isize = 12;
const M_PAGE_INDEX_MASK: AddressType = ((!0u64) >> (64 - LOG2_ROOT_SIZE)) << LOG2_PAGE_SIZE;
const M_PAGE_OFFSET_MASK: AddressType = !M_PAGE_INDEX_MASK;

#[derive(Default, Debug)]
pub struct MachineMerkleTree{

    m_page_node_map: BTreeMap<AddressType, Arc<Mutex<TreeNode>>>,
    pub m_root_storage: MRootStorage,

    #[cfg(feature = "merkle_dump_stats")]
    m_num_nodes: u64,    

    m_root: Option<Arc<Mutex<TreeNode>>>,

    m_merkle_update_nonce: u64,

    m_merkle_update_fifo: VecDeque<(isize, Arc<Mutex<TreeNode>>)>,

}
#[derive(Default, Debug)]

pub struct  MRootStorage {
    pub m_root_storage: Option<Arc<Mutex<TreeNode>>>,
    m_storage_mem: usize, 
}
impl MRootStorage {
    pub fn destroy_merkle_tree(&mut self) {
        self.destroy_merkle_tree_node(self.m_root_storage.as_ref().unwrap().lock().unwrap().child.as_ref().unwrap().get(0), MachineMerkleTree::get_log2_root_size() - 1);
        self.destroy_merkle_tree_node(self.m_root_storage.as_ref().unwrap().lock().unwrap().child.as_ref().unwrap().get(1), MachineMerkleTree::get_log2_root_size() - 1);
        let storage = std::mem::size_of_val(&self.m_root_storage.as_ref());
        self.m_root_storage.as_mut().unwrap().lock().unwrap().hash[0..std::mem::size_of_val(&storage.clone())].fill(0);
       }

       fn destroy_merkle_tree_node(&self, node: Option<&Arc<Mutex<TreeNode>>>, log2_size: isize) {
        if node.is_some() {
            if log2_size > MachineMerkleTree::get_log2_page_size() &&  (*(*(*(node.as_ref().unwrap())))).lock().unwrap().child.as_ref().is_some(){
                self.destroy_merkle_tree_node(Some(&(*(*(*(node.as_ref().unwrap())))).lock().unwrap().child.as_ref().unwrap()[0]), log2_size - 1);
                self.destroy_merkle_tree_node(Some(&(*(*(*(node.as_ref().unwrap())))).lock().unwrap().child.as_ref().unwrap()[1]), log2_size - 1);
               
            }
            
            #[cfg(feature = "merkle_dump_stats")]
            {
                self.m_num_nodes -= 1;
            }
            drop(node.unwrap());         
        }
    }

    fn destroy_node(&mut self, node: *mut Box<TreeNode>) {

        #[cfg(feature = "merkle_dump_stats")]
        {
            self.m_num_nodes -= 1;
        }

        unsafe {
            ptr::drop_in_place(node);
            dealloc(node as *mut u8, Layout::new::<TreeNode>());
        }
    }
}


#[derive(Default, Debug, Clone)]
pub struct TreeNode{
    hash: HashType,               
    parent: Option<Arc<Mutex<TreeNode>>>,                
    pub child: Option<Vec<Arc<Mutex<TreeNode>>>>, 
    mark: u64,               
}


impl <'a> MachineMerkleTree {

    fn pristine_hashes() -> PristineMerkleTree {
        let mut tree: PristineMerkleTree = Default::default();
        tree.pristine_merkle_tree(MachineMerkleTree::get_log2_root_size(), MachineMerkleTree::get_log2_word_size());
        return tree;
    }

    const fn get_log2_root_size() -> isize{
        return LOG2_ROOT_SIZE;
    }

    const fn get_log2_word_size() -> isize{
        return LOG2_WORD_SIZE;
    }

    fn get_page_index(address: AddressType) -> AddressType {
        return address & M_PAGE_INDEX_MASK;
    }

    const fn get_log2_page_size() -> isize{
        return LOG2_PAGE_SIZE;
    }

    fn get_page_node(&mut self, page_index: AddressType) -> Option<Arc<Mutex<TreeNode>>> {
        if self.m_page_node_map.last_key_value().is_none() {
            return None;
        }
        let it: Option<&Arc<Mutex<TreeNode>>> = self.m_page_node_map.get(&page_index);

        if it.is_some() {
            return Some(Arc::clone(it.unwrap()));
        } else {
            return None;
        }
    }

    fn get_offset_in_page(address: AddressType) -> AddressType {
        return address & M_PAGE_OFFSET_MASK;
    }

    fn set_page_node_map(&mut self, page_index: AddressType, node: Arc<Mutex<TreeNode>>) -> isize {
        self.m_page_node_map.insert(page_index, node);
        return 1;
    }

    fn create_node(&mut self) -> Option<Arc<Mutex<TreeNode>>>{


        #[cfg(feature = "merkle_dump_stats")]
        {
            self.m_num_nodes += 1;
        }
        return Some(Arc::new(Mutex::new(Default::default())));
    }


    fn new_page_node(&mut self, page_index: AddressType) -> Option<Arc<Mutex<TreeNode>>> {

        unsafe {let mut bit_mask: AddressType = (1u64) << (MachineMerkleTree::get_log2_root_size() - 1);
        let mut node = self.m_root.clone();
        let mut child: Option<Arc<Mutex<TreeNode>>> = None;
        while true {
            let bit: isize = ((page_index & bit_mask) != 0) as isize;

            if (*node.as_ref().unwrap().clone()).lock().unwrap().child.is_none() || Arc::as_ptr((*node.as_ref().unwrap().clone()).lock().unwrap().child.as_ref().unwrap().get(bit as usize).unwrap()).is_null(){

                child = self.create_node();
                if child.is_none() {
                    return None;
                }

                (*(*child.as_mut().unwrap())).lock().unwrap().parent = Some(Arc::clone(node.as_ref().unwrap()));
                {
                    (*(*node.as_mut().unwrap())).lock().unwrap().child = Some(vec![Arc::new(Mutex::new(Default::default()));2]);
                }
                {
                    (*node.as_mut().as_mut().unwrap()).lock().unwrap().child.as_mut().unwrap().push(Arc::clone(child.as_ref().unwrap()));
                }
                {
                    (*node.as_mut().unwrap()).lock().unwrap().child.as_mut().unwrap().swap(bit as usize, 2);
                }
                {
                    (*node.as_mut().unwrap()).lock().unwrap().child.as_mut().unwrap().swap_remove(2);
                }
            }
            else {
                child = (*node.unwrap()).lock().unwrap().child.as_ref().unwrap().get(bit as usize).cloned();
            }
        
            node = child.clone();

            bit_mask >>= 1;
            
            if (bit_mask & M_PAGE_INDEX_MASK) == 0 {
                break;
            }
        }
        if self.set_page_node_map(page_index, Arc::clone(node.as_ref().unwrap())) != 1 {

            return None;
        }
        

        return node;
    }
    }

    fn get_page_node_hash_start(&self, h: &mut HasherType, start: *const u8, log2_size: isize, hash: &mut HashType) {
        let mut log2_size = log2_size;
        if log2_size > MachineMerkleTree::get_log2_word_size() {
            let mut child0: HashType = Default::default();
            let mut child1: HashType = Default::default();
            log2_size -= 1;
            let size: AddressType = 1u64 << log2_size;
            self.get_page_node_hash_start(h, start, log2_size, &mut child0);
            unsafe {
                 self.get_page_node_hash_start(h, start.add(size as usize), log2_size, &mut child1);
            }
            h.reset();
            h.update(child0.as_slice());
            h.update(child1.as_slice());
            *hash = Box::new(h.clone().finalize().as_slice().to_vec());
        } else {
            h.reset();
            unsafe {
                h.update([*start]);
            }
            *hash = Box::new(h.clone().finalize().as_slice().to_vec());
        }
    }

    pub fn get_page_node_hash(&self, h: &mut HasherType, page_data: *mut u8, hash: &mut HashType) {
        unsafe {
           if *page_data != 0 {
            self.get_page_node_hash_start(h, page_data, MachineMerkleTree::get_log2_page_size(), hash);
            } else {
                *hash = MachineMerkleTree::get_pristine_hash(MachineMerkleTree::get_log2_page_size()).clone();
            } 
        }
    }

    pub fn get_page_node_hash_address(&mut self, page_index: AddressType, hash: &mut HashType) {
        assert!(page_index == MachineMerkleTree::get_page_index(page_index));
        let node:Option<Arc<Mutex<TreeNode>>> = self.get_page_node(page_index);
            if node.is_none() {
            *hash = MachineMerkleTree::get_pristine_hash(MachineMerkleTree::get_log2_page_size()).clone();
        } else {
            *hash = (*node.unwrap()).lock().unwrap().hash.clone();
        }
        
    }
    
    fn get_child_hash(&self, child_log2_size: isize, node: Arc<Mutex<TreeNode>>,
        bit: isize) -> HashType{
            let node = (*node).lock().unwrap();
            let binding = node.child.as_ref().unwrap();
            
            let child: Option<&Arc<Mutex<TreeNode>>> = binding.get(bit as usize);
            if child.is_some() {
                return (*(*child.unwrap())).lock().unwrap().hash.clone();
            }
        return MachineMerkleTree::get_pristine_hash(child_log2_size).clone();
    }

    fn update_inner_node_hash(&self, h: &mut HasherType, log2_size: isize, node: Arc<Mutex<TreeNode>>) {
        h.reset();
        h.update(self.get_child_hash(log2_size - 1, Arc::clone(&node), 0).as_slice());
        h.update(self.get_child_hash(log2_size - 1, Arc::clone(&node), 1).as_slice());
        Arc::clone(&node).lock().unwrap().hash = Box::new(h.clone().finalize().to_vec());
    }

    fn dump_hash(hash: &HashType) {
        for &b in hash.iter() {
            let hex_string = hex::encode(vec![b]);
            eprint!("{}", hex_string);
        };
        eprintln!();
    }

    fn get_pristine_hash(log2_size: isize) -> HashType{
        return MachineMerkleTree::pristine_hashes().get_hash(log2_size).clone();
    } 

    fn dump_merkle_tree(&self, node: Option<&Arc<Mutex<TreeNode>>>, address: u64, log2_size: isize) {
        for i in 0..MachineMerkleTree::get_log2_root_size() - log2_size {
            eprint!(" ");
        }

        eprint!("0x{} : {} ", format!("{:0>16}", hex::encode(vec![address as u8])), format!("{:0>2}", log2_size));
        unsafe {if node.is_some()  {
            
            MachineMerkleTree::dump_hash(&(*(*node.unwrap())).lock().unwrap().hash);
            if log2_size > MachineMerkleTree::get_log2_page_size() && (*(*node.unwrap())).lock().unwrap().child.as_ref().is_some(){    
                {        
                    self.dump_merkle_tree((*(*node.unwrap())).lock().unwrap().child.as_ref().unwrap().get(0), address, log2_size - 1);
                }
                {
                    self.dump_merkle_tree((*(*node.unwrap())).lock().unwrap().child.as_ref().unwrap().get(1), address + (1u64 << (log2_size - 1)), log2_size - 1);
                }               
            }
        
            } else {
                eprintln!("null");
            }
        }
    }


    fn get_inside_page_sibling_hashes_h(&self, h: &mut HasherType, address: AddressType, log2_size: isize,
        mut hash: &'a mut HashType, curr_data:*mut u8, log2_curr_size: isize, curr_hash: &'a mut HashType, parent_diverged: isize,
        curr_diverged: isize, proof: &mut ProofType) {

        if log2_curr_size > MachineMerkleTree::get_log2_word_size() {
            let log2_child_size: isize = log2_curr_size - 1;
            let child_size: AddressType = 1u64 << log2_child_size;
            let mut first_hash: HashType = Default::default();
            let mut second_hash: HashType = Default::default();
            let child_bit: isize = ((address & child_size) != 0) as isize;
            self.get_inside_page_sibling_hashes_h(h, address, log2_size, hash, curr_data, log2_child_size, &mut first_hash,
                (parent_diverged != 0 || curr_diverged != 0) as isize, (child_bit != 0) as isize, proof);
            self.get_inside_page_sibling_hashes_h(h, address, log2_size, hash, (curr_data as u8 + child_size as u8) as *mut u8, log2_child_size,
                &mut second_hash, (parent_diverged != 0 || curr_diverged != 0) as isize, (child_bit != 1) as isize, proof);
            h.reset();
            h.update(first_hash.as_slice());
            h.update(second_hash.as_slice());
            *curr_hash = Box::new(h.clone().finalize().as_slice().to_vec());
        } else {
            unsafe {
                h.reset();
                h.update([*curr_data.as_ref().unwrap()]);
                *curr_hash = Box::new(h.clone().finalize().as_slice().to_vec());
            }
        }
        if parent_diverged == 0{
            if curr_diverged != 0 && log2_curr_size >= proof.get_log2_target_size() {
                proof.set_sibling_hash(curr_hash, log2_curr_size);
            } else if log2_curr_size == log2_size {
                hash = curr_hash;
            }
        } 
    }

    fn get_inside_page_sibling_hashes(&self, address: AddressType, log2_size: isize, hash: &mut HashType,
        page_data: *mut u8, page_hash: &mut HashType, proof: &mut ProofType) {
        let mut h: HasherType = Default::default();
        self.get_inside_page_sibling_hashes_h(&mut h, address, log2_size, hash, page_data, MachineMerkleTree::get_log2_page_size(), page_hash,
            0, 0, proof);
    }

    pub fn dump_merkle_tree_empty(&self) {
        self.dump_merkle_tree(Some(self.m_root.as_ref().unwrap()), 0, MachineMerkleTree::get_log2_root_size());
    }

    pub fn begin_update(&mut self) -> bool {
        self.m_merkle_update_fifo.clear();
        return true;
    }

    pub fn update_page_node_hash(&mut self, page_index: AddressType, hash: &HashType) -> bool{
        assert!(MachineMerkleTree::get_page_index(page_index) == page_index);
        let mut node = self.get_page_node(page_index);
        if node.is_none() {
            node = self.new_page_node(page_index);
        }
        if node.is_none() {
           return false;
        }
        (*node.as_mut().unwrap()).lock().unwrap().hash = hash.clone();
        if (*node.as_ref().unwrap()).lock().unwrap().parent.is_some() && (*(*node.as_ref().unwrap()).lock().unwrap().parent.as_ref().unwrap()).lock().unwrap().mark != self.m_merkle_update_nonce {
            {
                (*(*node.as_ref().unwrap()).lock().unwrap().parent.as_ref().unwrap()).lock().unwrap().mark = self.m_merkle_update_nonce;
            }
            &self.m_merkle_update_fifo.push_back((MachineMerkleTree::get_log2_page_size() + 1, Arc::clone((*node.as_ref().unwrap()).lock().unwrap().parent.as_ref().unwrap())));

    }
        return true;
    }

    pub fn end_update(&mut self, h: &mut HasherType) -> bool {
        while !&self.m_merkle_update_fifo.is_empty() {
            let (log2_size, node) = self.m_merkle_update_fifo.front().unwrap().clone();
            self.update_inner_node_hash(h, log2_size, Arc::clone(&node));
            self.m_merkle_update_fifo.pop_front();
            if (*node.as_ref()).lock().unwrap().parent.is_some() && (*(*node).lock().unwrap().parent.as_ref().unwrap()).lock().unwrap().mark != self.m_merkle_update_nonce {
                {
                    self.m_merkle_update_fifo.push_back((log2_size.clone() + 1, Arc::clone((*node).lock().unwrap().parent.as_ref().unwrap())));
                }
                (*(*node).lock().unwrap().parent.as_mut().unwrap()).lock().unwrap().mark = self.m_merkle_update_nonce;
            }
        }
        self.m_merkle_update_nonce += 1;
        return true;
    }

    pub fn machine_merkle_tree_initialization(&mut self) {
    self.m_root_storage = MRootStorage{
        m_root_storage: Some(Default::default()),
        m_storage_mem: std::mem::size_of_val(&self.m_root_storage),
    };
    self.m_root = Some(Arc::clone(self.m_root_storage.m_root_storage.as_ref().unwrap()));
    self.m_merkle_update_nonce = 1;
    (*self.m_root.as_mut().unwrap()).lock().unwrap().hash = MachineMerkleTree::get_pristine_hash(MachineMerkleTree::get_log2_root_size()).clone();

        #[cfg(feature = "merkle_dump_stats")]
        {
            self.m_num_nodes = 0;
        }
    }

    pub fn machine_merkle_tree(&mut self) {

        #[cfg(feature = "merkle_dump_stats")] {
        eprintln!("before destruction");
        eprintln!("  number of tree nodes:     {}", self.m_num_nodes);
        }

        self.m_root_storage.destroy_merkle_tree();
        self.m_root_storage.m_root_storage.as_mut().unwrap().lock().unwrap().hash[0..self.m_root_storage.m_storage_mem].fill(0);

        #[cfg(feature = "merkle_dump_stats")] {
        eprintln!("after destruction");
        eprintln!("  number of tree nodes:     {}", self.m_num_nodes);
        }

    }

    pub fn get_root_hash(&self, hash: &mut HashType) {
        *hash = (*self.m_root.as_ref().unwrap().clone()).lock().unwrap().hash.clone();
    }

    pub fn verify_tree(&self) -> bool {
        let mut h: HasherType = Default::default(); 
        return self.verify_tree_with_arguments(&mut h, self.m_root.as_ref().unwrap(), MachineMerkleTree::get_log2_root_size());
    }

    fn verify_tree_with_arguments(&self, h: &mut HasherType, node: &Arc<Mutex<TreeNode>>, log2_size: isize) -> bool {
           if (*node).lock().unwrap().hash.is_empty() {
                return true;
            }
        
             if log2_size > MachineMerkleTree::get_log2_page_size() {
                let child_log2_size: isize = log2_size - 1;
                let mut first_ok: bool;
                {
                    first_ok = self.verify_tree_with_arguments(h, &node.lock().unwrap().child.as_ref().unwrap()[0], child_log2_size);
                }
                let second_ok = self.verify_tree_with_arguments(h, &node.lock().unwrap().child.as_ref().unwrap()[1], child_log2_size);
                if !first_ok || !second_ok {
                    return false;
                }
                let mut hash: HashType = Default::default();
                h.reset();
                h.update(self.get_child_hash(child_log2_size, node.clone(), 0).as_slice());
                h.update(self.get_child_hash(child_log2_size, node.clone(), 1).as_slice());
                hash = Box::new(h.clone().finalize().to_vec());
                return hash.eq(&(*node).lock().unwrap().hash);
            } else {
                return true;
            }
    }

    fn get_proof(&self, target_address: AddressType, log2_target_size: isize,
        page_data: u8) -> ProofType {

        if log2_target_size > MachineMerkleTree::get_log2_root_size() || log2_target_size < MachineMerkleTree::get_log2_word_size() {
            panic!("log2_target_size is out of bounds");
        }
    
        if (target_address & ((!0u64) >> (MachineMerkleTree::get_log2_root_size() - log2_target_size))) != 0 {
            panic!("misaligned target address");
        }
    
        let mut proof: ProofType = Default::default();
        proof.merkle_tree_proof(MachineMerkleTree::get_log2_root_size(), log2_target_size);
    
        let log2_stop_size: isize = cmp::max(log2_target_size, MachineMerkleTree::get_log2_page_size());
        let mut log2_node_size: isize = MachineMerkleTree::get_log2_root_size();
        let mut node: Option<Arc<Mutex<TreeNode>>> = self.m_root.clone();
            while !(*node.as_ref().unwrap()).lock().unwrap().hash.is_empty() && log2_node_size > log2_stop_size {
                let log2_child_size: isize = log2_node_size - 1;
                let path_bit: isize = ((target_address & 1u64 << (log2_child_size)) != 0) as isize;
                proof.set_sibling_hash(&self.get_child_hash(log2_child_size, Arc::clone(node.as_ref().unwrap()), !path_bit), log2_child_size);
                node = Some(Arc::clone(&(*node.unwrap()).lock().unwrap().child.as_ref().unwrap()[path_bit as usize]));
                log2_node_size = log2_child_size;
            }
        
        if (*node.as_ref().unwrap()).lock().unwrap().hash.is_empty() {
            if page_data != 0 {
                panic!("inconsistent merkle tree");
            }
            let mut i: isize = log2_node_size - 1;
            while i >= log2_target_size {
                proof.set_sibling_hash(&MachineMerkleTree::get_pristine_hash(i), i);
                i -= 1;   
            }
            proof.set_target_hash(&MachineMerkleTree::get_pristine_hash(log2_target_size));

        } else if log2_node_size == MachineMerkleTree::get_log2_page_size() {
            assert!(!(*node.as_ref().unwrap()).lock().unwrap().hash.is_empty());
            let mut page_hash: HashType = Default::default();
            if log2_target_size < MachineMerkleTree::get_log2_page_size() {

                if page_data != 0 {
                    let mut th =  proof.get_target_hash().clone();
                    self.get_inside_page_sibling_hashes(target_address, log2_target_size,&mut th, page_data as *mut u8,
                        &mut page_hash, &mut proof);
                } else {
                    page_hash = MachineMerkleTree::get_pristine_hash(MachineMerkleTree::get_log2_page_size());
                    let mut i: isize = MachineMerkleTree::get_log2_page_size() - 1;
                    while i >= log2_target_size {
                        proof.set_sibling_hash(&MachineMerkleTree::get_pristine_hash(i), i);
                        i -= 1;
                    }
                    proof.set_target_hash(&MachineMerkleTree::get_pristine_hash(log2_target_size));
                }
                if !(*node.as_ref().unwrap()).lock().unwrap().hash.eq(&page_hash) {
                    panic!("inconsistent merkle tree");
                }

            } else {
                proof.set_target_hash(&(*node.as_ref().unwrap()).lock().unwrap().hash);
            }
        } else {
            assert!(!(*node.as_ref().unwrap()).lock().unwrap().hash.is_empty() && log2_node_size == log2_target_size);
            proof.set_target_hash(&(*node.as_ref().unwrap()).lock().unwrap().hash);
        }
    
        proof.set_target_address(target_address);
        proof.set_root_hash(&(*(*self.m_root.as_ref().unwrap())).lock().unwrap().hash); 

        #[cfg(not(feature = "ndebug"))]
        if !proof.verify(&mut HasherType::new()) {
            panic!("proof failed verification");
        }

        return proof;
    }

}