use crate::pristine_merkle_tree::PristineMerkleTree;
use crate::merkle_tree_proof::MerkleTreeProof;

use std::ops::DerefMut;
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

pub struct MachineMerkleTree<'b> {

    m_page_node_map: BTreeMap<AddressType, &'b mut Box<TreeNode<'b>>>,
    m_root_storage: Option<Box<TreeNode<'b>>>,

    #[cfg(feature = "merkle_dump_stats")]
    m_num_nodes: u64,    

    m_root: Option<&'b mut Box<TreeNode<'b>>>,

    m_merkle_update_nonce: u64,

    m_merkle_update_fifo: VecDeque<(isize, &'b mut Box<TreeNode<'b>>)>,

}

#[derive(Default, Clone)]
pub struct TreeNode<'a>{
    hash: HashType,               
    parent: Option<Box<TreeNode<'a>>>,                
    child: Option<[&'a Box<TreeNode<'a>>;2]>, 
    mark: u64,               
}


impl<'b> MachineMerkleTree<'b> {

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

    fn get_page_node(&mut self, page_index: AddressType) -> Option<&'b mut Box<TreeNode>> {
        let compare = self.m_page_node_map.last_key_value().unwrap().0.clone();
        let it: Option<&mut &mut Box<TreeNode>> = self.m_page_node_map.get_mut(&page_index);
        if page_index != compare {
            return Some(it.unwrap());
        } else {
            return None;
        }
    }

    fn get_offset_in_page(address: AddressType) -> AddressType {
        return address & M_PAGE_OFFSET_MASK;
    }

    fn set_page_node_map(&mut self, page_index: AddressType, node: &'b mut Box<TreeNode<'b>>) -> isize {

        self.m_page_node_map.insert(page_index, node);
        return 1;

    }

    fn create_node(&mut self) -> Option<&'b mut Box<TreeNode<'b>>>{

        #[cfg(feature = "merkle_dump_stats")]
        {
            self.m_num_nodes += 1;
        }

        return None;
    }

    fn destroy_node(&mut self, node: *mut TreeNode) {

        #[cfg(feature = "merkle_dump_stats")]
        {
            self.m_num_nodes -= 1;
        }

        unsafe {
            ptr::drop_in_place(node);
            dealloc(node as *mut u8, Layout::new::<TreeNode>());
        }
    }

    fn new_page_node(&'b mut self, page_index: AddressType) -> Option<&'b mut Box<TreeNode<'b>>> {

        let mut bit_mask: AddressType = (1u64) << (MachineMerkleTree::get_log2_root_size() - 1);
        let mut node: Option<&'b mut Box<TreeNode<'b>>> = Default::default();
        while true {
            let bit: isize = ((page_index & bit_mask) != 0) as isize;
            let mut child: Option<&'b mut Box<TreeNode<'b>>> = None;

            if self.m_root.as_ref().unwrap().child.as_ref().unwrap().get(bit as usize).is_none() {
                child = self.create_node();
                if child.is_none() {
                    return None;
                }
                child.as_mut().unwrap().parent = Some(Box::new(*(*node.as_ref().unwrap().clone()).clone()));
                node.unwrap().child.unwrap()[bit as usize] = child.as_ref().unwrap().clone();
            }
            node = child;
            bit_mask >>= 1;
            if (bit_mask & M_PAGE_INDEX_MASK) == 0 {
                break;
            }
        }
        /*if !self.set_page_node_map(page_index, node.as_mut().unwrap()) != 1 {
            return None;
        }*/
        return node;
    }

    fn get_page_node_hash_start(&self, h: &mut HasherType, start: u8, log2_size: isize, hash: &mut HashType) {
        if log2_size > MachineMerkleTree::get_log2_word_size() {
            let mut child0: HashType = Default::default();
            let mut child1: HashType = Default::default();
            --log2_size;
            let size: AddressType = 1u64 << log2_size;
            self.get_page_node_hash_start(h, start, log2_size, &mut child0);
            self.get_page_node_hash_start(h, start  + size as u8, log2_size, &mut child1);
            h.reset();
            h.update(child0.as_slice());
            h.update(child1.as_slice());
            *hash = Box::new(h.clone().finalize().as_slice().to_vec());
        } else {
            h.reset();
            h.update([start]);
            *hash = Box::new(h.clone().finalize().as_slice().to_vec());
        }
    }

    fn get_page_node_hash(&self, h: &mut HasherType, page_data: u8, hash: &mut HashType) {
        if page_data != 0 {
            self.get_page_node_hash_start(h, page_data, MachineMerkleTree::get_log2_page_size(), hash);
        } else {
            *hash = MachineMerkleTree::get_pristine_hash(MachineMerkleTree::get_log2_page_size()).clone();
        }
    }

    fn get_page_node_hash_address(&'b self, page_index: AddressType, hash: &mut HashType) {
        assert!(page_index == MachineMerkleTree::get_page_index(page_index));
        let node:Option<&mut Box<TreeNode<'b>>> = self.get_page_node(page_index);
            if node.is_none() {
            *hash = MachineMerkleTree::get_pristine_hash(MachineMerkleTree::get_log2_page_size()).clone();
        } else {
            *hash = node.unwrap().hash.clone();
        }
        
    }
    
    fn get_child_hash(&self, child_log2_size: isize, node: &TreeNode,
        bit: isize) -> HashType{
        let binding = node.child.unwrap();
        let child: Option<&&Box<TreeNode>> = binding.get(bit as usize);
        if child.is_some() {
            return child.unwrap().hash.clone();
        }
        return MachineMerkleTree::get_pristine_hash(child_log2_size).clone();
    }

    fn update_inner_node_hash(&self, h: &mut HasherType, log2_size: isize, node: &mut TreeNode) {
        h.reset();
        h.update(self.get_child_hash(log2_size - 1, &node, 0).as_slice());
        h.update(self.get_child_hash(log2_size - 1, &node, 1).as_slice());
        node.hash = Box::new(h.clone().finalize().to_vec());
    }

    fn dump_hash(hash: &HashType) {
        for &b in hash.iter() {
            let hex_string = hex::encode(format!("{:0>2}", b as isize));
            eprint!("{}", hex_string);
        };
        eprintln!();
    }

    fn get_pristine_hash(log2_size: isize) -> HashType{
        return MachineMerkleTree::pristine_hashes().get_hash(log2_size).clone();
    } 

    fn dump_merkle_tree(&self, node: Option<&Box<TreeNode>>, address: u64, log2_size: isize) {
        for i in 0..MachineMerkleTree::get_log2_root_size() - log2_size {
            eprint!("");
        }

        eprint!("0x{} : {} ", format!("{:0>16}", hex::encode(address.to_string())), format!("{:0>2}", log2_size as f64));

        if node.is_some() {
            MachineMerkleTree::dump_hash(&node.unwrap().hash);
            if log2_size > MachineMerkleTree::get_log2_page_size() {
                self.dump_merkle_tree(Some(&node.unwrap().child.unwrap()[0]), address, log2_size - 1);
                self.dump_merkle_tree(Some(&node.unwrap().child.unwrap()[1]), address + (1u64 << (log2_size - 1)), log2_size - 1);
            }
        } else {
            eprintln!();
        }
    }

    fn destroy_merkle_tree_node(&mut self, node: Option<TreeNode>, log2_size: isize) {
        if node.is_some() {
            if log2_size > MachineMerkleTree::get_log2_page_size() {
                self.destroy_merkle_tree_node(Some(*node.as_ref().unwrap().child.unwrap()[0].clone()), log2_size - 1);
                self.destroy_merkle_tree_node(Some(*node.as_ref().unwrap().child.unwrap()[1].clone()), log2_size - 1);
            }
            self.destroy_node(&mut node.unwrap() as *mut TreeNode);
        }
    }

    fn destroy_merkle_tree(&mut self) {
        self.destroy_merkle_tree_node(Some(*self.m_root_storage.as_ref().unwrap().child.unwrap()[0].clone()), MachineMerkleTree::get_log2_root_size() - 1);
        self.destroy_merkle_tree_node(Some(*self.m_root_storage.as_ref().unwrap().child.unwrap()[1].clone()), MachineMerkleTree::get_log2_root_size() - 1);
        let storage = &self.m_root_storage.clone();
        self.m_root_storage.as_mut().unwrap().hash[0..std::mem::size_of_val(storage)].fill(0);
    }

    fn get_inside_page_sibling_hashes_h(&self, h: &mut HasherType, address: AddressType, log2_size: isize,
        hash: &mut HashType, curr_data:*mut u8, log2_curr_size: isize, curr_hash: &mut HashType, parent_diverged: isize,
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
                h.update([*curr_data.as_mut().unwrap()]);
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
        self.get_inside_page_sibling_hashes_h(&mut h, address, log2_size, &mut hash, page_data, MachineMerkleTree::get_log2_page_size(), &mut page_hash,
            0, 0, &mut proof);
    }

    fn dump_merkle_tree_empty(&self) {
        self.dump_merkle_tree(Some(self.m_root.as_ref().unwrap()), 0, MachineMerkleTree::get_log2_root_size());
    }

    fn begin_update(&mut self) -> bool {
        self.m_merkle_update_fifo.clear();
        return true;
    }

    fn update_page_node_hash(&'b mut self, page_index: AddressType, hash: &HashType) -> bool{
        assert!(MachineMerkleTree::get_page_index(page_index) == page_index);
        let mut node: Option<&mut Box<TreeNode>> = self.get_page_node(page_index);
        let mut node: Option<&&mut Box<TreeNode>>;
        match &self.get_page_node(page_index) {
            Some (e) => node = Some(e),
            None => {
                let node_cur = self.new_page_node(page_index);
                if node_cur.is_none() {
                    return false;
                }
                node = Some(&&node_cur.unwrap());
            },
        }
        
        let mut node = node.unwrap();
        node.hash = hash.clone();
        if !node.parent.unwrap().hash.is_empty() && node.parent.unwrap().mark != self.m_merkle_update_nonce {
            &self.m_merkle_update_fifo.push_back((MachineMerkleTree::get_log2_page_size() + 1, &mut node.parent.unwrap()));
            node.parent.unwrap().mark = self.m_merkle_update_nonce;
        }
        return true;
    }

    fn end_update(&mut self, h: &mut HasherType) -> bool {
        while !&self.m_merkle_update_fifo.is_empty() {
            let (log2_size, node) = self.m_merkle_update_fifo.front().unwrap();
            //let mut node = &*node.clone();
            self.update_inner_node_hash(h, *log2_size, node.clone().as_mut());
            self.m_merkle_update_fifo.pop_front();
            if !node.parent.unwrap().hash.is_empty() && node.parent.unwrap().mark != self.m_merkle_update_nonce {
                self.m_merkle_update_fifo.push_back((log2_size + 1, &mut node.parent.unwrap()));
                node.parent.unwrap().mark = self.m_merkle_update_nonce;
            }
        }
        self.m_merkle_update_nonce += 1;
        return true;
    }

    fn machine_merkle_tree_initialization(&'b mut self) {
    self.m_root_storage = None;
    self.m_root = Some(self.m_root_storage.as_mut().unwrap());
    self.m_merkle_update_nonce = 1;
    self.m_root.as_mut().unwrap().hash = MachineMerkleTree::get_pristine_hash(MachineMerkleTree::get_log2_root_size()).clone();

        #[cfg(feature = "merkle_dump_stats")]
        {
            self.m_num_nodes = 0;
        }
    }

    fn machine_merkle_tree(&mut self) {

        #[cfg(feature = "merkle_dump_stats")] {
        eprintln!("before destruction");
        eprintln!("  number of tree nodes:     {}", self.m_num_nodes);
        }

        self.destroy_merkle_tree();

        #[cfg(feature = "merkle_dump_stats")] {
        eprintln!("after destruction");
        eprintln!("  number of tree nodes:     {}", self.m_num_nodes);
        }

    }

    fn get_root_hash(&self, hash: &mut HashType) {
        *hash = self.m_root.as_ref().unwrap().hash.clone();
    }

    fn verify_tree(&self) -> bool {
        let mut h: HasherType = Default::default(); 
        return self.verify_tree_with_arguments(&mut h, &self.m_root.as_ref().unwrap(), MachineMerkleTree::get_log2_root_size());
    }

    fn verify_tree_with_arguments(&self, h: &mut HasherType, node: &Box<TreeNode>, log2_size: isize) -> bool {
        if node.hash.is_empty() {
            return true;
        }
        if log2_size > MachineMerkleTree::get_log2_page_size() {
            let child_log2_size: isize = log2_size - 1;
            let first_ok = self.verify_tree_with_arguments(h, &node.child.unwrap()[0], child_log2_size);
            let second_ok = self.verify_tree_with_arguments(h, &node.child.unwrap()[1], child_log2_size);
            if !first_ok || !second_ok {
                return false;
            }
            let mut hash: HashType = Default::default();
            h.reset();
            h.update(self.get_child_hash(child_log2_size, &node, 0).as_slice());
            h.update(self.get_child_hash(child_log2_size, &node, 1).as_slice());
            hash = Box::new(h.clone().finalize().to_vec());
            return hash.eq(&node.hash);
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
        let mut node: &Box<TreeNode> = &self.m_root.as_ref().unwrap();
        while !node.hash.is_empty() && log2_node_size > log2_stop_size {
            let log2_child_size: isize = log2_node_size - 1;
            let path_bit: isize = ((target_address & 1u64 << (log2_child_size)) != 0) as isize;
            proof.set_sibling_hash(&self.get_child_hash(log2_child_size, &node, !path_bit), log2_child_size);
            node = &node.child.unwrap()[path_bit as usize];
            log2_node_size = log2_child_size;
        }

        if node.hash.is_empty() {
            if page_data != 0 {
                panic!("inconsistent merkle tree");
            }
            let i: isize = log2_node_size - 1;
            while i >= log2_target_size {
                proof.set_sibling_hash(&MachineMerkleTree::get_pristine_hash(i), i);
                --i;   
            }
            proof.set_target_hash(&MachineMerkleTree::get_pristine_hash(log2_target_size));

        } else if log2_node_size == MachineMerkleTree::get_log2_page_size() {
            assert!(!node.hash.is_empty());
            let mut page_hash: HashType = Default::default();
            if log2_target_size < MachineMerkleTree::get_log2_page_size() {

                if page_data != 0 {
                    let mut th =  proof.get_target_hash().clone();
                    self.get_inside_page_sibling_hashes(target_address, log2_target_size,&mut th, page_data as *mut u8,
                        &mut page_hash, &mut proof);
                } else {
                    page_hash = Box::new(*MachineMerkleTree::get_pristine_hash(MachineMerkleTree::get_log2_page_size()).clone());
                    let i: isize = MachineMerkleTree::get_log2_page_size() - 1;
                    while i >= log2_target_size {
                        proof.set_sibling_hash(&MachineMerkleTree::get_pristine_hash(i), i);
                        --i;
                    }
                    proof.set_target_hash(&MachineMerkleTree::get_pristine_hash(log2_target_size));
                }
                if !node.hash.eq(&page_hash) {
                    panic!("inconsistent merkle tree");
                }

            } else {
                proof.set_target_hash(&node.hash);
            }
        } else {
            assert!(!node.hash.is_empty() && log2_node_size == log2_target_size);
            proof.set_target_hash(&node.hash);
        }
        proof.set_target_address(target_address);
        proof.set_root_hash(&self.m_root.as_ref().unwrap().hash); 

        #[cfg(not(feature = "ndebug"))]
        if !proof.verify(&mut HasherType::new()) {
            panic!("proof failed verification");
        }

        return proof;
    }

}

/*impl fmt::Display for HasherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let result = "";
        for b in self {
            result += format!(" {:0>2}", b);
        }
        write!(f, "{}", result)
    }
}*/