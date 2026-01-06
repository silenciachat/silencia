use crate::error::{MlsError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupId(pub Vec<u8>);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub id: Vec<u8>,
    pub public_key: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Group {
    id: GroupId,
    epoch: u64,
    members: HashMap<Vec<u8>, Member>,
    my_id: Vec<u8>,
}

impl Group {
    pub fn create(creator_id: Vec<u8>, creator_pk: Vec<u8>) -> Result<Self> {
        let group_id = GroupId(rand::random::<[u8; 32]>().to_vec());
        
        let mut members = HashMap::new();
        members.insert(
            creator_id.clone(),
            Member {
                id: creator_id.clone(),
                public_key: creator_pk,
            },
        );
        
        Ok(Self {
            id: group_id,
            epoch: 0,
            members,
            my_id: creator_id,
        })
    }
    
    pub fn id(&self) -> &GroupId {
        &self.id
    }
    
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    
    pub fn add_member(&mut self, member_id: Vec<u8>, public_key: Vec<u8>) -> Result<()> {
        if self.members.contains_key(&member_id) {
            return Err(MlsError::MemberExists);
        }
        
        self.members.insert(
            member_id.clone(),
            Member {
                id: member_id,
                public_key,
            },
        );
        
        self.epoch += 1;
        Ok(())
    }
    
    pub fn remove_member(&mut self, member_id: &[u8]) -> Result<()> {
        if !self.members.contains_key(member_id) {
            return Err(MlsError::MemberNotFound);
        }
        
        if member_id == self.my_id.as_slice() {
            return Err(MlsError::CannotRemoveSelf);
        }
        
        self.members.remove(member_id);
        self.epoch += 1;
        Ok(())
    }
    
    pub fn rekey(&mut self) -> Result<()> {
        self.epoch += 1;
        Ok(())
    }
    
    pub fn member_count(&self) -> usize {
        self.members.len()
    }
    
    pub fn members(&self) -> Vec<&Member> {
        self.members.values().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_group_creation() {
        let group = Group::create(vec![1, 2, 3], vec![4, 5, 6]).unwrap();
        assert_eq!(group.epoch(), 0);
        assert_eq!(group.member_count(), 1);
    }
    
    #[test]
    fn test_add_member() {
        let mut group = Group::create(vec![1], vec![2]).unwrap();
        group.add_member(vec![3], vec![4]).unwrap();
        
        assert_eq!(group.member_count(), 2);
        assert_eq!(group.epoch(), 1);
    }
    
    #[test]
    fn test_remove_member() {
        let mut group = Group::create(vec![1], vec![2]).unwrap();
        group.add_member(vec![3], vec![4]).unwrap();
        group.remove_member(&[3]).unwrap();
        
        assert_eq!(group.member_count(), 1);
        assert_eq!(group.epoch(), 2);
    }
    
    #[test]
    fn test_rekey() {
        let mut group = Group::create(vec![1], vec![2]).unwrap();
        let initial_epoch = group.epoch();
        
        group.rekey().unwrap();
        assert_eq!(group.epoch(), initial_epoch + 1);
    }
}
