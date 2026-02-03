use schnorr;
use std::{embedded_curve_ops::EmbeddedCurvePoint, hash::pedersen_hash};

global DEPTH: u32 = 2;

struct Account {
    balance: u32,
    nonce: u32, // transaction counter
    // public key coordinates on the elliptic curve
    pub_key_x: Field,
    pub_key_y: Field,
}

struct Transaction {
    amount: u32,
    sender_idx: u32,
    receiver_idx: u32,
}

// compute hash using account data
fn hash_account(acc: Account) -> Field {
    pedersen_hash(
        [acc.balance as Field, acc.nonce as Field, acc.pub_key_x, acc.pub_key_y],
    )
}

// computes the merkle tree inner node by hashing the hashes of its children
fn hash_inode(left_child: Field, right_child: Field) -> Field {
    pedersen_hash([left_child, right_child])
}

// current_node: hash of current node
// index: position of current node in merkle tree
// siblings: an array of siblings of current node on each level respectively
fn hash_root(mut current_node: Field, index: u32, siblings: [Field; DEPTH]) -> Field {
    for i in 0..DEPTH {
        let bit = (index >> i) & 1;
        let sibling = siblings[i];

        if bit == 0 {
            current_node = hash_inode(current_node, sibling);
        } else {
            current_node = hash_inode(sibling, current_node);
        }
    }
    current_node
}

fn main(
    sender: Account,
    sender_siblings: [Field; DEPTH],
    receiver: Account,
    receiver_siblings: [Field; DEPTH],
    tx: Transaction,
    signature: [u8; 64],
    msg_hash: [u8; 32],
    old_root: pub Field,
    new_root: pub Field,
) {
    // tx integrity validation: self-transfer and sufficient funds
    assert(tx.sender_idx != tx.receiver_idx);
    assert(sender.balance >= tx.amount);

    // signature verification
    let pub_key =
        EmbeddedCurvePoint { x: sender.pub_key_x, y: sender.pub_key_y, is_infinite: false }; // combine coordinates into a single point
    let is_valid = schnorr::verify_signature(pub_key, signature, msg_hash);
    assert(is_valid);

    // verification of sender's existence in current state
    let sender_leaf = hash_account(sender);
    let old_root_check = hash_root(sender_leaf, tx.sender_idx, sender_siblings);
    assert(old_root_check == old_root);

    // sender state update
    let mut updated_sender = sender;
    updated_sender.balance -= tx.amount;
    updated_sender.nonce += 1;

    let new_sender_leaf = hash_account(updated_sender);

    // intermediate root calulation - after the sender pays but before the receiver is paid
    let intermediate_root = hash_root(new_sender_leaf, tx.sender_idx, sender_siblings);

    // verification of receiver's existence in current state
    let receiver_leaf = hash_account(receiver);
    let inner_root_check = hash_root(receiver_leaf, tx.receiver_idx, receiver_siblings);

    assert(intermediate_root == inner_root_check);

    // receiver state update
    let mut updated_receiver = receiver;
    updated_receiver.balance += tx.amount;

    let new_receiver_leaf = hash_account(updated_receiver);

    // final root calculation
    let calculated_new_root = hash_root(new_receiver_leaf, tx.receiver_idx, receiver_siblings);

    assert(calculated_new_root == new_root);
}
