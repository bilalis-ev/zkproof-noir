use schnorr;
use std::{hash::pedersen_hash, embedded_curve_ops::EmbeddedCurvePoint};

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

fn main(sender: Account, sender_siblings:, receiver: Account, receiver_siblings:, tx: Transaction, signature: [u8; 64], msg_hash[u8, 32], old_root: pub Field) -> pub Field {
    let pub_key = EmbeddedCurvePoint { x: sender.pub_key_x, y: sender.pub_key_y, is_infinite: false};
}

// computes the merkle tree leaf by hashing the account's balance and nonce
fn hash_leaf(balance: u32, nonce: u32) -> Field {
    // balance and nonce are represented as ints for safe arithmetic and are then converted to fields for hashing
    let balance_field = balance as Field;
    let nonce_field = nonce as Field;

    pedersen_hash([balance_field, nonce_field])
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

fn main(balance: u32, nonce: u32, index: u32, siblings: [Field; DEPTH], root: pub Field) {
    assert(index < 4);

    let leaf = hash_leaf(balance, nonce);
    let new_root = hash_root(leaf, index, siblings);

    assert(new_root == root);
}

#[test]
fn merkle_test() {
    // balance and nonce of each of the 4 accounts
    let b0: u32 = 10;
    let n0: u32 = 0;
    let b1: u32 = 20;
    let n1: u32 = 0;
    let b2: u32 = 30;
    let n2: u32 = 0;
    let b3: u32 = 40;
    let n3: u32 = 0;

    // leaf hashes
    let l0 = hash_leaf(b0, n0);
    let l1 = hash_leaf(b1, n1);
    let l2 = hash_leaf(b2, n2);
    let l3 = hash_leaf(b3, n3);

    // internal node hashes
    let h01 = hash_inode(l0, l1);
    let h23 = hash_inode(l2, l3);

    // root hash
    let root = hash_inode(h01, h23);

    // prove inclusion for index 0 (binary 10)
    let index: u32 = 0;
    let siblings: [Field; 2] = [l1, h23];

    // call the circuit function
    main(b0, n0, index, siblings, root);
}
