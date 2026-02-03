use schnorr;
use std::{embedded_curve_ops::EmbeddedCurvePoint, hash::pedersen_hash};

global DEPTH: u32 = 2;
global BATCH_SIZE: u32 = 1;

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
    senders: [Account; BATCH_SIZE],
    sender_siblings: [[Field; DEPTH]; BATCH_SIZE],
    receivers: [Account; BATCH_SIZE],
    receiver_siblings: [[Field; DEPTH]; BATCH_SIZE],
    txs: [Transaction; BATCH_SIZE],
    signatures: [[u8; 64]; BATCH_SIZE],
    msg_hashes: [[u8; 32]; BATCH_SIZE],
    old_root: pub Field,
    new_root: pub Field,
) {
    let mut current_root = old_root;

    for i in 0..BATCH_SIZE {
        let tx = txs[i];
        let sender = senders[i];
        let receiver = receivers[i];
        let signature = signatures[i];
        let msg_hash = msg_hashes[i];
        let receiver_sibling = receiver_siblings[i];
        let sender_sibling = sender_siblings[i];

        // tx integrity
        assert(tx.sender_idx != tx.receiver_idx); // self-transfer
        assert(sender.balance >= tx.amount); // sufficient balance

        // signature verification
        let pub_key =
            EmbeddedCurvePoint { x: sender.pub_key_x, y: sender.pub_key_y, is_infinite: false }; // combine coordinates into a single point
        let is_valid = schnorr::verify_signature(pub_key, signature, msg_hash);
        //assert(is_valid);

        // verification of sender's existence in current state
        let sender_leaf = hash_account(sender);
        let root_check = hash_root(sender_leaf, tx.sender_idx, sender_sibling);
        assert(root_check == current_root);

        // sender state update
        let mut updated_sender = sender;
        updated_sender.balance -= tx.amount;
        updated_sender.nonce += 1;

        let new_sender_leaf = hash_account(updated_sender);

        // root update
        current_root = hash_root(new_sender_leaf, tx.sender_idx, sender_sibling);

        // verification of receiver's existence in current state
        let receiver_leaf = hash_account(receiver);
        let receiver_root_check = hash_root(receiver_leaf, tx.receiver_idx, receiver_sibling);

        assert(receiver_root_check == current_root);

        // receiver state update
        let mut updated_receiver = receiver;
        updated_receiver.balance += tx.amount;

        let new_receiver_leaf = hash_account(updated_receiver);

        // final root calculation
        current_root = hash_root(new_receiver_leaf, tx.receiver_idx, receiver_sibling);
    }

    assert(current_root == new_root);
}

// module definition for testing
mod test {

    use crate::{Account, hash_account, hash_inode, main, Transaction};

    #[test]
    fn tx_test() {
        let sender = Account { balance: 100, nonce: 0, pub_key_x: 0, pub_key_y: 0 };
        let receiver = Account { balance: 50, nonce: 0, pub_key_x: 0, pub_key_y: 0 };

        let sender_leaf = hash_account(sender);
        let receiver_leaf = hash_account(receiver);

        let empty_leaf = hash_inode(sender_leaf, receiver_leaf);

        let inode01 = hash_inode(sender_leaf, receiver_leaf);
        let inode23 = hash_inode(empty_leaf, empty_leaf);

        let old_root = hash_inode(inode01, inode23);

        let tx = Transaction { amount: 10, sender_idx: 0, receiver_idx: 1 };

        let sender_siblings = [receiver_leaf, inode23];

        let mut updated_sender = sender;
        updated_sender.balance -= tx.amount;
        updated_sender.nonce += 1;

        let updated_sender_leaf = hash_account(updated_sender);

        let receiver_siblings = [updated_sender_leaf, inode23];

        let mut updated_receiver = receiver;
        updated_receiver.balance += tx.amount;

        let updated_receiver_leaf = hash_account(updated_receiver);

        let new_inode01 = hash_inode(updated_sender_leaf, updated_receiver_leaf);
        let new_root = hash_inode(new_inode01, inode23);

        let senders = [sender];
        let receivers = [receiver];
        let txs = [tx];
        let s_siblings = [sender_siblings];
        let r_siblings = [receiver_siblings];

        let sigs = [[0; 64]];
        let msgs = [[0; 32]];

        main(
            senders,
            s_siblings,
            receivers,
            r_siblings,
            txs,
            sigs,
            msgs,
            old_root,
            new_root,
        );
    }
}
