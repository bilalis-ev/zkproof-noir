use std::hash::pedersen_hash;

// Merkle tree depth
global DEPTH: u32 = 2;
// number of transactions processed per proof
global BATCH_SIZE: u32 = 1;

// account structure with fields: balance and nonce
struct Account {
    balance: u32,
    nonce: u32,
}

// transaction structure with fields: sender's index, receiver's index, amount to be transferred and sender's nonce
struct Transaction {
    sender_index: u32,
    receiver_index: u32,
    amount: u32,
    sender_nonce: u32,
}

// calculates and returns the pedersen hash of the account's fields to produce the leaf
fn hash_leaf(acc: Account) -> Field {
    pedersen_hash([acc.balance as Field, acc.nonce as Field])
}

// calculates and returns the pedersen hash of two child nodes to produce a parent node
fn hash_inode(left: Field, right: Field) -> Field {
    pedersen_hash([left, right])
}

// takes a leaf and builds the merkle tree up to the root, using the sibling hashes at each level
fn build_root(leaf: Field, index: u32, siblings: [Field; DEPTH]) -> Field {
    let mut current = leaf;
    let mut idx = index;
    // loop for each level of the tree, from bottom to top
    for i in 0..DEPTH {
        // extract the lowest bit of the current index
        let bit = idx % 2;
        // right shift of the index to remove the used bit
        idx = idx / 2;
        // if bit is equal to 0, then the current node is the left child
        if bit == 0 {
            current = hash_inode(current, siblings[i]);
            // otherwise, it is the right child
        } else {
            current = hash_inode(siblings[i], current);
        }
    }
    // after all the iterations, return the current node that now contains the root
    current
}

fn main(
    senders: [Account; BATCH_SIZE],
    sender_siblings: [[Field; DEPTH]; BATCH_SIZE],
    receivers: [Account; BATCH_SIZE],
    receiver_siblings: [[Field; DEPTH]; BATCH_SIZE],
    txs: [Transaction; BATCH_SIZE],
    old_root: pub Field,
    new_root: pub Field,
) {
    let mut current_root = old_root;

    for i in 0..BATCH_SIZE {
        let tx = txs[i];
        let sender = senders[i];
        let receiver = receivers[i];

        // assert that the sender and the receiver do not refer to the same account
        assert(tx.sender_index != tx.receiver_index, "Self-transfer");

        // assert that the sender has sufficient balance for the transaction
        assert(sender.balance >= tx.amount, "Insufficient sender balance");

        // assert that the sender's nonce is equal to the transaction's nonce (replay protection)
        assert(tx.sender_nonce == sender.nonce, "Mismatched nonce");

        // hash the sender's account and compute the root based on it
        let sender_leaf = hash_leaf(sender);
        let sender_root = build_root(sender_leaf, tx.sender_index, sender_siblings[i]);
        // assert that the root calculated from the sender is the same as the current root (old sender and old receiver root)
        assert(sender_root == current_root, "Sender Merkle proof invalid");

        // update sender's account
        let mut updated_sender = sender;
        updated_sender.balance = sender.balance - tx.amount;
        updated_sender.nonce = sender.nonce + 1;
        // compute the leaf based on the updated sender
        let new_sender_leaf = hash_leaf(updated_sender);

        // recompute the root based on the updated sender leaf
        current_root = build_root(new_sender_leaf, tx.sender_index, sender_siblings[i]);

        // hash the receiver's account and compute the root based on it
        let receiver_leaf = hash_leaf(receiver);
        let receiver_root = build_root(receiver_leaf, tx.receiver_index, receiver_siblings[i]);
        // assert that the root calculated from the receiver is the same as the current root (new sender and old receiver root)
        assert(receiver_root == current_root, "Receiver Merkle proof invalid");

        //update receiver's account
        let mut updated_receiver = receiver;
        updated_receiver.balance = receiver.balance + tx.amount;
        // compute the leaf based on the updated receiver
        let new_receiver_leaf = hash_leaf(updated_receiver);

        // recompute the root based on the updated receiver leaf
        current_root = build_root(new_receiver_leaf, tx.receiver_index, receiver_siblings[i]);
    }

    // assert that the final computed root is the same as the provided new root
    assert(current_root == new_root, "Final root mismatch");
}

mod tests {
    use crate::{Account, hash_inode, hash_leaf, main, Transaction};

    // test of a valid transaction on a tree with a sender, a receiver and two empty nodes
    #[test]
    fn test_valid_transaction() {
        // account setup
        let sender = Account { balance: 100, nonce: 0 };
        let receiver = Account { balance: 50, nonce: 0 };
        let empty_acc = Account { balance: 0, nonce: 0 };

        // Merkle tree initialization
        let leaf0 = hash_leaf(sender);
        let leaf1 = hash_leaf(receiver);
        let leaf2 = hash_leaf(empty_acc);
        let leaf3 = hash_leaf(empty_acc);

        let inode01 = hash_inode(leaf0, leaf1);
        let inode23 = hash_inode(leaf2, leaf3);
        let old_root = hash_inode(inode01, inode23);

        // transaction to be processed (valid)
        let tx = Transaction { sender_index: 0, receiver_index: 1, amount: 10, sender_nonce: 0 };

        // compute intermediate root after sender update
        let updated_sender =
            Account { balance: sender.balance - tx.amount, nonce: sender.nonce + 1 };
        let new_leaf0 = hash_leaf(updated_sender);

        // siblings
        let sender_siblings = [leaf1, inode23];
        let receiver_siblings = [new_leaf0, inode23];

        // compute new root after receiver update
        let new_receiver = Account { balance: receiver.balance + tx.amount, nonce: receiver.nonce };
        let new_leaf1 = hash_leaf(new_receiver);
        let new_inode01 = hash_inode(new_leaf0, new_leaf1);
        let new_root = hash_inode(new_inode01, inode23);

        // circuit execution
        main(
            [sender],
            [sender_siblings],
            [receiver],
            [receiver_siblings],
            [tx],
            old_root,
            new_root,
        );
    }

    // test of a valid transaction in a tree with four accounts
    #[test]
    fn test_four_accounts() {
        // account setup
        let acc0 = Account { balance: 100, nonce: 0 };
        let acc1 = Account { balance: 50, nonce: 0 };
        let acc2 = Account { balance: 75, nonce: 0 };
        let acc3 = Account { balance: 25, nonce: 0 };

        // build the initial merkle tree
        let leaf0 = hash_leaf(acc0);
        let leaf1 = hash_leaf(acc1);
        let leaf2 = hash_leaf(acc2);
        let leaf3 = hash_leaf(acc3);

        let inode01 = hash_inode(leaf0, leaf1);
        let inode23 = hash_inode(leaf2, leaf3);
        let old_root = hash_inode(inode01, inode23);

        // transaction to be processed (valid)
        let tx = Transaction { sender_index: 0, receiver_index: 1, amount: 20, sender_nonce: 0 };

        // compute intermediate root after sender update
        let new_sender = Account { balance: acc0.balance - tx.amount, nonce: acc0.nonce + 1 };
        let new_leaf0 = hash_leaf(new_sender);

        // siblings
        let sender_siblings = [leaf1, inode23];
        let receiver_siblings = [new_leaf0, inode23];

        // compute new root after receiver update
        let new_receiver = Account { balance: acc1.balance + tx.amount, nonce: acc1.nonce };
        let new_leaf1 = hash_leaf(new_receiver);
        let new_inode01 = hash_inode(new_leaf0, new_leaf1);
        let new_root = hash_inode(new_inode01, inode23);

        // main call
        main(
            [acc0],
            [sender_siblings],
            [acc1],
            [receiver_siblings],
            [tx],
            old_root,
            new_root,
        );
    }

    // test where the balance of the sender is insufficient for the transaction
    #[test(should_fail_with = "Insufficient sender balance")]
    fn test_insufficient_balance() {
        // account setup
        let sender = Account { balance: 5, nonce: 0 };
        let receiver = Account { balance: 50, nonce: 0 };
        let empty_acc = Account { balance: 0, nonce: 0 };

        // calculation of initial Merkle tree
        let leaf0 = hash_leaf(sender);
        let leaf1 = hash_leaf(receiver);
        let leaf2 = hash_leaf(empty_acc);
        let leaf3 = hash_leaf(empty_acc);

        let inode01 = hash_inode(leaf0, leaf1);
        let inode23 = hash_inode(leaf2, leaf3);
        let old_root = hash_inode(inode01, inode23);

        // transaction to be processed (sender.balance < tx.amount)
        let tx = Transaction { sender_index: 0, receiver_index: 1, amount: 10, sender_nonce: 0 };

        // siblings
        let sender_siblings = [leaf1, inode23];
        let receiver_siblings = [leaf0, inode23];

        // main call
        main(
            [sender],
            [sender_siblings],
            [receiver],
            [receiver_siblings],
            [tx],
            old_root,
            old_root,
        );
    }

    // test of self-transfer
    #[test(should_fail_with = "Self-transfer")]
    fn test_self_transfer() {
        //account setup
        let sender = Account { balance: 100, nonce: 0 };
        let dummy = Account { balance: 50, nonce: 0 };
        let empty_acc = Account { balance: 0, nonce: 0 };

        // Merkle tree initialization
        let leaf0 = hash_leaf(sender);
        let leaf1 = hash_leaf(dummy);
        let leaf2 = hash_leaf(empty_acc);
        let leaf3 = hash_leaf(empty_acc);

        let inode01 = hash_inode(leaf0, leaf1);
        let inode23 = hash_inode(leaf2, leaf3);
        let old_root = hash_inode(inode01, inode23);

        // transaction to be processed (sender_idx = receiver_idx)
        let tx = Transaction { sender_index: 0, receiver_index: 0, amount: 10, sender_nonce: 0 };

        // siblings
        let siblings = [leaf1, inode23];

        // main call
        main(
            [sender],
            [siblings],
            [sender],
            [siblings],
            [tx],
            old_root,
            old_root,
        );
    }

    // test with invalid Merkle proof
    #[test(should_fail_with = "Sender Merkle proof invalid")]
    fn test_invalid_merkle_proof() {
        // account setup
        let sender = Account { balance: 100, nonce: 0 };
        let receiver = Account { balance: 50, nonce: 0 };
        let empty_acc = Account { balance: 0, nonce: 0 };

        // Merkle tree initialization
        let leaf0 = hash_leaf(sender);
        let leaf1 = hash_leaf(receiver);
        let leaf2 = hash_leaf(empty_acc);
        let leaf3 = hash_leaf(empty_acc);

        let inode01 = hash_inode(leaf0, leaf1);
        let inode23 = hash_inode(leaf2, leaf3);
        let old_root = hash_inode(inode01, inode23);

        // transaction to be processed (valid)
        let tx = Transaction { sender_index: 0, receiver_index: 1, amount: 10, sender_nonce: 0 };

        // siblings
        let wrong_siblings = [hash_leaf(empty_acc), hash_leaf(empty_acc)];
        let dummy_siblings = [0, 0];

        // main call
        main(
            [sender],
            [wrong_siblings],
            [receiver],
            [dummy_siblings],
            [tx],
            old_root,
            old_root,
        );
    }

    // test with wrong nonce (replay attack)
    #[test(should_fail_with = "Mismatched nonce")]
    fn test_nonce_mismatch() {
        // account setup
        let sender = Account { balance: 100, nonce: 0 };
        let receiver = Account { balance: 50, nonce: 0 };
        let empty_acc = Account { balance: 0, nonce: 0 };

        // Merkle tree initialization
        let leaf0 = hash_leaf(sender);
        let leaf1 = hash_leaf(receiver);
        let leaf2 = hash_leaf(empty_acc);
        let leaf3 = hash_leaf(empty_acc);

        let inode01 = hash_inode(leaf0, leaf1);
        let inode23 = hash_inode(leaf2, leaf3);
        let old_root = hash_inode(inode01, inode23);

        // transaction to be processed (wrong nonce)
        let tx = Transaction { sender_index: 0, receiver_index: 1, amount: 10, sender_nonce: 5 };

        // siblings
        let sender_siblings = [leaf1, inode23];
        let receiver_siblings = [leaf0, inode23];

        // main call
        main(
            [sender],
            [sender_siblings],
            [receiver],
            [receiver_siblings],
            [tx],
            old_root,
            old_root,
        );
    }

    // a test that prints the values used in Prover.toml
    #[test]
    fn print_prover_values() {
        let sender = Account { balance: 100, nonce: 0 };
        let receiver = Account { balance: 50, nonce: 0 };
        let empty_acc = Account { balance: 0, nonce: 0 };

        let leaf0 = hash_leaf(sender);
        let leaf1 = hash_leaf(receiver);
        let leaf2 = hash_leaf(empty_acc);
        let leaf3 = hash_leaf(empty_acc);

        let inode01 = hash_inode(leaf0, leaf1);
        let inode23 = hash_inode(leaf2, leaf3);
        let old_root = hash_inode(inode01, inode23);

        let tx = Transaction { sender_index: 0, receiver_index: 1, amount: 10, sender_nonce: 0 };

        let new_sender = Account { balance: sender.balance - tx.amount, nonce: sender.nonce + 1 };
        let new_leaf0 = hash_leaf(new_sender);

        let new_receiver = Account { balance: receiver.balance + tx.amount, nonce: receiver.nonce };
        let new_leaf1 = hash_leaf(new_receiver);

        let new_inode01 = hash_inode(new_leaf0, new_leaf1);
        let new_root = hash_inode(new_inode01, inode23);

        println(f"old_root = {old_root}");
        println(f"new_root = {new_root}");
        println(f"sender_sibling_0 = {leaf1}");
        println(f"sender_sibling_1 = {inode23}");
        println(f"receiver_sibling_0 = {new_leaf0}");
        println(f"receiver_sibling_1 = {inode23}");
    }
}
