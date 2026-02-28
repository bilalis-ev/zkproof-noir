use std::hash::pedersen_hash;

// Merkle tree depth
global DEPTH: u32 = 4;
// number of transactions processed per proof
global BATCH_SIZE: u32 = 2;

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

    // builds and returns a 16-leaf Merkle tree
    fn build_tree(leaves: [Field; 16]) -> ([Field; 8], [Field; 4], [Field; 2], Field) {
        let mut level1: [Field; 8] = [0; 8];
        for i in 0..8 {
            level1[i] = hash_inode(leaves[2 * i], leaves[2 * i + 1]);
        }

        let mut level2: [Field; 4] = [0; 4];
        for i in 0..4 {
            level2[i] = hash_inode(level1[2 * i], level1[2 * i + 1]);
        }

        let mut level3: [Field; 2] = [0; 2];
        for i in 0..2 {
            level3[i] = hash_inode(level2[2 * i], level2[2 * i + 1]);
        }

        let root = hash_inode(level3[0], level3[1]);

        (level1, level2, level3, root)
    }

    // returns all the sibling for a given leaf
    fn get_siblings(
        index: u32,
        leaves: [Field; 16],
        level1: [Field; 8],
        level2: [Field; 4],
        level3: [Field; 2],
    ) -> [Field; 4] {
        let mut siblings: [Field; 4] = [0; 4];
        let mut index = index;

        // Level 0 sibling (leaf level)
        if index % 2 == 0 {
            siblings[0] = leaves[index + 1];
        } else {
            siblings[0] = leaves[index - 1];
        }
        index = index / 2;

        // Level 1 sibling
        if index % 2 == 0 {
            siblings[1] = level1[index + 1];
        } else {
            siblings[1] = level1[index - 1];
        }
        index = index / 2;

        // Level 2 sibling
        if index % 2 == 0 {
            siblings[2] = level2[index + 1];
        } else {
            siblings[2] = level2[index - 1];
        }
        index = index / 2;

        // Level 3 sibling
        if index % 2 == 0 {
            siblings[3] = level3[index + 1];
        } else {
            siblings[3] = level3[index - 1];
        }

        siblings
    }

    #[test]
    fn test_valid_batch() {
        // account setup: 4 normal accounts and 12 empty ones
        let acc0 = Account { balance: 1000, nonce: 0 };
        let acc1 = Account { balance: 500, nonce: 0 };
        let acc2 = Account { balance: 200, nonce: 0 };
        let acc3 = Account { balance: 100, nonce: 0 };

        let empty = Account { balance: 0, nonce: 0 };
        let empty_leaf = hash_leaf(empty);

        // tree initialization
        let mut leaves: [Field; 16] = [empty_leaf; 16];

        leaves[0] = hash_leaf(acc0);
        leaves[1] = hash_leaf(acc1);
        leaves[2] = hash_leaf(acc2);
        leaves[3] = hash_leaf(acc3);

        let (lvl1, lvl2, lvl3, root) = build_tree(leaves);

        // first transaction
        let tx1 = Transaction { sender_index: 0, receiver_index: 1, amount: 50, sender_nonce: 0 };
        let sender_siblings1 = get_siblings(0, leaves, lvl1, lvl2, lvl3);

        // sender update
        let new_node = Account { balance: acc0.balance - tx1.amount, nonce: acc0.nonce + 1 };
        leaves[0] = hash_leaf(new_node);

        let (lvl1b, lvl2b, lvl3b, _) = build_tree(leaves);

        let receiver_siblings1 = get_siblings(1, leaves, lvl1b, lvl2b, lvl3b);

        // receiver update
        leaves[1] = hash_leaf(Account { balance: 550, nonce: 0 });
        let (lvl1c, lvl2c, lvl3c, _) = build_tree(leaves);

        // second transaction
        let tx2 = Transaction { sender_index: 2, receiver_index: 3, amount: 30, sender_nonce: 0 };
        let sender_sibs_2 = get_siblings(2, leaves, lvl1c, lvl2c, lvl3c);

        // sender update
        leaves[2] = hash_leaf(Account { balance: 170, nonce: 1 });
        let (lvl1d, lvl2d, lvl3d, _) = build_tree(leaves);

        let receiver_sibs_2 = get_siblings(3, leaves, lvl1d, lvl2d, lvl3d);

        // receiver update
        leaves[3] = hash_leaf(Account { balance: 130, nonce: 0 });
        let (_, _, _, new_root) = build_tree(leaves);

        // main call
        main(
            [acc0, acc2],
            [sender_siblings1, sender_sibs_2],
            [acc1, acc3],
            [receiver_siblings1, receiver_sibs_2],
            [tx1, tx2],
            root,
            new_root,
        );
    }

    // insufficient sender balance
    #[test(should_fail)]
    fn test_insufficient_balance() {
        let acc0 = Account { balance: 5, nonce: 0 };
        let acc1 = Account { balance: 500, nonce: 0 };
        let acc2 = Account { balance: 200, nonce: 0 };
        let acc3 = Account { balance: 100, nonce: 0 };

        let empty = Account { balance: 0, nonce: 0 };
        let empty_leaf = hash_leaf(empty);

        let mut leaves: [Field; 16] = [empty_leaf; 16];
        leaves[0] = hash_leaf(acc0);
        leaves[1] = hash_leaf(acc1);
        leaves[2] = hash_leaf(acc2);
        leaves[3] = hash_leaf(acc3);

        let (lvl1, lvl2, lvl3, old_root) = build_tree(leaves);

        // transactions
        let tx1 = Transaction { sender_index: 0, receiver_index: 1, amount: 50, sender_nonce: 0 };
        let tx2 = Transaction { sender_index: 2, receiver_index: 3, amount: 30, sender_nonce: 0 };

        let sender1 = get_siblings(0, leaves, lvl1, lvl2, lvl3);
        let sender2 = get_siblings(2, leaves, lvl1, lvl2, lvl3);
        let receiver1 = get_siblings(1, leaves, lvl1, lvl2, lvl3);
        let receiver2 = get_siblings(3, leaves, lvl1, lvl2, lvl3);

        main(
            [acc0, acc2],
            [sender1, sender2],
            [acc1, acc3],
            [receiver1, receiver2],
            [tx1, tx2],
            old_root,
            old_root,
        );
    }

    // self-transfer
    #[test(should_fail)]
    fn test_self_transfer() {
        let acc0 = Account { balance: 1000, nonce: 0 };
        let acc1 = Account { balance: 500, nonce: 0 };
        let acc2 = Account { balance: 200, nonce: 0 };
        let acc3 = Account { balance: 100, nonce: 0 };
        let empty = Account { balance: 0, nonce: 0 };
        let empty_leaf = hash_leaf(empty);

        let mut leaves: [Field; 16] = [empty_leaf; 16];
        leaves[0] = hash_leaf(acc0);
        leaves[1] = hash_leaf(acc1);
        leaves[2] = hash_leaf(acc2);
        leaves[3] = hash_leaf(acc3);

        let (lvl1, lvl2, lvl3, old_root) = build_tree(leaves);

        // transactions
        let tx1 = Transaction { sender_index: 0, receiver_index: 0, amount: 50, sender_nonce: 0 };
        let tx2 = Transaction { sender_index: 2, receiver_index: 3, amount: 30, sender_nonce: 0 };

        let sender1 = get_siblings(0, leaves, lvl1, lvl2, lvl3);
        let sender2 = get_siblings(2, leaves, lvl1, lvl2, lvl3);
        let receiver1 = get_siblings(0, leaves, lvl1, lvl2, lvl3);
        let receiver2 = get_siblings(3, leaves, lvl1, lvl2, lvl3);

        main(
            [acc0, acc2],
            [sender1, sender2],
            [acc0, acc3],
            [receiver1, receiver2],
            [tx1, tx2],
            old_root,
            old_root,
        );
    }

    // nonce mismatch
    #[test(should_fail)]
    fn test_nonce_mismatch() {
        let acc0 = Account { balance: 1000, nonce: 0 };
        let acc1 = Account { balance: 500, nonce: 0 };
        let acc2 = Account { balance: 200, nonce: 0 };
        let acc3 = Account { balance: 100, nonce: 0 };
        let empty = Account { balance: 0, nonce: 0 };
        let empty_leaf = hash_leaf(empty);

        let mut leaves: [Field; 16] = [empty_leaf; 16];
        leaves[0] = hash_leaf(acc0);
        leaves[1] = hash_leaf(acc1);
        leaves[2] = hash_leaf(acc2);
        leaves[3] = hash_leaf(acc3);

        let (lvl1, lvl2, lvl3, old_root) = build_tree(leaves);

        // transactions
        let tx1 = Transaction { sender_index: 0, receiver_index: 1, amount: 50, sender_nonce: 5 };
        let tx2 = Transaction { sender_index: 2, receiver_index: 3, amount: 30, sender_nonce: 0 };

        let sender1 = get_siblings(0, leaves, lvl1, lvl2, lvl3);
        let sender2 = get_siblings(2, leaves, lvl1, lvl2, lvl3);
        let receiver1 = get_siblings(1, leaves, lvl1, lvl2, lvl3);
        let receiver2 = get_siblings(3, leaves, lvl1, lvl2, lvl3);

        main(
            [acc0, acc2],
            [sender1, sender2],
            [acc1, acc3],
            [receiver1, receiver2],
            [tx1, tx2],
            old_root,
            old_root,
        );
    }

    // prints values for Prover.toml
    #[test]
    fn print_prover_values() {
        let acc0 = Account { balance: 1000, nonce: 0 };
        let acc1 = Account { balance: 500, nonce: 0 };
        let acc2 = Account { balance: 200, nonce: 0 };
        let acc3 = Account { balance: 100, nonce: 0 };
        let empty = Account { balance: 0, nonce: 0 };
        let empty_leaf = hash_leaf(empty);

        let mut leaves: [Field; 16] = [empty_leaf; 16];
        leaves[0] = hash_leaf(acc0);
        leaves[1] = hash_leaf(acc1);
        leaves[2] = hash_leaf(acc2);
        leaves[3] = hash_leaf(acc3);

        let (lvl1, lvl2, lvl3, old_root) = build_tree(leaves);

        // TX 1 sender siblings
        let ss1 = get_siblings(0, leaves, lvl1, lvl2, lvl3);

        // Update sender
        leaves[0] = hash_leaf(Account { balance: 950, nonce: 1 });
        let (lvl1b, lvl2b, lvl3b, _) = build_tree(leaves);

        // TX 1 receiver siblings
        let rs1 = get_siblings(1, leaves, lvl1b, lvl2b, lvl3b);

        // Update receiver
        leaves[1] = hash_leaf(Account { balance: 550, nonce: 0 });
        let (lvl1c, lvl2c, lvl3c, _) = build_tree(leaves);

        // TX 2 sender siblings
        let ss2 = get_siblings(2, leaves, lvl1c, lvl2c, lvl3c);

        // Update sender
        leaves[2] = hash_leaf(Account { balance: 170, nonce: 1 });
        let (lvl1d, lvl2d, lvl3d, _) = build_tree(leaves);

        // TX 2 receiver siblings
        let rs2 = get_siblings(3, leaves, lvl1d, lvl2d, lvl3d);

        // Update receiver
        leaves[3] = hash_leaf(Account { balance: 130, nonce: 0 });
        let (_, _, _, new_root) = build_tree(leaves);

        println("=== VALUES FOR Prover.toml (DEPTH=4, BATCH_SIZE=2) ===");
        println(f"old_root = {old_root}");
        println(f"new_root = {new_root}");

        let ss1_0 = ss1[0];
        let ss1_1 = ss1[1];
        let ss1_2 = ss1[2];
        let ss1_3 = ss1[3];
        println(f"ss1_0 = {ss1_0}");
        println(f"ss1_1 = {ss1_1}");
        println(f"ss1_2 = {ss1_2}");
        println(f"ss1_3 = {ss1_3}");

        let rs1_0 = rs1[0];
        let rs1_1 = rs1[1];
        let rs1_2 = rs1[2];
        let rs1_3 = rs1[3];
        println(f"rs1_0 = {rs1_0}");
        println(f"rs1_1 = {rs1_1}");
        println(f"rs1_2 = {rs1_2}");
        println(f"rs1_3 = {rs1_3}");

        let ss2_0 = ss2[0];
        let ss2_1 = ss2[1];
        let ss2_2 = ss2[2];
        let ss2_3 = ss2[3];
        println(f"ss2_0 = {ss2_0}");
        println(f"ss2_1 = {ss2_1}");
        println(f"ss2_2 = {ss2_2}");
        println(f"ss2_3 = {ss2_3}");

        let rs2_0 = rs2[0];
        let rs2_1 = rs2[1];
        let rs2_2 = rs2[2];
        let rs2_3 = rs2[3];
        println(f"rs2_0 = {rs2_0}");
        println(f"rs2_1 = {rs2_1}");
        println(f"rs2_2 = {rs2_2}");
        println(f"rs2_3 = {rs2_3}");
    }
}
