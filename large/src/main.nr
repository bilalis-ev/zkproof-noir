use std::hash::pedersen_hash;

// Merkle tree depth
global DEPTH: u32 = 8;
// number of transactions processed per proof
global BATCH_SIZE: u32 = 4;

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
    for i in 0..DEPTH {
        let bit = idx % 2;
        idx = idx / 2;
        if bit == 0 {
            current = hash_inode(current, siblings[i]);
        } else {
            current = hash_inode(siblings[i], current);
        }
    }
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
        // assert that the root calculated from the sender is the same as the current root
        assert(sender_root == current_root, "Sender Merkle proof invalid");

        // update sender's account
        let mut updated_sender = sender;
        updated_sender.balance = sender.balance - tx.amount;
        updated_sender.nonce = sender.nonce + 1;
        let new_sender_leaf = hash_leaf(updated_sender);

        // recompute the root based on the updated sender leaf
        current_root = build_root(new_sender_leaf, tx.sender_index, sender_siblings[i]);

        // hash the receiver's account and compute the root based on it
        let receiver_leaf = hash_leaf(receiver);
        let receiver_root = build_root(receiver_leaf, tx.receiver_index, receiver_siblings[i]);
        // assert that the root calculated from the receiver is the same as the current root
        assert(receiver_root == current_root, "Receiver Merkle proof invalid");

        // update receiver's account
        let mut updated_receiver = receiver;
        updated_receiver.balance = receiver.balance + tx.amount;
        let new_receiver_leaf = hash_leaf(updated_receiver);

        // recompute the root based on the updated receiver leaf
        current_root = build_root(new_receiver_leaf, tx.receiver_index, receiver_siblings[i]);
    }

    // assert that the final computed root is the same as the provided new root
    assert(current_root == new_root, "Final root mismatch");
}

mod tests {
    use crate::{Account, hash_inode, hash_leaf, main, Transaction};

    // computes empty subtree hashes for each level of the tree
    // empty[0] = hash of an empty account (leaf)
    // empty[i] = hash_inode(empty[i-1], empty[i-1])
    fn compute_empty_subtrees() -> [Field; 8] {
        let empty_acc = Account { balance: 0, nonce: 0 };
        let mut empty_hashes: [Field; 8] = [0; 8];
        empty_hashes[0] = hash_leaf(empty_acc);
        for i in 1..8 {
            // empty_hashes[i-1] is used for both children since they are both empty
            empty_hashes[i] = hash_inode(empty_hashes[i - 1], empty_hashes[i - 1]);
        }
        empty_hashes
    }

    // rebuilds the 256-leaf tree from 8 active leaves
    // leaves 0-7 are active, while leaves 8-255 are empty
    // only the first 3 levels result from hashing live nodes
    // the rest of the levels result from hashing a live node and an empty one
    fn rebuild(active_leaves: [Field; 8], empty: [Field; 8]) -> ([Field; 4], [Field; 2], Field) {
        // level 1: 4 nodes from 8 leaves
        let mut lvl1: [Field; 4] = [0; 4];
        for i in 0..4 {
            lvl1[i] = hash_inode(active_leaves[2 * i], active_leaves[2 * i + 1]);
        }

        // level 2: 2 nodes from 4 nodes
        let mut lvl2: [Field; 2] = [0; 2];
        for i in 0..2 {
            lvl2[i] = hash_inode(lvl1[2 * i], lvl1[2 * i + 1]);
        }
        // Level 3: 1 node from 2 nodes
        let lvl3 = hash_inode(lvl2[0], lvl2[1]);
        // levels 4-7: active subtree at position 0, sibling is empty subtree
        let lvl4 = hash_inode(lvl3, empty[3]);
        let lvl5 = hash_inode(lvl4, empty[4]);
        let lvl6 = hash_inode(lvl5, empty[5]);
        let lvl7 = hash_inode(lvl6, empty[6]);

        let root = hash_inode(lvl7, empty[7]);

        (lvl1, lvl2, root)
    }

    // gets siblings for leaf index 0-7 in the 256-leaf tree
    // levels 0-2 use live nodes while levels 3-7 use empty subtree hashes
    fn get_siblings(
        index: u32,
        active_leaves: [Field; 8],
        lvl1: [Field; 4],
        lvl2: [Field; 2],
        empty: [Field; 8],
    ) -> [Field; 8] {
        let mut siblings: [Field; 8] = [0; 8];
        let mut index = index;

        // level 0 sibling
        if index % 2 == 0 {
            siblings[0] = active_leaves[index + 1];
        } else {
            siblings[0] = active_leaves[index - 1];
        }
        index = index / 2;

        // level 1 sibling
        if index % 2 == 0 {
            siblings[1] = lvl1[index + 1];
        } else {
            siblings[1] = lvl1[index - 1];
        }
        index = index / 2;

        // level 2 sibling
        if index % 2 == 0 {
            siblings[2] = lvl2[index + 1];
        } else {
            siblings[2] = lvl2[index - 1];
        }

        // levels 3-7: empty subtree hashes
        siblings[3] = empty[3];
        siblings[4] = empty[4];
        siblings[5] = empty[5];
        siblings[6] = empty[6];
        siblings[7] = empty[7];

        siblings
    }

    // valid batch of 4 transactions
    #[test]
    fn test_valid_batch() {
        let empty = compute_empty_subtrees();

        let acc0 = Account { balance: 1000, nonce: 0 };
        let acc1 = Account { balance: 800, nonce: 0 };
        let acc2 = Account { balance: 600, nonce: 0 };
        let acc3 = Account { balance: 400, nonce: 0 };
        let acc4 = Account { balance: 300, nonce: 0 };
        let acc5 = Account { balance: 200, nonce: 0 };
        let acc6 = Account { balance: 100, nonce: 0 };
        let acc7 = Account { balance: 50, nonce: 0 };

        let mut leaves: [Field; 8] = [0; 8];

        leaves[0] = hash_leaf(acc0);
        leaves[1] = hash_leaf(acc1);
        leaves[2] = hash_leaf(acc2);
        leaves[3] = hash_leaf(acc3);
        leaves[4] = hash_leaf(acc4);
        leaves[5] = hash_leaf(acc5);
        leaves[6] = hash_leaf(acc6);
        leaves[7] = hash_leaf(acc7);

        let (n1, n2, old_root) = rebuild(leaves, empty);

        // transaction 1
        let tx1 = Transaction { sender_index: 0, receiver_index: 1, amount: 100, sender_nonce: 0 };
        let ss1 = get_siblings(0, leaves, n1, n2, empty);

        leaves[0] = hash_leaf(Account { balance: 900, nonce: 1 });
        let (n1b, n2b, _) = rebuild(leaves, empty);
        let rs1 = get_siblings(1, leaves, n1b, n2b, empty);

        leaves[1] = hash_leaf(Account { balance: 900, nonce: 0 });
        let (n1c, n2c, _) = rebuild(leaves, empty);

        // transaction 2
        let tx2 = Transaction { sender_index: 2, receiver_index: 3, amount: 50, sender_nonce: 0 };
        let ss2 = get_siblings(2, leaves, n1c, n2c, empty);

        leaves[2] = hash_leaf(Account { balance: 550, nonce: 1 });
        let (n1d, n2d, _) = rebuild(leaves, empty);
        let rs2 = get_siblings(3, leaves, n1d, n2d, empty);

        leaves[3] = hash_leaf(Account { balance: 450, nonce: 0 });
        let (n1e, n2e, _) = rebuild(leaves, empty);

        // transaction 3
        let tx3 = Transaction { sender_index: 4, receiver_index: 5, amount: 30, sender_nonce: 0 };
        let ss3 = get_siblings(4, leaves, n1e, n2e, empty);

        leaves[4] = hash_leaf(Account { balance: 270, nonce: 1 });
        let (n1f, n2f, _) = rebuild(leaves, empty);
        let rs3 = get_siblings(5, leaves, n1f, n2f, empty);

        leaves[5] = hash_leaf(Account { balance: 230, nonce: 0 });
        let (n1g, n2g, _) = rebuild(leaves, empty);

        // transaction 4
        let tx4 = Transaction { sender_index: 6, receiver_index: 7, amount: 10, sender_nonce: 0 };
        let ss4 = get_siblings(6, leaves, n1g, n2g, empty);

        leaves[6] = hash_leaf(Account { balance: 90, nonce: 1 });
        let (n1h, n2h, _) = rebuild(leaves, empty);
        let rs4 = get_siblings(7, leaves, n1h, n2h, empty);

        leaves[7] = hash_leaf(Account { balance: 60, nonce: 0 });
        let (_, _, new_root) = rebuild(leaves, empty);

        main(
            [acc0, acc2, acc4, acc6],
            [ss1, ss2, ss3, ss4],
            [acc1, acc3, acc5, acc7],
            [rs1, rs2, rs3, rs4],
            [tx1, tx2, tx3, tx4],
            old_root,
            new_root,
        );
    }

    // prints values for Prover.toml
    #[test]
    fn print_prover_values() {
        let empty = compute_empty_subtrees();

        let acc0 = Account { balance: 1000, nonce: 0 };
        let acc1 = Account { balance: 800, nonce: 0 };
        let acc2 = Account { balance: 600, nonce: 0 };
        let acc3 = Account { balance: 400, nonce: 0 };
        let acc4 = Account { balance: 300, nonce: 0 };
        let acc5 = Account { balance: 200, nonce: 0 };
        let acc6 = Account { balance: 100, nonce: 0 };
        let acc7 = Account { balance: 50, nonce: 0 };

        let mut leaves: [Field; 8] = [0; 8];
        leaves[0] = hash_leaf(acc0);
        leaves[1] = hash_leaf(acc1);
        leaves[2] = hash_leaf(acc2);
        leaves[3] = hash_leaf(acc3);
        leaves[4] = hash_leaf(acc4);
        leaves[5] = hash_leaf(acc5);
        leaves[6] = hash_leaf(acc6);
        leaves[7] = hash_leaf(acc7);

        let (n1, n2, old_root) = rebuild(leaves, empty);

        // transaction 1
        let ss1 = get_siblings(0, leaves, n1, n2, empty);
        leaves[0] = hash_leaf(Account { balance: 900, nonce: 1 });
        let (n1b, n2b, _) = rebuild(leaves, empty);
        let rs1 = get_siblings(1, leaves, n1b, n2b, empty);
        leaves[1] = hash_leaf(Account { balance: 900, nonce: 0 });
        let (n1c, n2c, _) = rebuild(leaves, empty);

        // transaction 2
        let ss2 = get_siblings(2, leaves, n1c, n2c, empty);
        leaves[2] = hash_leaf(Account { balance: 550, nonce: 1 });
        let (n1d, n2d, _) = rebuild(leaves, empty);
        let rs2 = get_siblings(3, leaves, n1d, n2d, empty);
        leaves[3] = hash_leaf(Account { balance: 450, nonce: 0 });
        let (n1e, n2e, _) = rebuild(leaves, empty);

        // transaction 3
        let ss3 = get_siblings(4, leaves, n1e, n2e, empty);
        leaves[4] = hash_leaf(Account { balance: 270, nonce: 1 });
        let (n1f, n2f, _) = rebuild(leaves, empty);
        let rs3 = get_siblings(5, leaves, n1f, n2f, empty);
        leaves[5] = hash_leaf(Account { balance: 230, nonce: 0 });
        let (n1g, n2g, _) = rebuild(leaves, empty);

        // transaction 4
        let ss4 = get_siblings(6, leaves, n1g, n2g, empty);
        leaves[6] = hash_leaf(Account { balance: 90, nonce: 1 });
        let (n1h, n2h, _) = rebuild(leaves, empty);
        let rs4 = get_siblings(7, leaves, n1h, n2h, empty);
        leaves[7] = hash_leaf(Account { balance: 60, nonce: 0 });
        let (_, _, new_root) = rebuild(leaves, empty);

        println(f"old_root = {old_root}");
        println(f"new_root = {new_root}");

        let v = ss1[0];
        println(f"ss1_0 = {v}");
        let v = ss1[1];
        println(f"ss1_1 = {v}");
        let v = ss1[2];
        println(f"ss1_2 = {v}");
        let v = ss1[3];
        println(f"ss1_3 = {v}");
        let v = ss1[4];
        println(f"ss1_4 = {v}");
        let v = ss1[5];
        println(f"ss1_5 = {v}");
        let v = ss1[6];
        println(f"ss1_6 = {v}");
        let v = ss1[7];
        println(f"ss1_7 = {v}");

        let v = rs1[0];
        println(f"rs1_0 = {v}");
        let v = rs1[1];
        println(f"rs1_1 = {v}");
        let v = rs1[2];
        println(f"rs1_2 = {v}");
        let v = rs1[3];
        println(f"rs1_3 = {v}");
        let v = rs1[4];
        println(f"rs1_4 = {v}");
        let v = rs1[5];
        println(f"rs1_5 = {v}");
        let v = rs1[6];
        println(f"rs1_6 = {v}");
        let v = rs1[7];
        println(f"rs1_7 = {v}");

        let v = ss2[0];
        println(f"ss2_0 = {v}");
        let v = ss2[1];
        println(f"ss2_1 = {v}");
        let v = ss2[2];
        println(f"ss2_2 = {v}");
        let v = ss2[3];
        println(f"ss2_3 = {v}");
        let v = ss2[4];
        println(f"ss2_4 = {v}");
        let v = ss2[5];
        println(f"ss2_5 = {v}");
        let v = ss2[6];
        println(f"ss2_6 = {v}");
        let v = ss2[7];
        println(f"ss2_7 = {v}");

        let v = rs2[0];
        println(f"rs2_0 = {v}");
        let v = rs2[1];
        println(f"rs2_1 = {v}");
        let v = rs2[2];
        println(f"rs2_2 = {v}");
        let v = rs2[3];
        println(f"rs2_3 = {v}");
        let v = rs2[4];
        println(f"rs2_4 = {v}");
        let v = rs2[5];
        println(f"rs2_5 = {v}");
        let v = rs2[6];
        println(f"rs2_6 = {v}");
        let v = rs2[7];
        println(f"rs2_7 = {v}");

        let v = ss3[0];
        println(f"ss3_0 = {v}");
        let v = ss3[1];
        println(f"ss3_1 = {v}");
        let v = ss3[2];
        println(f"ss3_2 = {v}");
        let v = ss3[3];
        println(f"ss3_3 = {v}");
        let v = ss3[4];
        println(f"ss3_4 = {v}");
        let v = ss3[5];
        println(f"ss3_5 = {v}");
        let v = ss3[6];
        println(f"ss3_6 = {v}");
        let v = ss3[7];
        println(f"ss3_7 = {v}");

        let v = rs3[0];
        println(f"rs3_0 = {v}");
        let v = rs3[1];
        println(f"rs3_1 = {v}");
        let v = rs3[2];
        println(f"rs3_2 = {v}");
        let v = rs3[3];
        println(f"rs3_3 = {v}");
        let v = rs3[4];
        println(f"rs3_4 = {v}");
        let v = rs3[5];
        println(f"rs3_5 = {v}");
        let v = rs3[6];
        println(f"rs3_6 = {v}");
        let v = rs3[7];
        println(f"rs3_7 = {v}");

        let v = ss4[0];
        println(f"ss4_0 = {v}");
        let v = ss4[1];
        println(f"ss4_1 = {v}");
        let v = ss4[2];
        println(f"ss4_2 = {v}");
        let v = ss4[3];
        println(f"ss4_3 = {v}");
        let v = ss4[4];
        println(f"ss4_4 = {v}");
        let v = ss4[5];
        println(f"ss4_5 = {v}");
        let v = ss4[6];
        println(f"ss4_6 = {v}");
        let v = ss4[7];
        println(f"ss4_7 = {v}");

        let v = rs4[0];
        println(f"rs4_0 = {v}");
        let v = rs4[1];
        println(f"rs4_1 = {v}");
        let v = rs4[2];
        println(f"rs4_2 = {v}");
        let v = rs4[3];
        println(f"rs4_3 = {v}");
        let v = rs4[4];
        println(f"rs4_4 = {v}");
        let v = rs4[5];
        println(f"rs4_5 = {v}");
        let v = rs4[6];
        println(f"rs4_6 = {v}");
        let v = rs4[7];
        println(f"rs4_7 = {v}");
    }
}
