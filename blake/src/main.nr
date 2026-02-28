// Merkle tree depth
global DEPTH: u32 = 2;
// number of transactions processed per proof
global BATCH_SIZE: u32 = 1;

struct Account {
    balance: u32,
    nonce: u32,
}

struct Transaction {
    sender_index: u32,
    receiver_index: u32,
    amount: u32,
    sender_nonce: u32,
}

// 32 bytes to Field conversion
fn bytes32_to_field(bytes: [u8; 32]) -> Field {
    let mut result: Field = 0;
    for i in 0..32 {
        result = result * 256 + bytes[i] as Field;
    }
    result
}

// Blake hash of account fields (balance and nonce packed as 8 bytes
fn hash_leaf(acc: Account) -> Field {
    let mut input: [u8; 8] = [0; 8];
    // balance as big-endian 4 bytes
    input[0] = ((acc.balance >> 24) & 0xFF) as u8;
    input[1] = ((acc.balance >> 16) & 0xFF) as u8;
    input[2] = ((acc.balance >> 8) & 0xFF) as u8;
    input[3] = (acc.balance & 0xFF) as u8;
    // nonce as big-endian 4 bytes
    input[4] = ((acc.nonce >> 24) & 0xFF) as u8;
    input[5] = ((acc.nonce >> 16) & 0xFF) as u8;
    input[6] = ((acc.nonce >> 8) & 0xFF) as u8;
    input[7] = (acc.nonce & 0xFF) as u8;

    let hash: [u8; 32] = std::hash::blake2s(input);
    bytes32_to_field(hash)
}

// Blake hash of two child nodes (64 bytes input)
fn hash_inode(left: Field, right: Field) -> Field {
    let left_bytes: [u8; 32] = left.to_be_bytes();
    let right_bytes: [u8; 32] = right.to_be_bytes();
    let mut input: [u8; 64] = [0; 64];
    for i in 0..32 {
        input[i] = left_bytes[i];
        input[32 + i] = right_bytes[i];
    }

    let hash: [u8; 32] = std::hash::blake2s(input);
    bytes32_to_field(hash)
}

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

        assert(tx.sender_index != tx.receiver_index, "Self-transfer");
        assert(sender.balance >= tx.amount, "Insufficient sender balance");
        assert(tx.sender_nonce == sender.nonce, "Mismatched nonce");

        let sender_leaf = hash_leaf(sender);
        let sender_root = build_root(sender_leaf, tx.sender_index, sender_siblings[i]);
        assert(sender_root == current_root, "Sender Merkle proof invalid");

        let mut updated_sender = sender;
        updated_sender.balance = sender.balance - tx.amount;
        updated_sender.nonce = sender.nonce + 1;
        let new_sender_leaf = hash_leaf(updated_sender);
        current_root = build_root(new_sender_leaf, tx.sender_index, sender_siblings[i]);

        let receiver_leaf = hash_leaf(receiver);
        let receiver_root = build_root(receiver_leaf, tx.receiver_index, receiver_siblings[i]);
        assert(receiver_root == current_root, "Receiver Merkle proof invalid");

        let mut updated_receiver = receiver;
        updated_receiver.balance = receiver.balance + tx.amount;
        let new_receiver_leaf = hash_leaf(updated_receiver);
        current_root = build_root(new_receiver_leaf, tx.receiver_index, receiver_siblings[i]);
    }

    assert(current_root == new_root, "Final root mismatch");
}

mod tests {
    use crate::{Account, hash_inode, hash_leaf, main, Transaction};

    #[test]
    fn test_valid_transaction() {
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

        let updated_sender =
            Account { balance: sender.balance - tx.amount, nonce: sender.nonce + 1 };
        let new_leaf0 = hash_leaf(updated_sender);

        let sender_siblings = [leaf1, inode23];
        let receiver_siblings = [new_leaf0, inode23];

        let new_receiver = Account { balance: receiver.balance + tx.amount, nonce: receiver.nonce };
        let new_leaf1 = hash_leaf(new_receiver);
        let new_inode01 = hash_inode(new_leaf0, new_leaf1);
        let new_root = hash_inode(new_inode01, inode23);

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
        let v = leaf1;
        println(f"sender_sibling_0 = {v}");
        let v = inode23;
        println(f"sender_sibling_1 = {v}");
        let v = new_leaf0;
        println(f"receiver_sibling_0 = {v}");
        let v = inode23;
        println(f"receiver_sibling_1 = {v}");
    }
}
