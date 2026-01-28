use std::hash::pedersen_hash;

global DEPTH: u32 = 2;

// computes the merkle tree leaf by hashing the given account's balance and nonce
fn hash_leaf(balance: u32, nonce: u32) -> Field {
    // balance and nonce are represented as ints for safe arithmetic and are then converted to fields for hashing
    let balance_field = balance as Field;
    let nonce_field = nonce as Field;

    pedersen_hash([balance_field, nonce_field])
}

struct Tx {
    from: u32,
    to: u32,
    amount: u32,
}

fn main(old_balances: [u32; 4], txs: [Tx; 2], old_root: pub Field, new_root: pub Field) {
    // verify that the old balances hash to the old root
    let old_balances_field: [Field; 4] = [
        old_balances[0] as Field,
        old_balances[1] as Field,
        old_balances[2] as Field,
        old_balances[3] as Field,
    ];

    assert(pedersen_hash(old_balances_field) == old_root);

    let mut balances = old_balances;

    for i in 0..2 {
        let tx = txs[i];

        // verify that the account indices are within bounds
        assert(tx.from < 4);
        assert(tx.to < 4);

        // verify that the sender's balance is sufficient for the transaction
        assert(balances[tx.from] >= tx.amount);

        // apply the transfer
        balances[tx.from] -= tx.amount;
        balances[tx.to] += tx.amount;
    }

    // verify that the new balances hash to the new root
    let new_balances_field: [Field; 4] =
        [balances[0] as Field, balances[1] as Field, balances[2] as Field, balances[3] as Field];

    assert(pedersen_hash(new_balances_field) == new_root);
}
