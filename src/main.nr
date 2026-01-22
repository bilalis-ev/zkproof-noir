use std::hash::pedersen_hash;

fn main(balances: [Field; 4], old_root: pub Field) {
    let new_root = pedersen_hash(balances);
    assert(new_root == old_root);
}
