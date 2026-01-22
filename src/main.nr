fn main(w: Field, y: pub Field) {
    // Prove knowledge of w such that 2*w^2 = y
    // Field:from(2) means embed the integer 2 into the finite field used by the circuitno
    let lhs = Field::from(2) * w * w;
    assert(lhs == y);
}
