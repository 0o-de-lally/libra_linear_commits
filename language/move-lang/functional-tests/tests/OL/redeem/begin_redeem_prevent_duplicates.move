//! account: bob, 10000000LBR
//! account: alice, 10000000LBR

// Initialize Redeem Module
//! new-transaction
//! sender: config
script {
use 0x0::Redeem;
fun main(s: &signer) {
    Redeem::initialize(s);
}
}
// check: EXECUTED

// Bob Submit VDF Proof
//! new-transaction
//! sender: bob
script {
use 0x0::Redeem;
fun main() {

    let difficulty = 100;
    let challenge = x"aa";
    let solution = x"005271e8f9ab2eb8a2906e851dfcb5542e4173f016b85e29d481a108dc82ed3b3f97937b7aa824801138d1771dea8dae2f6397e76a80613afda30f2c30a34b040baaafe76d5707d68689193e5d211833b372a6a4591abb88e2e7f2f5a5ec818b5707b86b8b2c495ca1581c179168509e3593f9a16879620a4dc4e907df452e8dd0ffc4f199825f54ec70472cc061f22eb54c48d6aa5af3ea375a392ac77294e2d955dde1d102ae2ace494293492d31cff21944a8bcb4608993065c9a00292e8d3f4604e7465b4eeefb494f5bea102db343bb61c5a15c7bdf288206885c130fa1f2d86bf5e4634fdc4216bc16ef7dac970b0ee46d69416f9a9acee651d158ac64915b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";

    let proof = Redeem::create_proof_blob(challenge, difficulty, solution);
    Redeem::begin_redeem( proof);

}
}
// check: EXECUTED

// Alice Submit the Duplicated VDF Proof.
//! new-transaction
//! sender: alice
script {
use 0x0::Redeem;
fun main() {

    let difficulty = 100;
    let challenge = x"aa";
    let solution = x"005271e8f9ab2eb8a2906e851dfcb5542e4173f016b85e29d481a108dc82ed3b3f97937b7aa824801138d1771dea8dae2f6397e76a80613afda30f2c30a34b040baaafe76d5707d68689193e5d211833b372a6a4591abb88e2e7f2f5a5ec818b5707b86b8b2c495ca1581c179168509e3593f9a16879620a4dc4e907df452e8dd0ffc4f199825f54ec70472cc061f22eb54c48d6aa5af3ea375a392ac77294e2d955dde1d102ae2ace494293492d31cff21944a8bcb4608993065c9a00292e8d3f4604e7465b4eeefb494f5bea102db343bb61c5a15c7bdf288206885c130fa1f2d86bf5e4634fdc4216bc16ef7dac970b0ee46d69416f9a9acee651d158ac64915b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";

    let proof = Redeem::create_proof_blob(challenge, difficulty, solution);
    Redeem::begin_redeem(proof);
}
}
// check: ABORTED 10000