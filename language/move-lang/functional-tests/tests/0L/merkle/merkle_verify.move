///// Setting up the test fixtures for the transactions below. 
///// The tags below create validators alice and bob, giving them 1000000 GAS coins.

//! account: alice, 1000000, 0, validator
//! account: bob, 1000000, 0, validator
//! account: carol, 1000000, 0


///// DEMO 1: Happy case, the State resource is initialized to Alice's account, 
///// and can subsequently by written to, and read from.

///// This tag tells the test harness that what follows is a separate transaction 
///// from anything above, and that the sender is alice.

//! new-transaction
//! sender: alice
//! gas-currency: GAS
script {
    use 0x1::Merkle;
    use 0x1::Debug::print;

    // This sender argument was populated by the test harness with a random 
    // address for `alice`, which can be accessed with sender variable or 
    // the helper `{alice}`
    fun main(_alice: signer){ // alice's signer type added in tx.

      let a = Merkle::verify_sha3(b"test");
      print(&a);
    }
}