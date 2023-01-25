///////////////////////////////////////////////////////////////////
// InfraEscrow
// Manages the Infrastructure Escrow accounts
// Creates the escrow in validator accounts from balances
// keeps a list of the escrow holders
// withdraws from escrow as needed for current infrastructure costs. 
// (e.g. consensus subsidies for 0L's layer one) and other hypothetical future products (e.g. Oracle Networks, Layer 2, other layer ones).
///////////////////////////////////////////////////////////////////

address DiemFramework {

// # Summary 
// Per governance proposal #XXXX

// TODO: Bloom filter to quickly check who holds infraescrow accounts.

module InfraEscrow {
  // Danger: This function requires a Signer Type for both VM and user account. This function should only be callable by the VM on a genesis event.
  // Thus we use a "0L pseudocoma pattern": this is a private function which has no public API within the VM,
  // this forces us to call it from Rust on a writeset operation (which can be done on genesis.)
  // A test wrapper is created for transactional (functional) tests, limited to the testing scope.

  // When the hard fork occurs, the VM executes this migration.
  // the migration requires: creation of the account state in each validators account. This account state keeps some metadata, but mostly serves to contain the coins set aside for the escrow pledge.
  // Note: the infraescrow is not a pooled fund. It is a pledge of coins that remains in the user's account. The user being the validators, who join this pledge.
  fun create_on_fork(_vm: &signer, _validator: address) {

    // Iterate over the list of validators
    // check if each has the infra escrow struct.
    // if they do not, then create it.
    // Do not duplicate lists, use the validator list when needing a complete list of escrow accounts.
    // Update the bloom filter for quick checks for inclusion/exclusion.

  }


  /////// TEST WRAPPERS //////

  public fun test_create_on_fork(_vm: &signer, _validator: address) {
    // use DiemFramework::Testnet;
    // use Std::Errors;

    // assert!(
    //     Testnet::is_testnet(),
    //     Errors::requires_role(200201)
    // );
    // create_on_fork(_vm, _validator);
  }
}
}
