///////////////////////////////////////////////////////////////////
// Migrate Balance
// 
///////////////////////////////////////////////////////////////////

address DiemFramework {

/// # Summary 
/// Per governance proposal #XXXX

module MigrateBalance {
  // this can only happen at genesis. It requires the Rust side to iterate
  // through the full list of addresses in the system. Presumably from the Export JSON.

  // Tracker struct
  // VM instantiates this tracking state on genesis, before any splitting can happen.
  // on genesis take the systemwide balance, multiply by the split factor for the hard cap.
  // instantiate the migrated balances tracker at 0


  // The fuction which at genesis splits the account coins.
  // this is dangerous since it requires a Signer type for both VM and the user.
  // Thus we use a "0L pseudocoma pattern": this is a private function which has no public API within the VM,
  // this forces us to call it from Rust on a writeset operation (which can be done on genesis.)
  fun account_balance_split(_vm: &signer, _user: &signer) {
    // check there is a balance, and the balance is not zero. Exit early.

    // safety check: that we haven't split more coins than the hard cap.
    // safety check: that the total system balance is not greater than the hard cap.

    // split the v5 tokens into v6 tokens.

    // if the account is a validator, then apply the infrastructure escrow procedures
  }
}
}
