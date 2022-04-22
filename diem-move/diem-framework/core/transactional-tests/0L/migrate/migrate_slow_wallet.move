//# init --validators Alice
//! account: bob, 1000000, 0, validator
//! account: carol, 1000000


//! new-transaction
//! sender: diemroot
script {
    use DiemFramework::MigrateWallets;
    use DiemFramework::DiemAccount;
    fun main(vm: signer) { // alice's signer type added in tx.
      MigrateWallets::migrate_slow_wallets(&vm);
      assert!(DiemAccount::is_slow(@{{alice}}), 7357001);
      assert!(DiemAccount::is_slow(@{{bob}}), 7357002);
      assert!(!DiemAccount::is_slow(@{{carol}}), 7357003);
    }
}
// check: EXECUTED
