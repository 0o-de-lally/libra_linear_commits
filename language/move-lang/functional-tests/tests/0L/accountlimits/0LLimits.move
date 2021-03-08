// //! account: alice, 100, 0
// //! account: bob, 100, 0

// //! new-transaction
// //! sender: libraroot
// script {
//     use 0x1::AccountLimits;
//     use 0x1::CoreAddresses;
//     use 0x1::GAS::GAS;
//     fun main(account: &signer) {
//         AccountLimits::update_limits_definition<GAS>(account, CoreAddresses::LIBRA_ROOT_ADDRESS(), 0, 10, 0, 0);
//     }
// }
// // check: "Keep(EXECUTED)"

// //! new-transaction
// //! sender: libraroot
// //! execute-as: alice
// script {
// use 0x1::AccountLimits;
// use 0x1::GAS::GAS;
// fun main(lr: &signer, alice_account: &signer) {
//     AccountLimits::publish_unrestricted_limits<GAS>(alice_account);
//     AccountLimits::update_limits_definition<GAS>(lr, {{alice}}, 0, 10, 0, 0);
//     AccountLimits::publish_window<GAS>(lr, alice_account, {{alice}});
// }
// }
// // check: "Keep(EXECUTED)"


// //! new-transaction
// //! sender: libraroot
// //! execute-as: bob
// script {
// use 0x1::AccountLimits;
// use 0x1::GAS::GAS;
// fun main(lr: &signer, bob_account: &signer) {
//     AccountLimits::publish_unrestricted_limits<GAS>(bob_account);
//     AccountLimits::update_limits_definition<GAS>(lr, {{bob}}, 0, 10, 0, 0);
//     AccountLimits::publish_window<GAS>(lr, bob_account, {{bob}});
//     assert(AccountLimits::has_limits_published<GAS>({{bob}}), 1);
//     assert(AccountLimits::has_limits_published<GAS>({{alice}}), 2);
// }
// }
// // check: "Keep(EXECUTED)"

// //! new-transaction
// // Transfers between accounts is disabled
// //! sender: alice
// //! gas-currency: GAS
// script {
// use 0x1::LibraAccount;
// use 0x1::GAS::GAS;
// fun main(account: &signer) {
//     let with_cap = LibraAccount::extract_withdraw_capability(account);
//     LibraAccount::pay_from<GAS>(&with_cap, {{bob}}, 11, x"", x"");
//     assert(LibraAccount::balance<GAS>({{alice}}) == 89, 0);
//     assert(LibraAccount::balance<GAS>({{bob}}) == 111, 1);
//     LibraAccount::restore_withdraw_capability(with_cap);
// }
// }
// // check: "Keep(ABORTED { code: 776,"

// //! new-transaction
// // Transfers between accounts is disabled
// //! sender: alice
// //! gas-currency: GAS
// script {
// use 0x1::LibraAccount;
// use 0x1::GAS::GAS;
// fun main(account: &signer) {
//     let with_cap = LibraAccount::extract_withdraw_capability(account);
//     LibraAccount::pay_from<GAS>(&with_cap, {{bob}}, 10, x"", x"");
//     assert(LibraAccount::balance<GAS>({{alice}}) == 90, 0);
//     assert(LibraAccount::balance<GAS>({{bob}}) == 110, 1);
//     LibraAccount::restore_withdraw_capability(with_cap);
// }
// }
// // check: "Keep(EXECUTED)"

// //! new-transaction
// // Transfers between accounts is disabled
// //! sender: alice
// //! gas-currency: GAS
// script {
// use 0x1::LibraAccount;
// use 0x1::GAS::GAS;
// fun main(account: &signer) {
//     let with_cap = LibraAccount::extract_withdraw_capability(account);
//     LibraAccount::pay_from<GAS>(&with_cap, {{bob}}, 10, x"", x"");
//     assert(LibraAccount::balance<GAS>({{alice}}) == 80, 0);
//     assert(LibraAccount::balance<GAS>({{bob}}) == 120, 1);
//     LibraAccount::restore_withdraw_capability(with_cap);
// }
// }
// // check: "Keep(ABORTED { code: 776,"
