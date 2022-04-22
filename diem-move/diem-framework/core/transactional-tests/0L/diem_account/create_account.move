//# init

// TODO: switch to unit tests?

//# run --admin-script --signers DiemRoot TreasuryCompliance
script {
use DiemFramework::XUS::XUS;
use DiemFramework::DiemAccount;
use Std::BCS;
fun main(_dr: signer, account: signer) {
    let account = &account;
    let addr: address = @DiemFramework11101;
    assert!(!DiemAccount::exists_at(addr), 83);
    DiemAccount::create_parent_vasp_account<XUS>(account, addr, BCS::to_bytes(&addr), x"aa", false);
}
}

//# run --admin-script --signers DiemRoot DesignatedDealer
script {
use DiemFramework::XUS::XUS;
use DiemFramework::DiemAccount;
fun main(_dr: signer, account: signer) {
    let account = &account;
    let addr: address = @DiemFramework11101;
    let with_cap = DiemAccount::extract_withdraw_capability(account);
    DiemAccount::pay_from<XUS>(&with_cap, addr, 10, x"", x"");
    DiemAccount::restore_withdraw_capability(with_cap);
    assert!(DiemAccount::balance<XUS>(addr) == 10, 84);
    assert!(DiemAccount::sequence_number(addr) == 0, 84);
}
}
