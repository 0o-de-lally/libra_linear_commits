//# init --validators Alice Bob Jim

// Test runs various autopay instruction types to ensure they are being
// executed as expected

//# run --admin-script --signers DiemRoot Jim
script {
    use DiemFramework::Wallet;
    use Std::Vector;

  fun main(_dr: signer, sender: signer) {
      Wallet::set_comm(&sender);
      let list = Wallet::get_comm_list();
      assert!(Vector::length(&list) == 1, 7357001);
    }
}
// check: EXECUTED

// alice commits to paying jim 5% of her worth per epoch
//# run --admin-script --signers DiemRoot Alice
script {
  use DiemFramework::AutoPay;
  use Std::Signer;
  fun main(_dr: signer, sender: signer) {
    let sender = &sender;
    AutoPay::enable_autopay(sender);
    assert!(AutoPay::is_enabled(Signer::address_of(sender)), 0);
    
    // instruction type percent of balance
    AutoPay::create_instruction(
      sender,
      1, // UID
      0, // percent of balance type
      @Jim,
      2, // until epoch two
      500 // 5 percent
    );

    let (type, payee, end_epoch, percentage) = AutoPay::query_instruction(
      Signer::address_of(sender), 1
    );
    assert!(type == 0, 735701);
    assert!(payee == @Jim, 735702);
    assert!(end_epoch == 2, 735703);
    assert!(percentage == 500, 735704);
  }
}
// check: EXECUTED


///////////////////////////////////////////////////
///// Trigger Autopay Tick at 31 secs /////
///// i.e. 1 second after 1/2 epoch   /////
///////////////////////////////////////////////////
//# block --proposer Bob --time 31000000 --round 23

//# run --admin-script --signers DiemRoot DiemRoot
script {
  use DiemFramework::DiemAccount;
  use DiemFramework::GAS::GAS;

  fun main() {
    let ending_balance = DiemAccount::balance<GAS>(@Alice);
    assert!(ending_balance == 9500001, 735705);
  }
}
// check: EXECUTED

///////////////////////////////////////////////////
///// Trigger Autopay Tick at 31 secs /////
///// i.e. 1 second after 1/2 epoch   /////
///////////////////////////////////////////////////
//# block --proposer Bob --time 61000000 --round 65

///////////////////////////////////////////////////
///// Trigger Autopay Tick at 31 secs /////
///// i.e. 1 second after 1/2 epoch   /////
///////////////////////////////////////////////////
//# block --proposer Bob --time 92000000 --round 66

///////////////////////////////////////////////////
///// Trigger Autopay Tick at 31 secs /////
///// i.e. 1 second after 1/2 epoch   /////
///////////////////////////////////////////////////
//# block --proposer Bob --time 93000000 --round 67

//# run --admin-script --signers DiemRoot DiemRoot
script {
  use DiemFramework::DiemAccount;
  use DiemFramework::GAS::GAS;

  fun main() {
    let ending_balance = DiemAccount::balance<GAS>(@Alice);
    assert!(ending_balance == 9025001, 735711);

    // check balance of recipients
    let ending_balance = DiemAccount::balance<GAS>(@Jim);
    assert!(ending_balance == 10974999, 735712);
  }
}
// check: EXECUTED