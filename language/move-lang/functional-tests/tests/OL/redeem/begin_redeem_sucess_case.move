// Alice Submit VDF Proof
//! new-transaction
//! account: alice, 10000000GAS
//! sender: alice
script {
use 0x0::Redeem;
use 0x0::Transaction;

fun main() {

    let difficulty = 100;
    let challenge = x"aa";
    // Generate solutions with cd ./verfiable-delay/ cargo run -- -l=4096 aa 100
    // the -l=4096 is important because this is the security paramater of 0L miner.
    let solution = x"002fb6ae7221c8593fb21599fdbee8837426761b328f76609295c9175d5f061bb29792236d22366d0d9305040661b54f59cea3f8e143a584f178981549b462bdc96a3ef270dc1457985390a3401c484b721fdd00f0330b894755d34a311c547b73065aec1a71528d0dc350c13fa68aaf34d206a5fa56f7391b889f1226d7aacc3624eca7f27d523db4f2f18e4ca0bd4cd91b4133cce16b40245d9d393a0c32013f91c5d2bfaca7e5e4c4f71ea90bdc9047657e02e7a429b3f4988b3a7f0789a6c4e0b60af26139dba0c5a83eecc785dbdde0012e47ef3af7fe60e366b8e87ac437da111c8ffb57f400980513b47db04c47787380ea564ffaf1653aa5889e5b31340022cfdd5956cf2fc9130ea4e45a700a5fbd990aae8a4643b22508b6d0b6b80186b5eea2c656296ad2d2043867bd93d48a284b90c2792aeeb25f6a7f0dacac617e7660074e18109e6675480ebc6340f4b01d74d8e5943b9bc8f9acdb3d8ebef5f593858913ebbc2f0d4b1fc76dacca4b032bb8d97e018a614e667bbbb07da891d23028b60275bc2c715e975b347c2e72e5753282959973f34742a43393d76b025b6444e4cabf4272eceae3d94a19ae1f24edf725e8892eb45f34e8a224a5ee56effa8f4b5a3a3bf810579cba99f0e954ce8459afe963bbb2c2578bd5de48e6df56a29ef03dda9e03e19c08fed8b467065afd38720f634c646698a1841c4a21037700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";

    // return solution
    let proof = Redeem::create_proof_blob(challenge, difficulty, solution);
    Transaction::assert(5 == 5, 1);

    Redeem::begin_redeem(proof);

}
}
// check: EXECUTED

// // Bob Submit end_redeem Transaction. Only the one who initialed Redeem module can execute this transaction.
// //! new-transaction
// //! sender: config
// script {
// use 0x0::Redeem;
// fun main() {
//
//     Redeem::end_redeem({{alice}});
// }
// }
// // check: EXECUTED
