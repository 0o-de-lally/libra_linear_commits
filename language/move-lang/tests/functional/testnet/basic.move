//! new-transaction
script {
    use 0x0::Testnet;
    fun main(account: &signer) {
        Testnet::initialize(account);
    }
}
// check: ABORTED
// check: 0

//! new-transaction
//! sender: association
script {
    use 0x0::Testnet;
    fun main() {
        Testnet::remove_testnet();
    }
}

//! new-transaction
script {
    use 0x0::Testnet;
    fun main() {
        Testnet::remove_testnet();
    }
}
// check: ABORTED
// check: 0
