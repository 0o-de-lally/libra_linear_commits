/////////////////////////////////////////////////////////////////////////
// 0L Module
// Self Service
// Error code: 1905
/////////////////////////////////////////////////////////////////////////

// TL;DR the guarantees that Self Service offers is: workers pay themselved. By default they will be paid, we assume honesty. Some attacks are possible, and that's explicitly ok. It's not profitable to try to amplify attacks because time delays and bonds kick in as there are more pending payments int he system.

// Games need to have an equilibrium. In any community the honest actors always pay for the actions of bad actors. There's monetary cost, and demotivation, and that can push the game out of balance. But fraud in games is not always obvious to identify, but equally important, it's not necessarily something that should be eliminated entirely. There's an addage in payment processing: "only way to remove fraudulent transactions is to also remove the revenue".

// Self Service Buffet is a payment processing game for DAOs which optimizes for revenue, not for fraud prevention.

// DAO payments often tend towards practices of companies: delivering work, send a report, then an invoice, getting invoice approved, and later finding the funds and authorizing transactions. This has a feeling of safety. It is process oriented, and appears more orderly. But it leaves money on the table for both the workers and for the protocols.

// The greatest cost in such a system is opportunity cost. How much work is the DAO failing to get done, because it is optimizing for minimal fraud?

// Obviously, fraud can't be ignored.  But if we can limit the damage of the fraud, in material terms, and in psychological demotivation, while creating an automated process, we might have a net increase in value.



// The premise of Self-service buffet is that fraud prevention for work is gated by the amount of people monitoring the scheme. The team monitoring the entire flow of payments before, can instead be a small committee, that monitors for fraud (and this committee can obviously be expanded or reduced algorithmically, but that's not a concern here)

// Product requirements:

// Optimize for Net Payments. A few attacks is fine, if there is a net gain in productivity. But repeated attacks on scale should not be profitable.

// Distraction of the fraud monitoring team can be attacked, the policies should prevent monitors from getting overwhelmed.

// Expensive griefing: if just for fun someone spams requests so to prevent good actors from getting paid, the cost should increase until it is prohibitive.


// Mechanism:

// Each payment request has a Credit Limit, a maximum amount which can be disbursed. Note: credit limits are not per account, there is no reputation.

// Anyone can request multiple payments to circumvent Credit Limit. Thus requesting payments has a cost. The cost is time and a bond. 

// The costs increase as a function of two variables: 1) count of pending payments and 2) the value of pending payments.

// The expected effect is that while there are few payments in the network of low value, the Police have easy work. When there are many requests, the police have more time to sift through the payments. 

// rejected payments forfeit the bond. The bond is forfeitted and goes into the funding pool.

// Griefing attacks (submitting spam requests to slow down payments for honest actors) will require increasing amounts of bonds.

// And after a certain amount of pending payment (by value) are reached threshold a bond must also be placed, to prevent spam. In the ordinary course of events, with few payments below a value threshold, people get paid.

// Until there are 10 pending payments, the Delay is 3 epochs (days), and the Bond is 0.

address 0x1 {
  module SelfService {
    use 0x1::GAS::GAS;

    // gets initialized to a worker account when they submit a request for payment.
    struct Worker has key {
      pending_value: u64,
      pending_bond: u64,
      cumulative_payment: u64,
    }

    // gets initialized to the DAO address on init_dao()
    struct Buffet has key {
      balance: GAS,
      funder_addr: vector<address>,
      funder_value: vector<u64>,
      police_list: vector<address>,
      pending_payments: vector<Payment>,
      max_uid: u64,
    }

    struct Payment has key, store {
      uid: u64,
      worker: address,
      value: u64,
      epoch_requested: u64,
      deliverable: vector<u8>,
      bond: GAS,
      rejection: vector<address>
    }



    ///////// WORKER FUNCTIONS ////////

    public fun pay_me(_sender: &signer, _from_dao: address, _amount: u64, _deliverable: vector<u8>, _bond: u64) {

    }

    // Lazy computation. Payments need to be released by someone (there is no automatic scheduler).
    // Anyone who wants to get paid can submit the release all. It will release all payments for everyone that is due.
    public fun release_all(_sender: &signer, _from_dao: address) {

    }

    ////////// SPONSOR FUNCTIONS //////////

    // anyone can fund the pool. It doesn't give you any rights or governance.
    public fun fund_it(_sender: &signer, _from_dao: address, amount: u64) {

    }

    ////////// MANAGMENT FUNCTIONS //////////

    // a DAO can initialize their address with this state.
    // all transactions in the future need to reference the DAO address
    // this also creates the first Police address, which can subsequently onboard other people.
    public fun init_dao(_sender: &signer) {

    }

    // it takes one police member to reject a payment.
    public fun reject_payment(_sender: &signer, _uid: u64) {

    }

    // police can explicitly approve a payment faster
    public fun expedite_payment(_sender: &signer, _uid: u64) {

    }

    // if you are on the list you can add another police member
    public fun add_police(_sender: &signer, _new_police: address) {

    }

    // if you are on the list you can remove another police member
    public fun remove_police(_sender: &signer, _new_police: address) {
      
    }

    ////////// CALCS //////////
    fun get_bond(dao_addr: address) {

    }

    fun get_delay(dao_addr: address) {

    }
  }
}