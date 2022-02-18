/////////////////////////////////////////////////////////////////////////
// 0L Module
// Self Service Buffet
// Error code: 
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
    use 0x1::Vector;
    use 0x1::Signer;
    use 0x1::DiemConfig;
    use 0x1::Diem;

    // gets initialized to a worker account when they submit a request for payment.
    struct Worker has key {
      pending_value: u64,
      pending_bond: u64,
      cumulative_payment: u64,
    }

    // gets initialized to the DAO address on init_dao()
    struct Buffet has key {
      balance: Diem::Diem<GAS>,
      bond: Diem::Diem<GAS>, // Bond is here because it cannot be dropped
      funder_addr: vector<address>,
      funder_value: vector<u64>,
      police_list: vector<address>,
      pending_payments: vector<Payment>,
      max_uid: u64,
    }

    struct Payment has key, store, drop {
      uid: u64,
      worker: address,
      value: u64,
      epoch_requested: u64,
      epoch_due: u64,
      deliverable: vector<u8>,
      bond: u64, // NOTE: can't have the bond as the actual coin here, because this struct needs the 'drop' ability.
      rejection: vector<address>
    }

    ///////// WORKER FUNCTIONS ////////

    public fun pay_me(_sender: &signer, _from_dao: address, _amount: u64, _deliverable: vector<u8>, _bond: u64) {

      maybe_init_worker(_sender);
      // if it exists get the buffet object

      // calculate the date it will receive.
      // check if the bond is adequate.
      // push the payment onto the list

    }

    // Lazy computation. Payments need to be released by someone (there is no automatic scheduler).
    // Anyone who wants to get paid can submit the release all. It will release all payments for everyone that is due.
    public fun release_all(_sender: &signer, _from_dao: address) {

      // iterate through all the list of pending payments, and do maybe_make_payment

    }

    ////////// SPONSOR FUNCTIONS //////////

    // anyone can fund the pool. It doesn't give you any rights or governance.
    public fun fund_it(_sender: &signer, _dao: address, _new_deposit: Diem::Diem<GAS>) acquires Buffet {
      let b = borrow_global_mut<Buffet>(_dao);
      Diem::deposit<GAS>(&mut b.balance, _new_deposit);

      // TODO: add to funder table.

    }

    ////////// MANAGMENT FUNCTIONS //////////

    // a DAO can initialize their address with this state.
    // all transactions in the future need to reference the DAO address
    // this also creates the first Police address, which can subsequently onboard other people.
    public fun init_dao(_sender: &signer) {
      let new_buffet = Buffet {
        balance: Diem::zero<GAS>(),
        bond: Diem::zero<GAS>(),
        funder_addr: Vector::empty<address>(),
        funder_value: Vector::empty<u64>(),
        police_list: Vector::empty<address>(),
        pending_payments: Vector::empty<Payment>(),
        max_uid: 0,
      };
      move_to<Buffet>(_sender, new_buffet)
    }

    // it takes one police member to reject a payment.
    public fun reject_payment(_dao_addr: address, _sender: &signer, _uid: u64) acquires Buffet {
      if (is_police(_dao_addr, Signer::address_of(_sender))) {
        let (t, i) = get_index_by_uid(_dao_addr, _uid);
        if (t) {
          let b = borrow_global_mut<Buffet>(_dao_addr);
          Vector::remove(&mut b.pending_payments, i);
        }
      };
    }

    // police can explicitly approve a payment faster
    public fun expedite_payment(_dao_addr: address, _sender: &signer, _uid: u64) acquires Buffet {
      if (is_police(_dao_addr, Signer::address_of(_sender))) {
        maybe_make_payment(_dao_addr, _uid);
      };
    }

    // if you are on the list you can add another police member
    public fun add_police(_dao_addr: address, _sender: &signer, _new_police: address) acquires Buffet{
      if (is_police(_dao_addr, Signer::address_of(_sender))) {
        let b = borrow_global_mut<Buffet>(_dao_addr);
        Vector::push_back<address>(&mut b.police_list, _new_police);
      }

    }

    // if you are on the list you can remove another police member
    public fun remove_police(_dao_addr: address, _sender: &signer, _out_police: address) acquires Buffet {
      if (is_police(_dao_addr, Signer::address_of(_sender))) {
        let b = borrow_global_mut<Buffet>(_dao_addr);
        let (t, i) = Vector::index_of<address>(&b.police_list, &_out_police);
        if (t) {
          Vector::remove<address>(&mut b.police_list, i);
        }
       
      }
    }

    ////////// CALCS //////////

    fun get_bond_value(_dao_addr: address): u64 {
      // TODO: decide on the curve
      1
    }

    fun get_epochs_delay(_dao_addr: address): u64 {
      // TODO: decide on the curve
      2
    }

    ///////// PRIVATE FUNCTIONS ////////
    fun maybe_make_payment(_dao_addr: address, _uid: u64) acquires Buffet {
      let (t, i) = get_index_by_uid(_dao_addr, _uid);
      if (!t) return; // TODO make this an assert with Error
      let b = borrow_global_mut<Buffet>(_dao_addr);
      let p = Vector::borrow<Payment>(&b.pending_payments, i);
      if (p.epoch_due >= DiemConfig::get_current_epoch()) {
        // TODO: Make payment
        // p.value
      };

      // remove the element from vector if successful.
      let _ = Vector::remove<Payment>(&mut b.pending_payments, i);

    }

    fun is_police(_dao_addr: address, _addr: address): bool acquires Buffet {
      let b = borrow_global<Buffet>(_dao_addr);
      Vector::contains<address>(&b.police_list, &_addr)
    }

    fun maybe_init_worker(_sender: &signer) {
      if (!exists<Worker>(Signer::address_of(_sender))) {
        move_to<Worker>(_sender, Worker {
          pending_value: 0,
          pending_bond: 0,
          cumulative_payment: 0,
        })
      }
    }

    // removes an element from the list of payments, and returns in to scope.
    // need to add it back to the list
    fun get_index_by_uid(_dao_addr: address, _uid: u64): (bool, u64) acquires Buffet {
      let b = borrow_global<Buffet>(_dao_addr);
      let len = Vector::length<Payment>(&b.pending_payments);

      let i = 0;
      while (i < len) {
        let p = Vector::borrow<Payment>(&b.pending_payments, i);

        if (p.uid == _uid) return (true, i);

        i = i + 1;
      };
      (false, 0)
    }
  }
}