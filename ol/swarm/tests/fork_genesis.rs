use ol_swarm::swarm_wrap::OLSwarm;
use diem_types::PeerId as AccountAddress;
use forge::NodeExt;

#[tokio::test]

async fn fork_genesis() {
    let swarm = OLSwarm::new().unwrap().get_inner();


    vm_genesis::encode_recovery_genesis_changeset();
    // let client = swarm.validators().next().unwrap().rest_client();

    // let b = client.get_account_balances(AccountAddress::ZERO).await.unwrap();
    // let v = b.inner().into_iter()
    //     .find(|amount_view| amount_view.amount > 0)
    //     .unwrap();
    // assert!(v.amount == 10000000);
}
