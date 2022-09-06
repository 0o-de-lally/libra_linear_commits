use ol_swarm::swarm_wrap::OLSwarm;
use diem_types::PeerId as AccountAddress;
use forge::NodeExt;

#[tokio::test]

async fn ol_sanity() {
    let swarm = OLSwarm::new().await.unwrap().get_inner();
    let client = swarm.validators().next().unwrap().rest_client();

    let b = client.get_account_balances(AccountAddress::ZERO).await.unwrap();
    let v = b.inner().into_iter()
        .find(|amount_view| amount_view.amount > 0)
        .unwrap();
    assert!(v.amount == 10000000);
}
