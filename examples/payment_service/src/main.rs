use stdpp::prelude::*;

type Result<T> = std::result::Result<T, PaymentError>;
type Money = i64;
type PaymentId = u64;
type UserId = u64;

capability!(Db);
capability!(Time);

refined_type! {
    struct PositiveMoney(Money) where |value| *value > 0, "amount must be positive";
}

#[derive(Debug, Eq, PartialEq)]
struct PaymentError(&'static str);

trait PaymentRepository {
    async fn insert(&mut self, user: UserId, amount: PositiveMoney) -> Result<PaymentId>;
}

#[derive(Default)]
struct InMemoryPaymentRepository {
    next_id: PaymentId,
    rows: Vec<(PaymentId, UserId, Money)>,
}

impl PaymentRepository for InMemoryPaymentRepository {
    async fn insert(&mut self, user: UserId, amount: PositiveMoney) -> Result<PaymentId> {
        let amount = amount.into_inner();
        self.next_id += 1;
        self.rows.push((self.next_id, user, amount));
        Ok(self.next_id)
    }
}

#[component]
struct PaymentService<R: PaymentRepository> {
    repo: R,
}

#[contract]
impl<R: PaymentRepository> PaymentService<R> {
    fn new(repo: R) -> Self {
        Self { repo }
    }

    #[effects(Db, Time)]
    #[ensures(result.is_ok())]
    async fn charge(&mut self, user: UserId, amount: PositiveMoney) -> Result<PaymentId> {
        self.repo.insert(user, amount).await
    }
}

fn main() {
    let repo = InMemoryPaymentRepository::default();
    let mut service = PaymentService::new(repo);
    let amount = PositiveMoney::try_from(1_500).expect("amount should be valid");
    let id = asyncx::block_on(service.charge(42, amount)).expect("payment should succeed");

    println!("payment_id={id}");
}
