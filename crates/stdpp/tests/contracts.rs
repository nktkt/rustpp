use stdpp::prelude::*;

#[requires(value > 0)]
fn double(value: i32) -> i32 {
    value * 2
}

#[ensures(*result > 0)]
fn positive(value: i32) -> i32 {
    value
}

refined_type! {
    pub struct NonZeroI32(i32) where |value| *value != 0, "value must not be zero";
}

capability!(pub Db);

#[test]
fn requires_allows_valid_input() {
    assert_eq!(double(21), 42);
}

#[test]
#[should_panic(expected = "Rust++ requires failed")]
fn requires_rejects_invalid_input() {
    let _ = double(0);
}

#[test]
fn ensures_allows_valid_output() {
    assert_eq!(positive(7), 7);
}

#[test]
#[should_panic(expected = "Rust++ ensures failed")]
fn ensures_rejects_invalid_output() {
    let _ = positive(-1);
}

#[test]
fn refined_type_accepts_valid_value() {
    let value = NonZeroI32::try_from(7).expect("non-zero value should be accepted");

    assert_eq!(*value, 7);
    assert_eq!(value.into_inner(), 7);
}

#[test]
fn refined_type_rejects_invalid_value() {
    let error = NonZeroI32::try_from(0).expect_err("zero should be rejected");

    assert_eq!(error.message(), "value must not be zero");
}

#[test]
fn capability_macro_declares_named_effects() {
    assert_eq!(Db::NAME, "Db");
    assert_eq!(Effect::from(Db).name(), "Db");
}
