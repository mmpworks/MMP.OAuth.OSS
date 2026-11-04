//! Scenario S19: the type system keeps a `Secret` out of logs.
//!
//! Each file under `tests/ui/` must fail to compile, with the error recorded in its
//! `.stderr` file. If a later change adds `Display` or `Serialize` to `Secret`, a
//! file starts to compile and this test fails. Regenerate the `.stderr` files after
//! a toolchain change with `TRYBUILD=overwrite cargo test -p mmp-secret --test compile_fail`.

#[test]
fn secret_has_no_display_and_no_serialize() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/no_display.rs");
    cases.compile_fail("tests/ui/no_serialize.rs");
}
