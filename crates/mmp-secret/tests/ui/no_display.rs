// `Secret` has no Display, so formatting it with `{}` must not compile.
fn main() {
    let secret = mmp_secret::Secret::new("token");
    let _ = format!("{secret}");
}
