// `Secret` has no serde Serialize, so a serializer cannot write the plain text.
fn requires_serialize<T: serde::Serialize>(_: &T) {}

fn main() {
    let secret = mmp_secret::Secret::new("token");
    requires_serialize(&secret);
}
