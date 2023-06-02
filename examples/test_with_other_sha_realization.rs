extern crate sha1 as my_sha;
use other_sha::Digest;

fn f(m: &[u8]) {
    println!("Message = {}", String::from_utf8_lossy(m));

    let mut other_h = other_sha::Sha1::new();
    other_h.update(m);
    let r = other_h.finalize();
    println!("{:x} - result of other SHA-1 algorithm", r);

    let mut h = my_sha::SHA1::new();
    h.add(&*my_sha::u8_slice_to_bool(m));
    println!("{} - result of my SHA-1 algorithm", h.finalize().getHex());

    println!("\n\n\n");
}

fn main() {
    f(b"hello world!");
    f(b"123");
    f(
        b"hi1sdogih3289qp3uopa;jfhpg7t9q2a;holfp9t8t3q2[09gha;oishdgaodshgvna\
        09ewyty3w96ythwgiihd;fasgy3982hlahdgaw8wtyghw09y3thsf983hw89ghs",
    );
    f(b"");
}
