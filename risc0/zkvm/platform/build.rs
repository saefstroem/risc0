fn main() {
    println!("cargo::rustc-check-cfg=cfg(risc0_guest_allocator, values(\"embedded\"))");
}
