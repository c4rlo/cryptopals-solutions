extern crate crypto;
extern crate rand;

mod common;
mod set1;
mod set2;

fn main() {
    set1::run();
    set2::run();
}
