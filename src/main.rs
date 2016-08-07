extern crate crypto;
extern crate rand;
extern crate regex;

mod common;
#[macro_use]
mod items;
mod set1;
mod set2;

use std::env;
use std::io::Write;

fn parse_item_spec<T: IntoIterator<Item=String>>(args: T) -> Result<items::ItemsSpec, String> {
    let parser = items::ItemsParser::new();
    let mut spec = items::ItemsSpec::new();
    for arg in args {
        try!(parser.parse_arg(&mut spec, &arg));
    }
    Ok(spec)
}

fn main() {
    match parse_item_spec(env::args().skip(1)) {
        Ok(spec) => {
            set1::run(&spec);
            set2::run(&spec);
        },
        Err(msg) => writeln!(std::io::stderr(), "{}", &msg).unwrap()
    }
}
