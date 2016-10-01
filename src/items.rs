use std::collections::HashSet;
use regex::Regex;

pub struct ItemsSpec {
    items: HashSet<usize>,
    all_from: Option<usize>,
    everything: bool
}

impl ItemsSpec {
    pub fn new() -> Self {
        ItemsSpec {
            items: HashSet::new(),
            all_from: None,
            everything: true
        }
    }

    pub fn contains(&self, item: usize) -> bool {
        if self.everything {
            return true;
        }
        if let Some(from) = self.all_from {
            if from <= item {
                return true;
            }
        }
        self.items.contains(&item)
    }

    pub fn add(&mut self, item: usize) {
        self.everything = false;
        if let Some(from) = self.all_from {
            if from <= item {
                return;
            }
        }
        self.items.insert(item);
    }

    pub fn add_range(&mut self, from: usize, upto: usize) {
        self.everything = false;
        for i in from..(upto+1) {
            self.items.insert(i);
        }
    }

    pub fn add_all_from(&mut self, from: usize) {
        self.everything = false;
        if let Some(old_from) = self.all_from {
            if old_from < from {
                return;
            }
        }
        self.all_from = Some(from);
    }

    pub fn add_all_upto(&mut self, upto: usize) {
        self.everything = false;
        for i in 1..(upto+1) {
            self.items.insert(i);
        }
    }
}


pub struct ItemsParser {
    num_regex: Regex,
    range_regex: Regex
}

impl ItemsParser {
    pub fn new() -> Self {
        ItemsParser {
            num_regex: Regex::new(r"^\d+$").unwrap(),
            range_regex: Regex::new(r"^(\d*)-(\d*)$").unwrap()
        }
    }

    pub fn parse_arg(&self, items: &mut ItemsSpec, arg: &str)
                                                         -> Result<(), String> {
        if self.num_regex.is_match(arg) {
            items.add(arg.parse().unwrap());
        } else if let Some(caps) = self.range_regex.captures(arg) {
            fn parse_num(s: &Option<&str>) -> Option<usize> {
                if let Some(si) = *s {
                    if ! si.is_empty() {
                        return Some(si.parse().unwrap());
                    }
                }
                None
            }

            let low = parse_num(&caps.at(1));
            let high = parse_num(&caps.at(2));
            match (low, high) {
                (Some(l), Some(h)) => items.add_range(l, h),
                (Some(l), None)    => items.add_all_from(l),
                (None, Some(h))    => items.add_all_upto(h),
                (None, None)       => return Err(
                                           format!("illegal arg spec: {}", arg))
            }
        } else {
            return Err(format!("illegal arg spec: {}", arg));
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! ch {
    ($items:ident, $f:ident, $($e:expr),*) => (
        let challenge_len = "challenge".len();
        if $items.contains(stringify!($f)[challenge_len..].parse().unwrap()) {
            $f($($e),*);
        }
    );

    ($items:ident, $f:ident) => (ch!($items, $f, ));
}
