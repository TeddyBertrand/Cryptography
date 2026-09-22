fn main() {
    println!("{}", greeting());
}

fn greeting() -> &'static str {
    "hello from G-CNA-500-MPL-5-1-mypgp-3"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn greeting_is_not_empty() {
        assert!(!greeting().is_empty());
    }
}
