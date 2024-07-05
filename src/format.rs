use {
    anychain_core::Format,
    core::{default::Default, fmt},
};

#[derive(Default, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AptosFormat {
    #[default]
    Standard,
}

impl Format for AptosFormat {}

impl fmt::Display for AptosFormat {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Standard")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(AptosFormat::Standard.to_string(), "Standard");
    }
}
