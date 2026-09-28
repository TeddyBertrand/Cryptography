use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    NoArguments(String),
    UnknownFlag(String),
    MissingValue {
        flag: String,
        value: String,
    },
    Duplicate(String),
    InvalidValue {
        arg: String,
        value: String,
    },
    UnexpectedArgument(String),
    MissingRequired(String),
    GroupConflict {
        group: String,
        first: String,
        second: String,
    },
    GroupMissing(String),
    Conflict {
        first: String,
        second: String,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoArguments(help) => write!(f, "{help}"),
            Self::UnknownFlag(flag) => write!(f, "unknown flag '{flag}'"),
            Self::MissingValue { flag, value } => write!(f, "missing value {value} for '{flag}'"),
            Self::Duplicate(flag) => write!(f, "'{flag}' given more than once"),
            Self::InvalidValue { arg, value } => write!(f, "invalid {arg} '{value}'"),
            Self::UnexpectedArgument(arg) => write!(f, "unexpected argument '{arg}'"),
            Self::MissingRequired(arg) => write!(f, "missing required {arg}"),
            Self::GroupConflict {
                group,
                first,
                second,
            } => {
                write!(
                    f,
                    "'{first}' and '{second}' are both {group}, only one allowed"
                )
            }
            Self::GroupMissing(group) => write!(f, "missing {group}"),
            Self::Conflict { first, second } => {
                write!(f, "'{first}' cannot be used with '{second}'")
            }
        }
    }
}

impl std::error::Error for Error {}
