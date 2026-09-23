use std::collections::HashMap;

use crate::arg::{Arg, Group, Kind};
use crate::help::Layout;
use crate::Error;

#[derive(Debug, Clone)]
pub struct Parser {
    pub(crate) bin: &'static str,
    pub(crate) usage: &'static str,
    pub(crate) about: &'static str,
    pub(crate) layout: Layout,
    pub(crate) args: Vec<Arg>,
    groups: Vec<Group>,
    help_on_empty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Help,
    Matches(Matches),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Matches {
    values: HashMap<&'static str, Vec<String>>,
    groups: HashMap<&'static str, &'static str>,
}

impl Matches {
    pub fn is_present(&self, id: &str) -> bool {
        self.values.contains_key(id)
    }

    pub fn values(&self, id: &str) -> Option<&[String]> {
        self.values.get(id).map(Vec::as_slice)
    }

    pub fn value(&self, id: &str) -> Option<&str> {
        self.values(id)?.first().map(String::as_str)
    }

    /// Id of the group member that was given, if any.
    pub fn group(&self, name: &str) -> Option<&'static str> {
        self.groups.get(name).copied()
    }
}

impl Parser {
    pub fn new(bin: &'static str) -> Self {
        Self {
            bin,
            usage: "",
            about: "",
            layout: Layout::default(),
            args: Vec::new(),
            groups: Vec::new(),
            help_on_empty: false,
        }
    }

    /// No arguments at all fails with `Error::NoArguments` carrying the rendered help.
    pub fn help_on_empty(mut self, value: bool) -> Self {
        self.help_on_empty = value;
        self
    }

    pub fn usage(mut self, usage: &'static str) -> Self {
        self.usage = usage;
        self
    }

    pub fn about(mut self, about: &'static str) -> Self {
        self.about = about;
        self
    }

    pub fn layout(mut self, layout: Layout) -> Self {
        self.layout = layout;
        self
    }

    pub fn arg(mut self, arg: Arg) -> Self {
        self.args.push(arg);
        self
    }

    pub fn group(mut self, group: Group) -> Self {
        self.groups.push(group);
        self
    }

    pub fn parse<I>(&self, args: I) -> Result<Parsed, Error>
    where
        I: IntoIterator<Item = String>,
    {
        let tokens: Vec<String> = args.into_iter().collect();
        if tokens.is_empty() && self.help_on_empty {
            return Err(Error::NoArguments(self.render_help()));
        }
        if tokens.iter().any(|t| t == "-h" || t == "--help") {
            return Ok(Parsed::Help);
        }

        let mut matches = Matches::default();
        let mut positionals = self.args.iter().filter(|a| a.is_positional());
        let mut tokens = tokens.into_iter();

        while let Some(token) = tokens.next() {
            if let Some(arg) = self.args.iter().find(|a| a.matches_flag(&token)) {
                self.take_flag(arg, token, &mut tokens, &mut matches)?;
            } else if token.len() > 1 && token.starts_with('-') {
                return Err(Error::UnknownFlag(token));
            } else {
                let arg = positionals
                    .next()
                    .ok_or_else(|| Error::UnexpectedArgument(token.clone()))?;
                Self::take_positional(arg, token, &mut matches)?;
            }
        }

        self.validate(&mut matches)?;
        Ok(Parsed::Matches(matches))
    }

    fn take_flag(
        &self,
        arg: &Arg,
        token: String,
        rest: &mut impl Iterator<Item = String>,
        matches: &mut Matches,
    ) -> Result<(), Error> {
        if matches.is_present(arg.id) {
            return Err(Error::Duplicate(token));
        }
        let names: &[&str] = match &arg.kind {
            Kind::Flag { value_names, .. } => value_names,
            Kind::Positional { .. } => &[],
        };
        let mut values = Vec::with_capacity(names.len());
        for name in names {
            let value = rest.next().ok_or_else(|| Error::MissingValue {
                flag: token.clone(),
                value: (*name).to_string(),
            })?;
            values.push(value);
        }
        matches.values.insert(arg.id, values);
        Ok(())
    }

    fn take_positional(arg: &Arg, token: String, matches: &mut Matches) -> Result<(), Error> {
        if let Kind::Positional {
            possible_values, ..
        } = &arg.kind
        {
            if !possible_values.is_empty() && !possible_values.iter().any(|(v, _)| *v == token) {
                return Err(Error::InvalidValue {
                    arg: arg.name.to_string(),
                    value: token,
                });
            }
        }
        matches.values.insert(arg.id, vec![token]);
        Ok(())
    }

    fn validate(&self, matches: &mut Matches) -> Result<(), Error> {
        for arg in &self.args {
            if let Kind::Positional { required: true, .. } = arg.kind {
                if !matches.is_present(arg.id) {
                    return Err(Error::MissingRequired(arg.name.to_string()));
                }
            }
        }

        for group in &self.groups {
            let mut given = self
                .args
                .iter()
                .filter(|a| a.group == Some(group.name) && matches.is_present(a.id));
            match (given.next(), given.next()) {
                (Some(first), Some(second)) => {
                    return Err(Error::GroupConflict {
                        group: group.name.to_string(),
                        first: first.label(),
                        second: second.label(),
                    })
                }
                (Some(only), None) => {
                    matches.groups.insert(group.name, only.id);
                }
                (None, _) if group.required => {
                    return Err(Error::GroupMissing(group.name.to_string()))
                }
                (None, _) => {}
            }
        }

        for arg in self.args.iter().filter(|a| matches.is_present(a.id)) {
            for other in &arg.conflicts {
                if let Some(other) = self.args.iter().find(|a| a.id == *other) {
                    if matches.is_present(other.id) {
                        return Err(Error::Conflict {
                            first: arg.label(),
                            second: other.label(),
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parser() -> Parser {
        Parser::new("prog")
            .arg(Arg::positional("target", "TARGET").required(true))
            .arg(Arg::positional("extra", "EXTRA").conflicts_with("pair"))
            .group(Group::new("action").required(true))
            .arg(Arg::flag("run", "-r").long("--run").group("action"))
            .arg(Arg::flag("stop", "-s").group("action"))
            .arg(Arg::flag("pair", "-p").values(&["A", "B"]))
            .arg(Arg::flag("verbose", "-v"))
    }

    fn run(args: &[&str]) -> Result<Parsed, Error> {
        parser().parse(args.iter().map(|s| (*s).to_string()))
    }

    fn matches(args: &[&str]) -> Matches {
        match run(args) {
            Ok(Parsed::Matches(m)) => m,
            other => panic!("expected matches, got {other:?}"),
        }
    }

    #[test]
    fn empty_args_render_help_when_enabled() {
        let p = parser().help_on_empty(true);
        assert_eq!(
            p.parse(Vec::new()),
            Err(Error::NoArguments(p.render_help()))
        );
        assert_eq!(run(&[]), Err(Error::MissingRequired("TARGET".into())));
    }

    #[test]
    fn help_wins_anywhere() {
        assert_eq!(run(&["-h"]), Ok(Parsed::Help));
        assert_eq!(run(&["bogus", "--help", "-x"]), Ok(Parsed::Help));
    }

    #[test]
    fn flags_positionals_and_groups() {
        let m = matches(&["t", "--run", "-v", "e"]);
        assert_eq!(m.value("target"), Some("t"));
        assert_eq!(m.value("extra"), Some("e"));
        assert!(m.is_present("verbose"));
        assert_eq!(m.group("action"), Some("run"));
    }

    #[test]
    fn flag_values_consumed_in_order() {
        let m = matches(&["-s", "-p", "a", "b", "t"]);
        assert_eq!(
            m.values("pair"),
            Some(&["a".to_string(), "b".to_string()][..])
        );
        assert_eq!(m.value("target"), Some("t"));
    }

    #[test]
    fn missing_flag_value() {
        assert!(matches!(
            run(&["t", "-s", "-p", "a"]),
            Err(Error::MissingValue { .. })
        ));
    }

    #[test]
    fn unknown_flag() {
        assert_eq!(
            run(&["t", "-s", "-x"]),
            Err(Error::UnknownFlag("-x".into()))
        );
    }

    #[test]
    fn duplicate_flag() {
        assert_eq!(
            run(&["t", "-s", "-v", "-v"]),
            Err(Error::Duplicate("-v".into()))
        );
    }

    #[test]
    fn too_many_positionals() {
        assert_eq!(
            run(&["t", "e", "f", "-s"]),
            Err(Error::UnexpectedArgument("f".into()))
        );
    }

    #[test]
    fn missing_required_positional() {
        assert_eq!(run(&["-s"]), Err(Error::MissingRequired("TARGET".into())));
    }

    #[test]
    fn group_rules() {
        assert_eq!(run(&["t"]), Err(Error::GroupMissing("action".into())));
        assert!(matches!(
            run(&["t", "-r", "-s"]),
            Err(Error::GroupConflict { .. })
        ));
    }

    #[test]
    fn conflicting_args() {
        assert!(matches!(
            run(&["t", "e", "-s", "-p", "a", "b"]),
            Err(Error::Conflict { .. })
        ));
    }

    #[test]
    fn possible_values_enforced() {
        let p = Parser::new("prog").arg(Arg::positional("sys", "SYS").possible_value("a", ""));
        let ok = p.parse(["a".to_string()]);
        assert!(matches!(ok, Ok(Parsed::Matches(_))));
        let bad = p.parse(["b".to_string()]);
        assert!(matches!(bad, Err(Error::InvalidValue { .. })));
    }
}
