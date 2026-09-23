#[derive(Debug, Clone)]
pub(crate) enum Kind {
    Flag {
        long: Option<&'static str>,
        value_names: Vec<&'static str>,
    },
    Positional {
        possible_values: Vec<(&'static str, &'static str)>,
        required: bool,
    },
}

#[derive(Debug, Clone)]
pub struct Arg {
    pub(crate) id: &'static str,
    pub(crate) name: &'static str,
    pub(crate) kind: Kind,
    pub(crate) help: &'static str,
    pub(crate) section: Option<&'static str>,
    pub(crate) group: Option<&'static str>,
    pub(crate) conflicts: Vec<&'static str>,
}

impl Arg {
    pub fn flag(id: &'static str, short: &'static str) -> Self {
        Self::new(
            id,
            short,
            Kind::Flag {
                long: None,
                value_names: Vec::new(),
            },
        )
    }

    pub fn positional(id: &'static str, name: &'static str) -> Self {
        Self::new(
            id,
            name,
            Kind::Positional {
                possible_values: Vec::new(),
                required: false,
            },
        )
    }

    fn new(id: &'static str, name: &'static str, kind: Kind) -> Self {
        Self {
            id,
            name,
            kind,
            help: "",
            section: None,
            group: None,
            conflicts: Vec::new(),
        }
    }

    pub fn long(mut self, long: &'static str) -> Self {
        if let Kind::Flag { long: slot, .. } = &mut self.kind {
            *slot = Some(long);
        }
        self
    }

    pub fn values(mut self, names: &[&'static str]) -> Self {
        if let Kind::Flag { value_names, .. } = &mut self.kind {
            *value_names = names.to_vec();
        }
        self
    }

    pub fn possible_value(mut self, value: &'static str, help: &'static str) -> Self {
        if let Kind::Positional {
            possible_values, ..
        } = &mut self.kind
        {
            possible_values.push((value, help));
        }
        self
    }

    pub fn required(mut self, value: bool) -> Self {
        if let Kind::Positional { required, .. } = &mut self.kind {
            *required = value;
        }
        self
    }

    /// Multi-line help is written with `\n`; continuation lines are re-indented on render.
    pub fn help(mut self, help: &'static str) -> Self {
        self.help = help;
        self
    }

    pub fn section(mut self, section: &'static str) -> Self {
        self.section = Some(section);
        self
    }

    pub fn group(mut self, group: &'static str) -> Self {
        self.group = Some(group);
        self
    }

    pub fn conflicts_with(mut self, id: &'static str) -> Self {
        self.conflicts.push(id);
        self
    }

    pub(crate) fn matches_flag(&self, token: &str) -> bool {
        match &self.kind {
            Kind::Flag { long, .. } => self.name == token || *long == Some(token),
            Kind::Positional { .. } => false,
        }
    }

    pub(crate) fn is_positional(&self) -> bool {
        matches!(self.kind, Kind::Positional { .. })
    }

    pub(crate) fn label(&self) -> String {
        match &self.kind {
            Kind::Flag { value_names, .. } if !value_names.is_empty() => {
                format!("{} {}", self.name, value_names.join(" "))
            }
            _ => self.name.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Group {
    pub(crate) name: &'static str,
    pub(crate) required: bool,
}

impl Group {
    /// Members are mutually exclusive; `required` means exactly one must be given.
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            required: false,
        }
    }

    pub fn required(mut self, required: bool) -> Self {
        self.required = required;
        self
    }
}
