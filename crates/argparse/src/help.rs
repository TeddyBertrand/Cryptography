use crate::arg::{Arg, Kind};
use crate::Parser;

/// Column layout of the generated help, in spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub usage_indent: usize,
    pub section_indent: usize,
    pub entry_indent: usize,
    pub label_width: usize,
    /// Title width of a section that carries its own help (positional without possible values).
    pub inline_width: usize,
    pub quote_values: bool,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            usage_indent: 4,
            section_indent: 2,
            entry_indent: 4,
            label_width: 16,
            inline_width: 18,
            quote_values: false,
        }
    }
}

enum Block<'a> {
    Section {
        title: &'static str,
        entries: Vec<(String, &'static str)>,
    },
    Inline(&'a Arg),
}

impl Parser {
    pub fn render_help(&self) -> String {
        let layout = &self.layout;
        let mut out = format!(
            "USAGE\n{}{} {}\n\nDESCRIPTION\n{}",
            " ".repeat(layout.usage_indent),
            self.bin,
            self.usage,
            self.about
        );
        for block in self.blocks() {
            out.push_str("\n\n");
            match block {
                Block::Section { title, entries } => {
                    out.push_str(&" ".repeat(layout.section_indent));
                    out.push_str(title);
                    for (label, help) in entries {
                        out.push('\n');
                        out.push_str(&entry(
                            layout.entry_indent,
                            &label,
                            layout.label_width,
                            help,
                        ));
                    }
                }
                Block::Inline(arg) => out.push_str(&entry(
                    layout.section_indent,
                    arg.name,
                    layout.inline_width,
                    arg.help,
                )),
            }
        }
        out
    }

    fn blocks(&self) -> Vec<Block<'_>> {
        let mut blocks: Vec<Block<'_>> = Vec::new();
        for arg in &self.args {
            match &arg.kind {
                Kind::Positional {
                    possible_values, ..
                } if !possible_values.is_empty() => blocks.push(Block::Section {
                    title: arg.name,
                    entries: possible_values
                        .iter()
                        .map(|(value, help)| (self.value_label(value), *help))
                        .collect(),
                }),
                Kind::Positional { .. } => blocks.push(Block::Inline(arg)),
                Kind::Flag { .. } => {
                    let title = arg.section.unwrap_or("OPTIONS");
                    let existing = blocks.iter_mut().find_map(|b| match b {
                        Block::Section { title: t, entries } if *t == title => Some(entries),
                        _ => None,
                    });
                    match existing {
                        Some(entries) => entries.push((arg.label(), arg.help)),
                        None => blocks.push(Block::Section {
                            title,
                            entries: vec![(arg.label(), arg.help)],
                        }),
                    }
                }
            }
        }
        blocks
    }

    fn value_label(&self, value: &str) -> String {
        if self.layout.quote_values {
            format!("\"{value}\"")
        } else {
            value.to_string()
        }
    }
}

fn entry(indent: usize, label: &str, width: usize, help: &str) -> String {
    let pad = " ".repeat(indent);
    let mut lines = help.lines();
    let first = format!("{pad}{label:<width$} {}", lines.next().unwrap_or(""));
    let mut out = first.trim_end().to_string();
    for line in lines {
        out.push('\n');
        out.push_str(&pad);
        out.push_str(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::{Arg, Group, Parser};

    #[test]
    fn renders_sections_from_arg_metadata() {
        let help = Parser::new("prog")
            .usage("SYS MODE [file]")
            .about("Does things.")
            .arg(Arg::positional("sys", "SYS").possible_value("a", "first system"))
            .group(Group::new("mode"))
            .arg(
                Arg::flag("go", "-g")
                    .values(&["X"])
                    .section("MODE")
                    .help("go\nsomewhere"),
            )
            .arg(Arg::flag("quiet", "-q").help("be quiet"))
            .arg(Arg::positional("file", "file").help("input file"))
            .render_help();
        let expected = "\
USAGE
    prog SYS MODE [file]

DESCRIPTION
Does things.

  SYS
    a                first system

  MODE
    -g X             go
    somewhere

  OPTIONS
    -q               be quiet

  file               input file";
        assert_eq!(help, expected);
    }
}
