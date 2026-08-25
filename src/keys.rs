use anyhow::{bail, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputKey {
    Char(char),
    Enter,
    Esc,
    Up,
    Down,
    Backspace,
    Tab,
}

pub fn parse_keys(sequence: &str, stdin_value: &str) -> Result<Vec<InputKey>> {
    let mut output = Vec::new();
    let mut chars = sequence.char_indices().peekable();
    while let Some((start, character)) = chars.next() {
        if character != '<' {
            output.push(InputKey::Char(character));
            continue;
        }

        let remainder = &sequence[start + 1..];
        let Some(relative_end) = remainder.find('>') else {
            bail!("unterminated key token at byte {start}");
        };
        let end = start + 1 + relative_end;
        while chars.peek().is_some_and(|(index, _)| *index <= end) {
            chars.next();
        }
        match sequence[start + 1..end].to_ascii_lowercase().as_str() {
            "enter" | "return" => output.push(InputKey::Enter),
            "esc" | "escape" => output.push(InputKey::Esc),
            "up" => output.push(InputKey::Up),
            "down" => output.push(InputKey::Down),
            "backspace" | "bs" => output.push(InputKey::Backspace),
            "tab" => output.push(InputKey::Tab),
            "space" => output.push(InputKey::Char(' ')),
            "lt" => output.push(InputKey::Char('<')),
            "stdin" => output.extend(stdin_value.chars().map(InputKey::Char)),
            token => bail!("unknown key token <{token}>"),
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_literal_and_named_keys() {
        assert_eq!(
            parse_keys("nAPI<enter>x<space>y<esc>", "").unwrap(),
            vec![
                InputKey::Char('n'),
                InputKey::Char('A'),
                InputKey::Char('P'),
                InputKey::Char('I'),
                InputKey::Enter,
                InputKey::Char('x'),
                InputKey::Char(' '),
                InputKey::Char('y'),
                InputKey::Esc,
            ]
        );
    }

    #[test]
    fn expands_stdin_without_reinterpreting_it() {
        assert_eq!(
            parse_keys("<stdin>", "a<enter>b").unwrap(),
            "a<enter>b".chars().map(InputKey::Char).collect::<Vec<_>>()
        );
    }
}
