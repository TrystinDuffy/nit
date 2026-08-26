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
