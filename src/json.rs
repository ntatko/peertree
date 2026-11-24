use std::collections::BTreeMap;
use std::fmt::Write;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

impl Value {
    pub fn object(&self) -> Result<&BTreeMap<String, Value>, String> {
        match self {
            Self::Object(values) => Ok(values),
            _ => Err("Expected a JSON object.".into()),
        }
    }

    pub fn string(&self) -> Result<&str, String> {
        match self {
            Self::String(value) => Ok(value),
            _ => Err("Expected a JSON string.".into()),
        }
    }

    pub fn array(&self) -> Result<&[Value], String> {
        match self {
            Self::Array(values) => Ok(values),
            _ => Err("Expected a JSON array.".into()),
        }
    }

    pub fn unsigned(&self) -> Result<usize, String> {
        match self {
            Self::Number(number) => number
                .parse()
                .map_err(|_| "Expected an unsigned integer.".into()),
            _ => Err("Expected an unsigned integer.".into()),
        }
    }

    pub fn encode(&self) -> String {
        match self {
            Self::Null => "null".into(),
            Self::Bool(value) => value.to_string(),
            Self::Number(value) => value.clone(),
            Self::String(value) => quote(value),
            Self::Array(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(Self::encode)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::Object(values) => {
                let members = values
                    .iter()
                    .map(|(key, value)| format!("{}:{}", quote(key), value.encode()));
                format!("{{{}}}", members.collect::<Vec<_>>().join(","))
            }
        }
    }
}

pub fn quote(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            ch if ch.is_control() => write!(out, "\\u{:04x}", ch as u32).unwrap(),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub fn parse(text: &str) -> Result<Value, String> {
    let mut parser = Parser { text, offset: 0 };
    let value = parser.value(0)?;
    parser.spaces();
    if parser.offset != text.len() {
        return Err(parser.error("Unexpected trailing input"));
    }
    Ok(value)
}

struct Parser<'a> {
    text: &'a str,
    offset: usize,
}

impl Parser<'_> {
    fn error(&self, what: &str) -> String {
        format!("{what} at byte {}.", self.offset)
    }

    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.offset).copied()
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn spaces(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.offset += 1;
        }
    }

    fn value(&mut self, depth: u8) -> Result<Value, String> {
        if depth > 32 {
            return Err(self.error("JSON nesting is too deep"));
        }
        self.spaces();
        match self.peek() {
            Some(b'"') => self.string().map(Value::String),
            Some(b'[') => self.list(depth),
            Some(b'{') => self.object(depth),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err(self.error("Expected a JSON value")),
        }
    }

    fn literal(&mut self, literal: &str, value: Value) -> Result<Value, String> {
        if !self.text[self.offset..].starts_with(literal) {
            return Err(self.error("Invalid JSON literal"));
        }
        self.offset += literal.len();
        Ok(value)
    }

    fn list(&mut self, depth: u8) -> Result<Value, String> {
        self.offset += 1;
        self.spaces();
        let mut values = Vec::new();
        if self.consume(b']') {
            return Ok(Value::Array(values));
        }
        loop {
            values.push(self.value(depth + 1)?);
            self.spaces();
            if self.consume(b']') {
                return Ok(Value::Array(values));
            }
            if !self.consume(b',') {
                return Err(self.error("Expected a comma or closing bracket"));
            }
        }
    }

    fn object(&mut self, depth: u8) -> Result<Value, String> {
        self.offset += 1;
        self.spaces();
        let mut fields = BTreeMap::new();
        if self.consume(b'}') {
            return Ok(Value::Object(fields));
        }
        loop {
            self.spaces();
            let key = self.string()?;
            self.spaces();
            if !self.consume(b':') {
                return Err(self.error("Expected a colon"));
            }
            if fields.insert(key, self.value(depth + 1)?).is_some() {
                return Err(self.error("Duplicate JSON property"));
            }
            self.spaces();
            if self.consume(b'}') {
                return Ok(Value::Object(fields));
            }
            if !self.consume(b',') {
                return Err(self.error("Expected a comma or closing brace"));
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if !self.consume(b'"') {
            return Err(self.error("Expected a quoted string"));
        }
        let mut result = String::new();
        while let Some(ch) = self.text[self.offset..].chars().next() {
            self.offset += ch.len_utf8();
            match ch {
                '"' => return Ok(result),
                '\\' => {
                    let escaped = self
                        .peek()
                        .ok_or_else(|| self.error("Unfinished string escape"))?;
                    self.offset += 1;
                    match escaped {
                        b'"' => result.push('"'),
                        b'\\' => result.push('\\'),
                        b'/' => result.push('/'),
                        b'b' => result.push('\u{8}'),
                        b'f' => result.push('\u{c}'),
                        b'n' => result.push('\n'),
                        b'r' => result.push('\r'),
                        b't' => result.push('\t'),
                        b'u' => result.push(self.unicode()?),
                        _ => return Err(self.error("Invalid string escape")),
                    }
                }
                ch if (ch as u32) < 0x20 => return Err(self.error("Unescaped control character")),
                ch => result.push(ch),
            }
        }
        Err(self.error("Unclosed JSON string"))
    }

    fn code_unit(&mut self) -> Result<u16, String> {
        let mut result = 0;
        for _ in 0..4 {
            let digit = self
                .peek()
                .and_then(|value| char::from(value).to_digit(16))
                .ok_or_else(|| self.error("Invalid Unicode escape"))?;
            self.offset += 1;
            result = result * 16 + digit as u16;
        }
        Ok(result)
    }

    fn unicode(&mut self) -> Result<char, String> {
        let first = self.code_unit()?;
        let point = if (0xd800..=0xdbff).contains(&first) {
            if !self.consume(b'\\') || !self.consume(b'u') {
                return Err(self.error("Expected a second Unicode escape"));
            }
            let second = self.code_unit()?;
            if !(0xdc00..=0xdfff).contains(&second) {
                return Err(self.error("Invalid Unicode surrogate pair"));
            }
            0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second) - 0xdc00
        } else {
            u32::from(first)
        };
        char::from_u32(point).ok_or_else(|| self.error("Invalid Unicode code point"))
    }

    fn digits(&mut self) -> bool {
        let start = self.offset;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        self.offset != start
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.offset;
        self.consume(b'-');
        if !self.consume(b'0') && !self.digits() {
            return Err(self.error("Invalid JSON number"));
        }
        if self.consume(b'.') && !self.digits() {
            return Err(self.error("Invalid fractional value"));
        }
        if self.consume(b'e') || self.consume(b'E') {
            if !self.consume(b'+') {
                self.consume(b'-');
            }
            if !self.digits() {
                return Err(self.error("Invalid exponent"));
            }
        }
        Ok(Value::Number(self.text[start..self.offset].into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_unicode_and_escapes() {
        let parsed =
            parse(r#"{"title":"diff \ud83c\udf33\n日本語","codes":[-1,0,1.5e-2,true,null]}"#)
                .unwrap();
        assert_eq!(
            parsed.object().unwrap()["title"],
            Value::String("diff 🌳\n日本語".into())
        );
        assert_eq!(parse(&parsed.encode()).unwrap(), parsed);
    }

    #[test]
    fn rejects_ambiguous_and_invalid_inputs() {
        for invalid in [r#"{"x":1,"x":2}"#, r#""\ud800""#, "[1,]", "01", "1e"] {
            assert!(parse(invalid).is_err(), "{invalid}");
        }
    }
}
