//! Reads `settings_ssaid.xml`, where Android keeps each user's SSAID key (`userkey`)
//! and the SSAID it gave every app (keyed by the app's uid). Android 12+ writes it as
//! binary XML (ABX); older releases as text XML.

use std::fmt;

use base64::Engine as _;

/// One `<setting>` of the file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SettingEntry {
    pub name: String,
    pub value: Option<String>,
    pub package: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsaidError {
    /// Neither ABX nor text XML.
    UnknownFormat,
    /// The ABX stream ends inside a token.
    Truncated,
    /// An interned-string reference past the table.
    BadInternIndex(u16),
    /// A token this reader does not know.
    BadToken(u8),
}

impl fmt::Display for SsaidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFormat => write!(f, "not an ABX or XML settings file"),
            Self::Truncated => write!(f, "truncated ABX document"),
            Self::BadInternIndex(i) => write!(f, "ABX interned string {i} is undefined"),
            Self::BadToken(t) => write!(f, "unknown ABX token {t:#04x}"),
        }
    }
}

impl std::error::Error for SsaidError {}

/// The settings file of Android `user`.
pub fn path(user: u32) -> String {
    format!("/data/system/users/{user}/settings_ssaid.xml")
}

/// Every `<setting>` in the file at [`path`], or `None` when it can't be read.
pub async fn read(user: u32) -> Option<Vec<SettingEntry>> {
    let bytes = tokio::fs::read(path(user)).await.ok()?;
    parse_settings(&bytes)
        .inspect_err(|e| log::warn!("{}: {e}", path(user)))
        .ok()
}

/// Parse `settings_ssaid.xml` in either form.
pub fn parse_settings(bytes: &[u8]) -> Result<Vec<SettingEntry>, SsaidError> {
    if let Some(body) = bytes.strip_prefix(ABX_MAGIC) {
        return parse_abx(body);
    }
    let text = String::from_utf8_lossy(bytes);
    if text.trim_start().starts_with('<') {
        return Ok(parse_text(&text));
    }
    Err(SsaidError::UnknownFormat)
}

const ABX_MAGIC: &[u8] = b"ABX\0";

// AOSP `BinaryXmlSerializer`: a token byte is `type << 4 | command`.
const START_TAG: u8 = 2;
const ATTRIBUTE: u8 = 15;
const TYPE_NULL: u8 = 1;
const TYPE_STRING: u8 = 2;
const TYPE_STRING_INTERNED: u8 = 3;
const TYPE_BYTES_HEX: u8 = 4;
const TYPE_BYTES_BASE64: u8 = 5;
const TYPE_INT: u8 = 6;
const TYPE_INT_HEX: u8 = 7;
const TYPE_LONG: u8 = 8;
const TYPE_LONG_HEX: u8 = 9;
const TYPE_FLOAT: u8 = 10;
const TYPE_DOUBLE: u8 = 11;
const TYPE_BOOLEAN_TRUE: u8 = 12;
const TYPE_BOOLEAN_FALSE: u8 = 13;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    interned: Vec<String>,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], SsaidError> {
        let end = self.pos.checked_add(n).ok_or(SsaidError::Truncated)?;
        let out = self.buf.get(self.pos..end).ok_or(SsaidError::Truncated)?;
        self.pos = end;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, SsaidError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn utf(&mut self) -> Result<String, SsaidError> {
        let len = self.u16()? as usize;
        // Java's modified UTF-8; the names and values read here are plain ASCII.
        Ok(String::from_utf8_lossy(self.take(len)?).into_owned())
    }

    fn interned(&mut self) -> Result<String, SsaidError> {
        match self.u16()? {
            0xFFFF => {
                let s = self.utf()?;
                self.interned.push(s.clone());
                Ok(s)
            }
            i => self
                .interned
                .get(i as usize)
                .cloned()
                .ok_or(SsaidError::BadInternIndex(i)),
        }
    }

    /// A typed value; only string forms are kept.
    fn value(&mut self, ty: u8) -> Result<Option<String>, SsaidError> {
        Ok(match ty {
            TYPE_NULL | TYPE_BOOLEAN_TRUE | TYPE_BOOLEAN_FALSE => None,
            TYPE_STRING => Some(self.utf()?),
            TYPE_STRING_INTERNED => Some(self.interned()?),
            TYPE_BYTES_HEX | TYPE_BYTES_BASE64 => {
                let len = self.u16()? as usize;
                self.take(len)?;
                None
            }
            TYPE_INT | TYPE_INT_HEX | TYPE_FLOAT => {
                self.take(4)?;
                None
            }
            TYPE_LONG | TYPE_LONG_HEX | TYPE_DOUBLE => {
                self.take(8)?;
                None
            }
            _ => return Err(SsaidError::BadToken(ty << 4)),
        })
    }
}

fn parse_abx(body: &[u8]) -> Result<Vec<SettingEntry>, SsaidError> {
    let mut r = Reader {
        buf: body,
        pos: 0,
        interned: Vec::new(),
    };
    let mut out = Vec::new();
    let mut current: Option<SettingEntry> = None;
    while r.pos < r.buf.len() {
        let token = r.take(1)?[0];
        let (command, ty) = (token & 0x0f, token >> 4);
        if command == ATTRIBUTE {
            let name = r.interned()?;
            let value = r.value(ty)?;
            if let Some(entry) = current.as_mut() {
                set_attribute(entry, &name, value);
            }
            continue;
        }
        out.extend(current.take().filter(|e| !e.name.is_empty()));
        match command {
            START_TAG => {
                if r.value(ty)?.as_deref() == Some("setting") {
                    current = Some(SettingEntry::default());
                }
            }
            // END_DOCUMENT .. DOCDECL carry at most one value of their type.
            0..=10 => {
                r.value(ty)?;
            }
            _ => return Err(SsaidError::BadToken(token)),
        }
    }
    out.extend(current.filter(|e| !e.name.is_empty()));
    Ok(out)
}

fn set_attribute(entry: &mut SettingEntry, name: &str, value: Option<String>) {
    match name {
        "name" => entry.name = value.unwrap_or_default(),
        "value" => entry.value = value,
        // Android base64-encodes values that are not valid XML text.
        "valueBase64" => {
            entry.value = value
                .and_then(|v| base64::engine::general_purpose::STANDARD.decode(v).ok())
                .map(|b| String::from_utf8_lossy(&b).into_owned());
        }
        "package" => entry.package = value,
        _ => {}
    }
}

fn parse_text(text: &str) -> Vec<SettingEntry> {
    let mut out = Vec::new();
    for chunk in text.split("<setting").skip(1) {
        // `<settings` is the root element, not an entry.
        if !chunk.starts_with(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>') {
            continue;
        }
        let tag = chunk.split('>').next().unwrap_or("");
        let mut entry = SettingEntry::default();
        for (name, value) in text_attributes(tag) {
            set_attribute(&mut entry, name, Some(unescape(value)));
        }
        if !entry.name.is_empty() {
            out.push(entry);
        }
    }
    out
}

/// `name="value"` pairs of one start tag.
fn text_attributes(tag: &str) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let mut rest = tag;
    while let Some(eq) = rest.find('=') {
        let name = rest[..eq].trim().trim_start_matches('/').trim();
        let after = rest[eq + 1..].trim_start();
        let Some(quote) = after.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            break;
        };
        let Some(end) = after[1..].find(quote) else {
            break;
        };
        out.push((
            name.rsplit(char::is_whitespace).next().unwrap_or(name),
            &after[1..=end],
        ));
        rest = &after[end + 2..];
    }
    out
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let tail = &rest[amp..];
        let Some(semi) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let entity = &tail[1..semi];
        let ch = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .map(|h| u32::from_str_radix(h, 16))
                .or_else(|| entity.strip_prefix('#').map(str::parse))
                .and_then(Result::ok)
                .and_then(char::from_u32),
        };
        match ch {
            Some(c) => out.push(c),
            None => out.push_str(&tail[..=semi]),
        }
        rest = &tail[semi + 1..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic values; no real device key or SSAID.
    const KEY: &str = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";
    const HAPP: &str = "su.happ.proxyutility";

    /// The subset of AOSP's `BinaryXmlSerializer` the tests need.
    #[derive(Default)]
    struct Abx {
        out: Vec<u8>,
        interned: Vec<String>,
    }

    impl Abx {
        fn new() -> Self {
            let mut a = Self::default();
            a.out.extend_from_slice(ABX_MAGIC);
            a.out.push(TYPE_NULL << 4); // START_DOCUMENT
            a
        }
        fn utf(&mut self, s: &str) {
            self.out.extend_from_slice(&(s.len() as u16).to_be_bytes());
            self.out.extend_from_slice(s.as_bytes());
        }
        fn interned(&mut self, s: &str) {
            match self.interned.iter().position(|x| x == s) {
                Some(i) => self.out.extend_from_slice(&(i as u16).to_be_bytes()),
                None => {
                    self.out.extend_from_slice(&0xFFFFu16.to_be_bytes());
                    self.utf(s);
                    self.interned.push(s.to_owned());
                }
            }
        }
        fn start(&mut self, tag: &str) -> &mut Self {
            self.out.push(TYPE_STRING_INTERNED << 4 | START_TAG);
            self.interned(tag);
            self
        }
        fn end(&mut self, tag: &str) -> &mut Self {
            self.out.push(TYPE_STRING_INTERNED << 4 | 3);
            self.interned(tag);
            self
        }
        fn attr(&mut self, name: &str, value: &str) -> &mut Self {
            self.out.push(TYPE_STRING << 4 | ATTRIBUTE);
            self.interned(name);
            self.utf(value);
            self
        }
        fn attr_interned(&mut self, name: &str, value: &str) -> &mut Self {
            self.out.push(TYPE_STRING_INTERNED << 4 | ATTRIBUTE);
            self.interned(name);
            self.interned(value);
            self
        }
        fn attr_int(&mut self, name: &str, v: i32) -> &mut Self {
            self.out.push(TYPE_INT << 4 | ATTRIBUTE);
            self.interned(name);
            self.out.extend_from_slice(&v.to_be_bytes());
            self
        }
        fn attr_bool(&mut self, name: &str) -> &mut Self {
            self.out.push(TYPE_BOOLEAN_FALSE << 4 | ATTRIBUTE);
            self.interned(name);
            self
        }
        fn finish(&mut self) -> Vec<u8> {
            self.out.push(TYPE_NULL << 4 | 1); // END_DOCUMENT
            std::mem::take(&mut self.out)
        }
    }

    fn setting(a: &mut Abx, id: &str, name: &str, value: &str, package: &str) {
        a.start("setting")
            .attr("id", id)
            .attr_interned("name", name)
            .attr("value", value)
            .attr_interned("package", package)
            .attr("defaultValue", value)
            .attr_bool("defaultSysSet")
            .attr("tag", "null")
            .end("setting");
    }

    fn document() -> Vec<u8> {
        let mut a = Abx::new();
        a.start("settings").attr_int("version", -1);
        setting(&mut a, "0", "userkey", KEY, "android");
        setting(&mut a, "1", "10123", "00112233aabbccdd", HAPP);
        setting(
            &mut a,
            "2",
            "10200",
            "ffeeddccbbaa9988",
            "org.example.other",
        );
        a.end("settings").finish()
    }

    fn find<'e>(entries: &'e [SettingEntry], name: &str) -> &'e SettingEntry {
        entries.iter().find(|e| e.name == name).unwrap()
    }

    #[test]
    fn abx_reader_parses_synthetic_document() {
        let entries = parse_settings(&document()).unwrap();
        assert_eq!(entries.len(), 3);
        let key = find(&entries, "userkey");
        assert_eq!(key.value.as_deref(), Some(KEY));
        assert_eq!(key.package.as_deref(), Some("android"));
        let happ = entries
            .iter()
            .find(|e| e.package.as_deref() == Some(HAPP))
            .unwrap();
        assert_eq!(happ.name, "10123");
        assert_eq!(happ.value.as_deref(), Some("00112233aabbccdd"));
    }

    #[test]
    fn interned_strings_resolve() {
        // `package` and `setting` are interned once and referenced by index after.
        let entries = parse_settings(&document()).unwrap();
        let packages: Vec<_> = entries.iter().map(|e| e.package.as_deref()).collect();
        assert_eq!(
            packages,
            [Some("android"), Some(HAPP), Some("org.example.other")]
        );
        let mut bad = Abx::new();
        bad.out.push(TYPE_STRING_INTERNED << 4 | START_TAG);
        bad.out.extend_from_slice(&7u16.to_be_bytes());
        assert_eq!(
            parse_settings(&bad.finish()),
            Err(SsaidError::BadInternIndex(7))
        );
    }

    #[test]
    fn truncated_input_errors() {
        let doc = document();
        for cut in [doc.len() - 3, 40, 9, 6] {
            assert_eq!(
                parse_settings(&doc[..cut]),
                Err(SsaidError::Truncated),
                "cut at {cut}"
            );
        }
        assert_eq!(parse_settings(b"\x00\x01"), Err(SsaidError::UnknownFormat));
    }

    #[test]
    fn text_xml_parses() {
        let xml = format!(
            "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n\
             <settings version=\"-1\">\n\
             <setting id=\"0\" name=\"userkey\" value=\"{KEY}\" package=\"android\" defaultValue=\"{KEY}\" defaultSysSet=\"false\" tag=\"null\" />\n\
             <setting id=\"1\" name=\"10123\" value=\"00112233aabbccdd\" package=\"{HAPP}\" />\n\
             <setting id=\"2\" name=\"10124\" valueBase64=\"YSZi\" package='x&amp;y' />\n\
             </settings>\n"
        );
        let entries = parse_settings(xml.as_bytes()).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(find(&entries, "userkey").value.as_deref(), Some(KEY));
        assert_eq!(find(&entries, "10123").package.as_deref(), Some(HAPP));
        let third = find(&entries, "10124");
        assert_eq!(third.value.as_deref(), Some("a&b"));
        assert_eq!(third.package.as_deref(), Some("x&y"));
    }
}
