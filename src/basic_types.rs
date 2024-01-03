use std::fmt::{Display, Formatter};

/// A
/// [Pointer](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_pointer)
/// as provided by the WeeChat relay.
///
/// Note that while these pointers are probably parsed into an actual machine pointer type on the
/// relay side, the protocol treats them as strings with particular constraints. This means that
/// there are possible cases where a relay and a client may have a different interpretation of
/// things like whether two pointers are equal (e.g., leading zeros), or a pointer is valid at all
/// (e.g., Pointers longer than the relay machine's pointer width). Because the representation is
/// only specified at the protocol level, we strongly advise to only use pointers as opaque handles
/// provided by the relay.
// pointers are always represented as ASCII hex strings in the protocol
// e.g., command string "0xf00" == 3"f00" binary message
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Pointer(Vec<u8>);

#[derive(Debug)]
pub enum PointerError {
    /// The pointer string contains non-ASCII characters.
    NonAscii,
    /// The pointer string is valid UTF-8, but contains non-hexadecimal characters.
    NonHex,
    /// The pointer string is too long to fit in a pointer (as of version 3.7 of the WeeChat Relay
    /// protocol, 255 bytes).
    TooLong,
}

impl Pointer {
    pub fn new(ascii_bytes: Vec<u8>) -> Result<Pointer, PointerError> {
        let ascii_bytes = if ascii_bytes.starts_with(&[b'0', b'x']) {
            ascii_bytes[2..].to_vec()
        } else {
            ascii_bytes
        };
        if ascii_bytes.len() > 255 {
            return Err(PointerError::TooLong);
        }
        let pointer_str = std::str::from_utf8(&ascii_bytes).or(Err(PointerError::NonAscii))?;
        if pointer_str.chars().all(|c| char::is_ascii_hexdigit(&c)) {
            Ok(Pointer(ascii_bytes))
        } else {
            Err(PointerError::NonHex)
        }
    }

    // NULL is explicitly defined as having "a length of 1 with value 0",
    // with the demonstration showing that 0 to be ASCII 0, i.e. 0x30
    /// Construct a `NULL` pointer.
    ///
    /// The `NULL` pointer is always an invalid identifier, using it in commands will yield empty
    /// responses.
    pub fn null() -> Pointer {
        Pointer(vec![b'0'])
    }

    /// Whether this pointer is a `NULL` pointer.
    ///
    /// The `NULL` pointer is always an invalid identifier, using it in commands will yield empty
    /// responses.
    pub fn is_null(&self) -> bool {
        self.0.len() == 1 && self.0[0] == b'0'
    }
}

impl Display for Pointer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pointer_str = std::str::from_utf8(&self.0).expect("Invalid pointer: non-UTF-8");
        write!(f, "0x{}", pointer_str)
    }
}

/// A compression algorithm, or lack thereof.
#[derive(Debug, PartialEq, Eq)]
pub enum Compression {
    Off,
    Zlib,
    Zstd,
}

impl Compression {
    pub fn to_str(&self) -> &'static str {
        match self {
            Compression::Off => "off",
            Compression::Zlib => "zlib",
            Compression::Zstd => "zstd",
        }
    }
}

/// A password hash algorithm.
pub enum PasswordHashAlgo {
    Plain,
    Sha256,
    Sha512,
    Pbkdf2Sha256,
    Pbkdf2Sha512,
}

impl PasswordHashAlgo {
    pub fn to_str(&self) -> &'static str {
        match self {
            PasswordHashAlgo::Plain => "plain",
            PasswordHashAlgo::Sha256 => "sha256",
            PasswordHashAlgo::Sha512 => "sha512",
            PasswordHashAlgo::Pbkdf2Sha256 => "pbkdf2+sha256",
            PasswordHashAlgo::Pbkdf2Sha512 => "pbkdf2+sha512",
        }
    }
}
