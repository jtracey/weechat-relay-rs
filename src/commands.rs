pub use crate::basic_types::{Compression, PasswordHashAlgo, Pointer};

use std::fmt::Write;

/// A particular command, ready for sending.
pub struct Command<T: CommandType> {
    pub id: Option<String>,
    pub command: T,
}

/// Some abstracted command, ready for sending.
pub struct DynCommand {
    pub id: Option<String>,
    pub command: Box<dyn CommandType>,
}

impl<T: CommandType> Command<T> {
    pub fn new(id: Option<String>, command: T) -> Self {
        Command { id, command }
    }
}

impl<T: CommandType> std::fmt::Display for Command<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = Vec::with_capacity(2 + self.command.arguments().len());
        if let Some(id) = &self.id {
            fields.push(format!("({})", id));
        }
        fields.push(self.command.command().to_string());
        fields.extend(self.command.arguments());
        writeln!(f, "{}", fields.join(" "))
    }
}

impl std::fmt::Display for DynCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref id) = self.id {
            writeln!(f, "({}) {}", id, self.command)
        } else {
            self.command.fmt(f)
        }
    }
}

macro_rules! escaped {
    ($self:ident) => {{
        let mut fields = Vec::with_capacity(2 + $self.command.arguments().len());
        if let Some(id) = &$self.id {
            fields.push(format!("({})", id));
        }
        fields.push($self.command.command().to_string());

        fields.extend(
            $self
                .command
                .arguments()
                .iter()
                .map(|s| s.replace('\\', "\\\\").replace('\n', "\\n")),
        );

        let mut ret = fields.join(" ");
        ret.push('\n');
        ret
    }};
}

impl<T: CommandType> Command<T> {
    pub fn escaped(&self) -> String {
        escaped!(self)
    }
}

impl DynCommand {
    pub fn escaped(&self) -> String {
        escaped!(self)
    }
}

pub trait CommandType {
    fn command(&self) -> &'static str;
    fn arguments(&self) -> Vec<String>;
}

impl std::fmt::Display for dyn CommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = Vec::with_capacity(1 + self.arguments().len());
        fields.push(self.command().to_string());
        fields.extend(self.arguments());
        writeln!(f, "{}", fields.join(" "))
    }
}

/// The [handshake
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_handshake),
/// sent before anything else in a session.
///
/// The handshake should be performed using [`Connection::new`](crate::Connection::new).
///
/// Response: [Hashtable](crate::messages::WHashtable)
#[derive(Debug)]
pub struct HandshakeCommand {
    /// List of password hash algorithms this client is willing to accept.
    pub password_hash_algo: Vec<PasswordHashAlgo>,
    /// List of compresion algorithms this client is willing to accept.
    pub compression: Vec<Compression>,
    /// Whether commands sent should be escaped, allowing them to span multiple lines.
    pub escape_commands: bool,
}

// we don't want to implement CommandType, else a Connection could establish that contradicts its parameters
impl HandshakeCommand {
    fn command(&self) -> &'static str {
        "handshake"
    }

    fn arguments(&self) -> Vec<String> {
        let mut ret = vec![];
        if !self.password_hash_algo.is_empty() {
            ret.push(format!(
                "password_hash_algo={}",
                self.password_hash_algo
                    .iter()
                    .map(PasswordHashAlgo::to_str)
                    .collect::<Vec<&str>>()
                    .join(":")
            ));
        }
        if !self.compression.is_empty() {
            ret.push(format!(
                "compression={}",
                self.compression
                    .iter()
                    .map(Compression::to_str)
                    .collect::<Vec<&str>>()
                    .join(":")
            ));
        }
        if self.escape_commands {
            ret.push("escape_commands=on".to_string());
        }
        if ret.is_empty() {
            vec![]
        } else {
            vec![ret.join(",")]
        }
    }
}

impl std::fmt::Display for HandshakeCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = Vec::with_capacity(1 + self.arguments().len());
        fields.push(self.command().to_string());
        fields.extend(self.arguments());
        writeln!(f, "{}", fields.join(" "))
    }
}

/// The [init
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_init), used
/// to authenticate a session.
///
/// Response: None
pub struct InitCommand {
    /// Plaintext password authenticator. Probably mutually exclusive with `password_hash`.
    pub password: Option<String>,
    /// Hashed password. Probably mutually exclusive with `password`.
    pub password_hash: Option<PasswordHash>,
    /// Time-based One-Time Password. Typically combined with one of `password` or `password_hash`.
    pub totp: Option<String>,
}

impl CommandType for InitCommand {
    fn command(&self) -> &'static str {
        "init"
    }

    fn arguments(&self) -> Vec<String> {
        fn escape(arg: &str) -> String {
            arg.replace(',', "\\,")
        }
        let mut ret = vec![];
        let pw_hash: String;
        if let Some(password) = &self.password {
            ret.push(format!("password={}", escape(password)))
        }
        if let Some(password_hash) = &self.password_hash {
            pw_hash = password_hash.to_string();
            ret.push(format!("password_hash={}", pw_hash));
        }
        if let Some(totp) = &self.totp {
            ret.push(format!("totp={}", escape(totp)));
        }
        vec![ret.join(",")]
    }
}

/// The [hdata
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_hdata), used
/// to request structured data.
///
/// Response: [Hdata](crate::messages::GenericHdata)
pub struct HdataCommand {
    /// The name of the requested hdata.
    pub name: String,
    /// A pointer or list name, forming the root of the path to the requested variable.
    pub pointer: Countable<PointerOrName>,
    /// A list of variable names that, with the pointer root, form the path to the requested
    /// variable (the last in the path).
    pub vars: Vec<Countable<String>>,
    /// A list of keys to return in the hdata. An empty list returns all keys.
    pub keys: Vec<String>,
}

impl HdataCommand {
    fn path(&self) -> String {
        if self.vars.is_empty() {
            format!("{}:{}", self.name, self.pointer)
        } else {
            format!(
                "{}:{}/{}",
                self.name,
                self.pointer,
                self.vars
                    .iter()
                    .map(Countable::to_string)
                    .collect::<Vec<String>>()
                    .join("/")
            )
        }
    }
}

impl CommandType for HdataCommand {
    fn command(&self) -> &'static str {
        "hdata"
    }

    fn arguments(&self) -> Vec<String> {
        let mut args = vec![self.path()];
        if !self.keys.is_empty() {
            args.push(
                self.keys
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<&str>>()
                    .join(","),
            );
        }
        args
    }
}

/// The [info
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_info), used
/// to request a single name/value pair.
///
/// Response: [Info](crate::messages::WInfo)
pub struct InfoCommand {
    /// Name of the info being requested.
    pub name: String,
    /// Arguments to the info request.
    pub arguments: Vec<String>,
}

impl CommandType for InfoCommand {
    fn command(&self) -> &'static str {
        "info"
    }

    fn arguments(&self) -> Vec<String> {
        let mut ret = vec![self.name.clone()];
        ret.extend(self.arguments.iter().cloned());
        ret
    }
}

/// The [infolist
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_infolist),
/// used to request a list of name/value pairs.
///
/// Response: [Infolist](crate::messages::WInfolist)
pub struct InfolistCommand {
    name: String,
    // As of version 3.7 of the WeeChat Relay Protocol, if there are
    // any arguments, the first argument *must* be a Pointer.
    // Arguments to infolists without pointers can be accessed using a
    // NULL pointer.
    arguments: Option<(Pointer, Vec<String>)>,
}

impl InfolistCommand {
    /// InfolistCommand constructor.
    ///
    /// `name`: The name of the infolist being requested.
    ///
    /// `arguments`: Arguments to the infolist request.
    pub fn new(name: String, pointer: Option<Pointer>, arguments: Vec<String>) -> Self {
        let arguments = match (pointer, !arguments.is_empty()) {
            (None, false) => None,
            (Some(p), _) => Some((p, arguments)),
            (None, true) => Some((Pointer::null(), arguments)),
        };
        Self { name, arguments }
    }
}

impl CommandType for InfolistCommand {
    fn command(&self) -> &'static str {
        "infolist"
    }

    fn arguments(&self) -> Vec<String> {
        let mut ret = vec![self.name.clone()];
        if let Some(arguments) = &self.arguments {
            ret.push(arguments.0.to_string());
            ret.extend(arguments.1.iter().cloned());
        }
        ret
    }
}

/// The [nicklist
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_nicklist),
/// used to request a nicklist for one or all buffers.
///
/// Response: [Hdata](crate::messages::GenericHdata)
pub struct NicklistCommand {
    pub buffer: Option<PointerOrName>,
}

impl CommandType for NicklistCommand {
    fn command(&self) -> &'static str {
        "nicklist"
    }

    fn arguments(&self) -> Vec<String> {
        if let Some(buffer) = &self.buffer {
            vec![buffer.to_string()]
        } else {
            vec![]
        }
    }
}

/// The [input
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_input), used
/// to send data to a buffer.
///
/// Response: None
pub struct InputCommand {
    /// Pointer to or full name of the buffer.
    pub buffer: PointerOrName,
    /// String to input to the buffer.
    pub data: String,
}

impl CommandType for InputCommand {
    fn command(&self) -> &'static str {
        "input"
    }

    fn arguments(&self) -> Vec<String> {
        vec![self.buffer.to_string(), self.data.clone()]
    }
}

/// The [completion
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_completion),
/// used to request possible string completions.
///
/// Response: [Hdata](crate::messages::GenericHdata)
pub struct CompletionCommand {
    /// Pointer or name of the buffer to get completion from.
    pub buffer: PointerOrName,
    // if ever extended to negatives aside -1, extend this to i32
    // so behavior of all currently working values is preserved
    // (Idk what you're completing that's over 32,768 chars, but I'm not judging)
    /// Position in the string for completion if `Some`, else complete at the end if `None`.
    pub position: Option<u16>,
    /// String to complete. `None` is the same as the empty string.
    pub data: Option<String>,
}

impl CommandType for CompletionCommand {
    fn command(&self) -> &'static str {
        "completion"
    }

    fn arguments(&self) -> Vec<String> {
        let position = match self.position {
            Some(position) => position.to_string(),
            None => "-1".to_string(),
        };
        let mut ret = vec![self.buffer.to_string(), position];
        if let Some(data) = &self.data {
            ret.push(data.clone());
        }
        ret
    }
}

// At least in the current spec, "sync" and "desync" have identical invocations
// (though different interpretations).
macro_rules! sync_args {
    ( $self:ident ) => {
        match $self {
            Self::AllBuffers(options) => {
                if let Some(options) = options.to_string() {
                    vec![options]
                } else {
                    vec![]
                }
            }
            Self::SomeBuffers(buffers, options) => {
                let mut args = vec![buffers
                    .iter()
                    .map(PointerOrName::to_string)
                    .collect::<Vec<String>>()
                    .join(",")];
                match options {
                    SyncSomeBuffers::Buffer => args.push("buffer".to_string()),
                    SyncSomeBuffers::Nicklist => args.push("nicklist".to_string()),
                    SyncSomeBuffers::All => (),
                }
                args
            }
        }
    };
}

/// The [sync
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_sync), used
/// to pull updates for one or more buffers.
///
/// Response: 0 or more [Hdatas](crate::messages::GenericHdata), received until a [`DesyncCommand`]
/// is sent.
pub enum SyncCommand {
    AllBuffers(SyncAllBuffers),
    SomeBuffers(Vec<PointerOrName>, SyncSomeBuffers),
}

impl CommandType for SyncCommand {
    fn command(&self) -> &'static str {
        "sync"
    }

    fn arguments(&self) -> Vec<String> {
        sync_args!(self)
    }
}

/// The [desync
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_desync),
/// used to stop updates from one or more buffers.
///
/// Response: None
pub enum DesyncCommand {
    AllBuffers(SyncAllBuffers),
    SomeBuffers(Vec<PointerOrName>, SyncSomeBuffers),
}

impl CommandType for DesyncCommand {
    fn command(&self) -> &'static str {
        "desync"
    }

    fn arguments(&self) -> Vec<String> {
        sync_args!(self)
    }
}

/// The [test
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_test), used
/// to request sample objects for testing code.
///
/// Response (see linked docs above for values): [Char](crate::messages::WChar),
/// [Integer](crate::messages::WInteger), [Integer](crate::messages::WInteger),
/// [Long](crate::messages::WLongInteger), [Long](crate::messages::WLongInteger),
/// [String](crate::messages::WString), [String](crate::messages::WString),
/// [String](crate::messages::WString), [Buffer](crate::messages::WBuffer),
/// [Buffer](crate::messages::WBuffer), [Pointer], [Pointer], [Time](crate::messages::WTime),
/// [Array](crate::messages::WArray) ([String](crate::messages::WString)),
/// [Array](crate::messages::WArray) ([Integer](crate::messages::WInteger))
#[derive(Default)]
pub struct TestCommand {}

impl CommandType for TestCommand {
    fn command(&self) -> &'static str {
        "test"
    }
    fn arguments(&self) -> Vec<String> {
        vec![]
    }
}

/// The [ping
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_ping), used
/// to test liveness and response time.
///
/// Response: [String](crate::messages::WString), with [Pong](crate::messages::Event::Pong)
/// identifier.
pub struct PingCommand {
    pub argument: String,
}

impl CommandType for PingCommand {
    fn command(&self) -> &'static str {
        "ping"
    }
    fn arguments(&self) -> Vec<String> {
        vec![self.argument.clone()]
    }
}

/// The [quit
/// command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_quit), used
/// to disconnect from the relay.
///
/// Response: None
#[derive(Default)]
pub struct QuitCommand {}

impl CommandType for QuitCommand {
    fn command(&self) -> &'static str {
        "quit"
    }
    fn arguments(&self) -> Vec<String> {
        vec![]
    }
}

/// Options for syncing/desyncing all buffers.
pub struct SyncAllBuffers {
    /// Whether to receive signals about buffers: open/closed, moved, renamed, merged/unmerged,
    /// hidden/unhidden
    pub buffers: bool,
    /// Whether to receive signals about WeeChat upgrades (upgrade, upgrade ended)
    pub upgrade: bool,
    /// Whether to receive signals about each buffer (new lines, type changed, title changed, local
    /// variable added/removed, plus everything in [`Self::buffers`].
    pub buffer: bool,
    /// Whether to receive updated nicklists when changed.
    pub nicklist: bool,
}

impl SyncAllBuffers {
    fn to_string(&self) -> Option<String> {
        // spec specifically recommends (though doesn't require) handling the all case as the
        // default case
        if (self.buffers && self.upgrade && self.buffer && self.nicklist)
            || (!self.buffers && !self.upgrade && !self.buffer && !self.nicklist)
        {
            return None;
        }
        let mut ret = vec![];
        if self.buffers {
            ret.push("buffers");
        }
        if self.upgrade {
            ret.push("upgrade");
        }
        if self.buffer {
            ret.push("buffer");
        }
        if self.nicklist {
            ret.push("nicklist");
        }
        Some(format!("* {}", ret.join(",")))
    }
}

/// Options for syncing/desyncing some buffers.
pub enum SyncSomeBuffers {
    /// Only receive signals about the buffer: new lines, type changed, title changed, local
    /// variable added/removed, opened/closed, moved, renamed, merged/unmerged, hidden/unhidden.
    Buffer,
    /// Only receive updated nicklist when changed.
    Nicklist,
    /// Receive all of the above.
    All,
}

/// A hashed password, with parameters.
pub enum PasswordHash {
    Sha256 {
        salt: Vec<u8>,
        hash: [u8; 32],
    },
    Sha512 {
        salt: Vec<u8>,
        hash: [u8; 64],
    },
    Pbkdf2Sha256 {
        salt: Vec<u8>,
        iterations: u32,
        hash: [u8; 32],
    },
    Pbkdf2Sha512 {
        salt: Vec<u8>,
        iterations: u32,
        hash: [u8; 64],
    },
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}

impl std::fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordHash::Sha256 { salt, hash } => {
                write!(f, "sha256:{}:{}", hex_encode(salt), hex_encode(hash))
            }
            PasswordHash::Sha512 { salt, hash } => {
                write!(f, "sha512:{}:{}", hex_encode(salt), hex_encode(hash))
            }
            PasswordHash::Pbkdf2Sha256 {
                salt,
                iterations,
                hash,
            } => write!(
                f,
                "pbkdf2+sha256:{}:{}:{}",
                hex_encode(salt),
                iterations,
                hex_encode(hash)
            ),
            PasswordHash::Pbkdf2Sha512 {
                salt,
                iterations,
                hash,
            } => write!(
                f,
                "pbkdf2+sha512:{}:{}:{}",
                hex_encode(salt),
                iterations,
                hex_encode(hash)
            ),
        }
    }
}

/// The count of elements in an [`HdataCommand`].
///
/// Positive counts mean the next elements, negative counts mean the previous elements, a glob means
/// the next elements to the end of the list.
pub enum Count {
    Count(i32),
    Glob,
}

impl std::fmt::Display for Count {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Count::Count(c) => c.fmt(f),
            Count::Glob => "*".fmt(f),
        }
    }
}

/// A countable element in an [`HdataCommand`], with its count.
pub struct Countable<T: std::fmt::Display> {
    pub count: Option<Count>,
    pub object: T,
}

impl<T: std::fmt::Display> Countable<T> {
    pub fn new(count: Option<Count>, object: T) -> Self {
        Self { count, object }
    }
}

impl<T: std::fmt::Display> std::fmt::Display for Countable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.count {
            Some(count) => write!(f, "{}({})", self.object, count),
            None => self.object.fmt(f),
        }
    }
}

/// A [`Pointer`] or name in root of the path of an [`HdataCommand`].
pub enum PointerOrName {
    Pointer(Pointer),
    Name(String),
}

impl std::fmt::Display for PointerOrName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PointerOrName::Pointer(pointer) => pointer.fmt(f),
            PointerOrName::Name(string) => string.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // n.b. these tests only test the string commands they create,
    // not any kind of interaction with a server
    #[test]
    fn test_handshake() {
        use crate::basic_types::Compression;

        let default_handshake = HandshakeCommand {
            password_hash_algo: vec![],
            compression: vec![],
            escape_commands: false,
        };
        let compression_handshake = HandshakeCommand {
            password_hash_algo: vec![],
            compression: vec![Compression::Zstd],
            escape_commands: false,
        };
        let all_hash_algos = vec![
            PasswordHashAlgo::Plain,
            PasswordHashAlgo::Sha256,
            PasswordHashAlgo::Sha512,
            PasswordHashAlgo::Pbkdf2Sha256,
            PasswordHashAlgo::Pbkdf2Sha512,
        ];
        let full_handshake = HandshakeCommand {
            password_hash_algo: all_hash_algos,
            compression: vec![Compression::Zstd, Compression::Zlib, Compression::Off],
            escape_commands: false,
        };

        assert_eq!(default_handshake.to_string(), "handshake\n");
        assert_eq!(
            compression_handshake.to_string(),
            "handshake compression=zstd\n"
        );
        // FIXME: we shouldn't be testing the order of the options here,
        // but should make sure however we end up testing checks for proper formatting
        assert_eq!(
            full_handshake.to_string(),
            "handshake password_hash_algo=plain:sha256:sha512:pbkdf2+sha256:pbkdf2+sha512,compression=zstd:zlib:off\n"
        );
    }

    #[test]
    fn test_init() {
        let normal_password = InitCommand {
            password: Some("mypass".to_string()),
            password_hash: None,
            totp: None,
        };
        let password_with_commas = InitCommand {
            password: Some("mypass,with,commas".to_string()),
            password_hash: None,
            totp: None,
        };
        let password_with_totp = InitCommand {
            password: Some("mypass".to_string()),
            password_hash: None,
            totp: Some("123456".to_string()),
        };

        let salt = vec![
            0x85, 0xb1, 0xee, 0x00, 0x69, 0x5a, 0x5b, 0x25, 0x4e, 0x14, 0xf4, 0x88, 0x55, 0x38,
            0xdf, 0x0d, 0xa4, 0xb7, 0x32, 0x07, 0xf5, 0xaa, 0xe4,
        ];
        let salt_string = hex_encode(&salt);

        let sha256_password = InitCommand {
            password: None,
            password_hash: Some(PasswordHash::Sha256 {
                salt: salt.clone(),
                hash: [
                    0x2c, 0x6e, 0xd1, 0x2e, 0xb0, 0x10, 0x9f, 0xca, 0x3a, 0xed, 0xc0, 0x3b, 0xf0,
                    0x3d, 0x9b, 0x6e, 0x80, 0x4c, 0xd6, 0x0a, 0x23, 0xe1, 0x73, 0x1f, 0xd1, 0x77,
                    0x94, 0xda, 0x42, 0x3e, 0x21, 0xdb,
                ],
            }),
            totp: None,
        };

        let sha512_password = InitCommand {
            password: None,
            password_hash: Some(PasswordHash::Sha512 {
                salt: salt.clone(),
                hash: [
                    0x0a, 0x1f, 0x01, 0x72, 0xa5, 0x42, 0x91, 0x6b, 0xd8, 0x6e, 0x0c, 0xbc, 0xee,
                    0xbc, 0x1c, 0x38, 0xed, 0x79, 0x1f, 0x6b, 0xe2, 0x46, 0x12, 0x04, 0x52, 0x82,
                    0x5f, 0x0d, 0x74, 0xef, 0x10, 0x78, 0xc7, 0x9e, 0x98, 0x12, 0xde, 0x8b, 0x0a,
                    0xb3, 0xdf, 0xaf, 0x59, 0x8b, 0x6c, 0xa1, 0x45, 0x22, 0x37, 0x4e, 0xc6, 0xa8,
                    0x65, 0x3a, 0x46, 0xdf, 0x3f, 0x96, 0xa6, 0xb5, 0x4a, 0xc1, 0xf0, 0xf8,
                ],
            }),
            totp: None,
        };

        let pbkdf2_password = InitCommand {
            password: None,
            password_hash: Some(PasswordHash::Pbkdf2Sha256 {
                salt,
                iterations: 100000,
                hash: [
                    0xba, 0x7f, 0xac, 0xc3, 0xed, 0xb8, 0x9c, 0xd0, 0x6a, 0xe8, 0x10, 0xe2, 0x9c,
                    0xed, 0x85, 0x98, 0x0f, 0xf3, 0x6d, 0xe2, 0xbb, 0x59, 0x6f, 0xcf, 0x51, 0x3a,
                    0xaa, 0xb6, 0x26, 0x87, 0x64, 0x40,
                ],
            }),
            totp: None,
        };

        let command = Command::new(None, normal_password);
        assert_eq!(command.to_string(), "init password=mypass\n");

        let command = Command::new(None, password_with_commas);
        assert_eq!(
            command.to_string(),
            "init password=mypass\\,with\\,commas\n"
        );

        let command = Command::new(None, password_with_totp);
        assert_eq!(command.to_string(), "init password=mypass,totp=123456\n");

        let command = Command::new(None, sha256_password);
        let hash = "2c6ed12eb0109fca3aedc03bf03d9b6e804cd60a23e1731fd17794da423e21db";
        assert_eq!(
            command.to_string(),
            format!("init password_hash=sha256:{salt_string}:{hash}\n")
        );

        let command = Command::new(None, sha512_password);
        let hash = "0a1f0172a542916bd86e0cbceebc1c38ed791f6be246120452825f0d74ef1078c79e9812de8b0ab3dfaf598b6ca14522374ec6a8653a46df3f96a6b54ac1f0f8";
        assert_eq!(
            command.to_string(),
            format!("init password_hash=sha512:{salt_string}:{hash}\n")
        );

        let command = Command::new(None, pbkdf2_password);
        let hash = "ba7facc3edb89cd06ae810e29ced85980ff36de2bb596fcf513aaab626876440";
        assert_eq!(
            command.to_string(),
            format!("init password_hash=pbkdf2+sha256:{salt_string}:100000:{hash}\n")
        );
    }

    #[test]
    fn test_hdata() {
        let hdata_buffers = HdataCommand {
            name: "buffer".to_string(),
            pointer: Countable::new(
                Some(Count::Glob),
                PointerOrName::Name("gui_buffers".to_string()),
            ),
            vars: vec![],
            keys: vec!["number".to_string(), "full_name".to_string()],
        };

        let hdata_lines = HdataCommand {
            name: "buffer".to_string(),
            pointer: Countable::new(None, PointerOrName::Name("gui_buffers".to_string())),
            vars: vec![
                Countable::new(None, "own_lines".to_string()),
                Countable::new(Some(Count::Glob), "first_line".to_string()),
                Countable::new(None, "data".to_string()),
            ],
            keys: vec![],
        };

        let hdata_hotlist = HdataCommand {
            name: "hotlist".to_string(),
            pointer: Countable::new(
                Some(Count::Glob),
                PointerOrName::Name("gui_hotlist".to_string()),
            ),
            vars: vec![],
            keys: vec![],
        };

        let command = Command::new(Some("hdata_buffers".to_string()), hdata_buffers);
        assert_eq!(
            command.to_string(),
            "(hdata_buffers) hdata buffer:gui_buffers(*) number,full_name\n"
        );

        let command = Command::new(Some("hdata_lines".to_string()), hdata_lines);
        assert_eq!(
            command.to_string(),
            "(hdata_lines) hdata buffer:gui_buffers/own_lines/first_line(*)/data\n"
        );

        let command = Command::new(Some("hdata_hotlist".to_string()), hdata_hotlist);
        assert_eq!(
            command.to_string(),
            "(hdata_hotlist) hdata hotlist:gui_hotlist(*)\n"
        );
    }

    #[test]
    fn test_info() {
        let info = InfoCommand {
            name: "version".to_string(),
            arguments: vec![],
        };
        let command = Command::new(Some("info_version".to_string()), info);
        assert_eq!(command.to_string(), "(info_version) info version\n");

        let info = InfoCommand {
            name: "nick_color".to_string(),
            arguments: vec!["foo".to_string()],
        };
        let command = Command::new(Some("foo_color".to_string()), info);
        assert_eq!(command.to_string(), "(foo_color) info nick_color foo\n");
    }

    #[test]
    fn test_infolist() {
        let id = "infolist_buffer".to_string();
        let name = "buffer".to_string();
        let pointer = Pointer::new("1234abcd".as_bytes().to_vec()).expect("invalid pointer");
        let arguments = vec!["core.weechat".to_string()];

        let infolist_buffer = InfolistCommand::new(name.clone(), None, vec![]);
        let command = Command::new(Some(id.clone()), infolist_buffer);
        assert_eq!(command.to_string(), "(infolist_buffer) infolist buffer\n");

        let infolist_buffer = InfolistCommand::new(name.clone(), Some(pointer.clone()), vec![]);
        let command = Command::new(Some(id.clone()), infolist_buffer);
        assert_eq!(
            command.to_string(),
            "(infolist_buffer) infolist buffer 0x1234abcd\n"
        );

        let infolist_buffer = InfolistCommand::new(name.clone(), None, arguments.clone());
        let command = Command::new(Some(id.clone()), infolist_buffer);
        assert_eq!(
            command.to_string(),
            "(infolist_buffer) infolist buffer 0x0 core.weechat\n"
        );

        let infolist_buffer = InfolistCommand::new(name, Some(pointer), arguments);
        let command = Command::new(Some(id), infolist_buffer);
        assert_eq!(
            command.to_string(),
            "(infolist_buffer) infolist buffer 0x1234abcd core.weechat\n"
        );
    }

    #[test]
    fn test_nicklist() {
        let all_buffers = NicklistCommand { buffer: None };
        let one_buffer = NicklistCommand {
            buffer: Some(PointerOrName::Name("irc.libera.#weechat".to_string())),
        };

        let command = Command::new(Some("nicklist_all".to_string()), all_buffers);
        assert_eq!(command.to_string(), "(nicklist_all) nicklist\n");

        let command = Command::new(Some("nicklist_weechat".to_string()), one_buffer);
        assert_eq!(
            command.to_string(),
            "(nicklist_weechat) nicklist irc.libera.#weechat\n"
        );
    }

    #[test]
    fn test_input() {
        let help = InputCommand {
            buffer: PointerOrName::Name("core.weechat".to_string()),
            data: "/help filter".to_string(),
        };

        let hello = InputCommand {
            buffer: PointerOrName::Name("irc.libera.#weechat".to_string()),
            data: "hello!".to_string(),
        };

        let command = Command::new(None, help);
        assert_eq!(command.to_string(), "input core.weechat /help filter\n");

        let command = Command::new(None, hello);
        assert_eq!(command.to_string(), "input irc.libera.#weechat hello!\n");
    }

    #[test]
    fn test_completion() {
        let completion_help = CompletionCommand {
            buffer: PointerOrName::Name("core.weechat".to_string()),
            position: None,
            data: Some("/help fi".to_string()),
        };

        let completion_query = CompletionCommand {
            buffer: PointerOrName::Name("core.weechat".to_string()),
            position: Some(5),
            data: Some("/quernick".to_string()),
        };

        let command = Command::new(Some("completion_help".to_string()), completion_help);
        assert_eq!(
            command.to_string(),
            "(completion_help) completion core.weechat -1 /help fi\n"
        );

        let command = Command::new(Some("completion_query".to_string()), completion_query);
        assert_eq!(
            command.to_string(),
            "(completion_query) completion core.weechat 5 /quernick\n"
        );
    }

    #[test]
    fn test_sync() {
        let all_buffers = SyncCommand::AllBuffers(SyncAllBuffers {
            buffers: true,
            upgrade: true,
            buffer: true,
            nicklist: true,
        });

        let core_buffer = SyncCommand::SomeBuffers(
            vec![PointerOrName::Name("core.buffer".to_string())],
            SyncSomeBuffers::All,
        );

        let without_nicklist = SyncCommand::SomeBuffers(
            vec![PointerOrName::Name("irc.libera.#weechat".to_string())],
            SyncSomeBuffers::Buffer,
        );

        let general_signals = SyncCommand::AllBuffers(SyncAllBuffers {
            buffers: true,
            upgrade: true,
            buffer: false,
            nicklist: false,
        });

        let command = Command {
            id: None,
            command: all_buffers,
        };
        assert_eq!(command.to_string(), "sync\n");

        let command = Command::new(None, core_buffer);
        assert_eq!(command.to_string(), "sync core.buffer\n");

        let command = Command::new(None, without_nicklist);
        assert_eq!(command.to_string(), "sync irc.libera.#weechat buffer\n");

        let command = Command::new(None, general_signals);
        assert_eq!(command.to_string(), "sync * buffers,upgrade\n");
    }

    #[test]
    fn test_desync() {
        let all_buffers = DesyncCommand::AllBuffers(SyncAllBuffers {
            buffers: true,
            upgrade: true,
            buffer: true,
            nicklist: true,
        });

        let nicklist = DesyncCommand::SomeBuffers(
            vec![PointerOrName::Name("irc.libera.#weechat".to_string())],
            SyncSomeBuffers::Nicklist,
        );

        let all_signals = DesyncCommand::SomeBuffers(
            vec![PointerOrName::Name("irc.libera.#weechat".to_string())],
            SyncSomeBuffers::All,
        );

        let command = Command::new(None, all_buffers);
        assert_eq!(command.to_string(), "desync\n");

        let command = Command::new(None, nicklist);
        assert_eq!(command.to_string(), "desync irc.libera.#weechat nicklist\n");

        let command = Command::new(None, all_signals);
        assert_eq!(command.to_string(), "desync irc.libera.#weechat\n");
    }

    #[test]
    fn test_test() {
        let test = TestCommand {};
        let command = Command::new(None, test);
        assert_eq!(command.to_string(), "test\n");
    }

    #[test]
    fn test_ping() {
        let ping = PingCommand {
            argument: "foo".to_string(),
        };
        let command = Command::new(None, ping);
        assert_eq!(command.to_string(), "ping foo\n");
    }

    #[test]
    fn test_quit() {
        let quit = QuitCommand {};
        let command = Command::new(None, quit);
        assert_eq!(command.to_string(), "quit\n");
    }
}
