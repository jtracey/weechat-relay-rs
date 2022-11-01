pub use crate::basic_types::{Compression, PasswordHashAlgo, Pointer};

#[derive(Debug, PartialEq, Eq)]
pub enum WeechatError {
    NewlineInArgument,
}

/// A [String] that has been checked for invalid argument representations.
///
/// The checks are for basic validity, in the sense that using this as an argument will not cause malformed commands at the protocol level (improper or incorrect arguments are still possible, but they won't break the protocol itself). Currently, this only implies that the argument is a valid string, and that it contains no newlines.
#[derive(Debug, Clone)]
pub struct StringArgument(String);

/// A [&str] that has been checked for invalid argument representations. See [StringArgument].
#[derive(Debug)]
pub struct StrArgument<'a>(&'a str);

impl StringArgument {
    /// Create a new [StringArgument], returning an error if it fails any checks.
    pub fn new(string: String) -> Result<Self, WeechatError> {
        if string.contains('\n') {
            return Err(WeechatError::NewlineInArgument);
        }
        Ok(Self(string))
    }

    /// Create a new [Option<StringArgument>] from an [Option<String>], returning an error it if fails any checks.
    pub fn option_new(string: Option<String>) -> Result<Option<Self>, WeechatError> {
        string.map(Self::new).map_or(Ok(None), |s| s.map(Some))
    }
}

/// Create a [StringArgument] from a string literal (i.e., a [`&'static str`](str)).
///
/// The underlying [String] is allocated at runtime, but the correctness checks are performed at compile time.
#[macro_export]
macro_rules! literal_stringarg {
    ($string:expr) => {{
        const STR_ARG: StrArgument = StrArgument::const_new($string);
        STR_ARG.to_stringargument()
    }};
}

impl std::fmt::Display for StringArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<'a> StrArgument<'a> {
    /// Create a new [StrArgument], returning an error if it fails any checks.
    pub fn new(string: &'a str) -> Result<Self, WeechatError> {
        if string.contains('\n') {
            return Err(WeechatError::NewlineInArgument);
        }
        Ok(Self(string))
    }

    /// Create a new [Option<StrArgument>] from an [Option<&str>], returning an error it if fails any checks.
    pub fn option_new(string: Option<&'a str>) -> Result<Option<Self>, WeechatError> {
        string.map(Self::new).map_or(Ok(None), |s| s.map(Some))
    }

    /// The same as [new](StrArgument::new), but const (i.e., validity checks can be performed at compile-time).
    /// This could be called at runtime too, but because bad arguments would cause assertion failures rather than returning an error, it is strongly advised to not be.
    pub const fn const_new(string: &'static str) -> Self {
        let bytes = string.as_bytes();
        let mut i = 0;
        while i < string.len() {
            let c = bytes[i];
            assert!(c != b'\n', "{}", string);
            i += 1;
        }
        Self(string)
    }

    /// Converts to a [StringArgument].
    pub fn to_stringargument(self) -> StringArgument {
        StringArgument(self.0.to_string())
    }
}

impl<'a> std::fmt::Display for StrArgument<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A particular command, ready for sending.
pub struct Command<T: CommandType> {
    pub id: Option<StringArgument>,
    pub command: T,
}

/// Some abstracted command, ready for sending.
pub struct DynCommand {
    pub id: Option<StringArgument>,
    pub command: Box<dyn CommandType>,
}

impl<T: CommandType> Command<T> {
    pub fn new(id: Option<StringArgument>, command: T) -> Self {
        Command { id, command }
    }
}

impl<T: CommandType> std::fmt::Display for Command<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = vec![self.command.command().to_string()];

        let id = self.id.as_ref().map(|id| format!("({})", id));
        if let Some(id_str) = id {
            fields.insert(0, id_str);
        };

        fields.extend(self.command.arguments());

        writeln!(f, "{}", fields.join(" "))
    }
}

impl std::fmt::Display for DynCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut fields = vec![self.command.command().to_string()];

        let id = self.id.as_ref().map(|id| format!("({})", id));
        if let Some(id_str) = id {
            fields.insert(0, id_str);
        };

        fields.extend(self.command.arguments());

        writeln!(f, "{}", fields.join(" "))
    }
}

pub trait CommandType {
    fn command(&self) -> &'static str;
    fn arguments(&self) -> Vec<String>;
}

/// The [handshake command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_handshake), sent before anything else in a session.
///
/// Response: [Hashtable](crate::messages::WHashtable)
pub struct HandshakeCommand {
    password_hash_algo: Vec<PasswordHashAlgo>,
    compression: Vec<Compression>,
}

impl HandshakeCommand {
    pub fn new(password_hash_algo: Vec<PasswordHashAlgo>, compression: Vec<Compression>) -> Self {
        Self {
            password_hash_algo,
            compression,
        }
    }
}

impl CommandType for HandshakeCommand {
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
        if ret.is_empty() {
            vec![]
        } else {
            vec![ret.join(",")]
        }
    }
}

/// The [init command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_init), used to authenticate a session.
///
/// Response: None
pub struct InitCommand {
    password: Option<StringArgument>,
    password_hash: Option<PasswordHash>,
    totp: Option<StringArgument>,
}

impl InitCommand {
    pub fn new(
        password: Option<StringArgument>,
        password_hash: Option<PasswordHash>,
        totp: Option<StringArgument>,
    ) -> Self {
        Self {
            password,
            password_hash,
            totp,
        }
    }
}

impl CommandType for InitCommand {
    fn command(&self) -> &'static str {
        "init"
    }

    fn arguments(&self) -> Vec<String> {
        fn escape(arg: &StringArgument) -> String {
            arg.0.replace(',', "\\,")
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

/// The [hdata command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_hdata), used to request structured data.
///
/// Response: [Hdata](crate::messages::GenericHdata)
pub struct HdataCommand {
    name: StringArgument,
    pointer: Countable<PointerOrName>,
    vars: Vec<Countable<StringArgument>>,
    keys: Vec<StringArgument>,
}

impl HdataCommand {
    /// HdataCommand constructor.
    ///
    /// name: The name of the requested hdata.
    ///
    /// pointer: A pointer or list name, forming the root of the path to the requested variable.
    ///
    /// vars: A list of variable names that, with the pointer root, form the path to the requested variable (the last in the path).
    ///
    /// keys: A list of keys to return in the hdata. An empty list returns all keys.
    pub fn new(
        name: StringArgument,
        pointer: Countable<PointerOrName>,
        vars: Vec<Countable<StringArgument>>,
        keys: Vec<StringArgument>,
    ) -> Self {
        Self {
            name,
            pointer,
            vars,
            keys,
        }
    }

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
                    .map(|s| s.0.as_str())
                    .collect::<Vec<&str>>()
                    .join(","),
            );
        }
        args
    }
}

/// The [info command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_info), used to request a single name/value pair.
///
/// Response: [Info](crate::messages::WInfo)
pub struct InfoCommand {
    name: StringArgument,
    arguments: Vec<StringArgument>,
}

impl InfoCommand {
    pub fn new(name: StringArgument, arguments: Vec<StringArgument>) -> Self {
        Self { name, arguments }
    }
}

impl CommandType for InfoCommand {
    fn command(&self) -> &'static str {
        "info"
    }

    fn arguments(&self) -> Vec<String> {
        let mut ret = vec![self.name.0.clone()];
        ret.extend(self.arguments.iter().map(|s| s.0.clone()));
        ret
    }
}

/// The [infolist command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_infolist), used to request a list of name/value pairs.
///
/// Response: [Infolist](crate::messages::WInfolist)
pub struct InfolistCommand {
    name: StringArgument,
    // As of version 3.7 of the WeeChat Relay Protocol, if there are any arguments, the first argument *must* be a Pointer.
    // Arguments to infolists without pointers can be accessed using a NULL pointer.
    arguments: Option<(Pointer, Vec<StringArgument>)>,
}

impl InfolistCommand {
    /// InfolistCommand constructor.
    ///
    /// name: The name of the infolist being requested.
    ///
    /// arguments: Arguments to the infolist request.
    pub fn new(
        name: StringArgument,
        pointer: Option<Pointer>,
        arguments: Vec<StringArgument>,
    ) -> Self {
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
        let mut ret = vec![self.name.0.clone()];
        if let Some(arguments) = &self.arguments {
            ret.push(arguments.0.to_string());
            ret.extend(arguments.1.iter().map(|s| s.0.clone()));
        }
        ret
    }
}

/// The [nicklist command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_nicklist), used to request a nicklist for one or all buffers.
///
/// Response: [Hdata](crate::messages::GenericHdata)
pub struct NicklistCommand {
    buffer: Option<PointerOrName>,
}

impl NicklistCommand {
    pub fn new(buffer: Option<PointerOrName>) -> Self {
        Self { buffer }
    }
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

/// The [input command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_input), used to send data to a buffer.
///
/// Response: None
pub struct InputCommand {
    buffer: PointerOrName,
    data: StringArgument,
}

impl InputCommand {
    pub fn new(buffer: PointerOrName, data: StringArgument) -> Self {
        Self { buffer, data }
    }
}

impl CommandType for InputCommand {
    fn command(&self) -> &'static str {
        "input"
    }

    fn arguments(&self) -> Vec<String> {
        vec![self.buffer.to_string(), self.data.0.clone()]
    }
}

/// The [completion command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_completion), used to request possible string completions.
///
/// Response: [Hdata](crate::messages::GenericHdata)
pub struct CompletionCommand {
    buffer: PointerOrName,
    // if ever extended to negatives aside -1, extend this to i32
    // so behavior of all currently working values is preserved
    // (Idk what you're completing that's over 32,768 chars, but I'm not judging)
    position: Option<u16>,
    data: Option<StringArgument>,
}

impl CompletionCommand {
    pub fn new(buffer: PointerOrName, position: Option<u16>, data: Option<StringArgument>) -> Self {
        Self {
            buffer,
            position,
            data,
        }
    }
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
            ret.push(data.0.clone());
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

/// The [sync command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_sync), used to pull updates for one or more buffers.
///
/// Response: 0 or more [Hdatas](crate::messages::GenericHdata), recieved until a [DesyncCommand] is sent.
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

/// The [desync command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_desync), used to stop updates from one or more buffers.
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

/// The [test command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_test), used to request sample objects for testing code.
///
/// Response (see linked docs above for values): [Char](crate::messages::WChar), [Integer](crate::messages::WInteger), [Integer](crate::messages::WInteger), [Long](crate::messages::WLongInteger), [Long](crate::messages::WLongInteger), [String](crate::messages::WString), [String](crate::messages::WString), [String](crate::messages::WString), [Buffer](crate::messages::WBuffer), [Buffer](crate::messages::WBuffer), [Pointer], [Pointer], [Time](crate::messages::WTime), [Array](crate::messages::WArray) ([String](crate::messages::WString)), [Array](crate::messages::WArray) ([Integer](crate::messages::WInteger))
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

/// The [ping command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_ping), used to test liveness and response time.
///
/// Response: [String](crate::messages::WString), with [Pong](crate::messages::Event::Pong) identifier.
pub struct PingCommand {
    pub argument: StringArgument,
}

impl PingCommand {
    pub fn new(argument: StringArgument) -> Self {
        Self { argument }
    }
}

impl CommandType for PingCommand {
    fn command(&self) -> &'static str {
        "ping"
    }
    fn arguments(&self) -> Vec<String> {
        vec![self.argument.0.clone()]
    }
}

/// The [quit command](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_quit), used to disconnect from the relay.
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
    /// Whether to receive signals about buffers: open/closed, moved, renamed, merged/unmerged, hidden/unhidden
    pub buffers: bool,
    /// Whether to receive signals about WeeChat upgrades (upgrade, upgrade ended)
    pub upgrade: bool,
    /// Whether to receive signals about each buffer (new lines, type changed, title changed, local variable added/removed, plus everything in [Self::buffers].
    pub buffer: bool,
    /// Whether to receive updated nicklists when changed.
    pub nicklist: bool,
}

impl SyncAllBuffers {
    fn to_string(&self) -> Option<String> {
        // spec specifically recommends (though doesn't require) handling the all case as the default case
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
    /// Only receive signals about the buffer: new lines, type changed, title changed, local variable added/removed, opened/closed, moved, renamed, merged/unmerged, hidden/unhidden.
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

fn print_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

impl std::fmt::Display for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordHash::Sha256 { salt, hash } => {
                write!(f, "sha256:{}:{}", print_bytes(salt), print_bytes(hash))
            }
            PasswordHash::Sha512 { salt, hash } => {
                write!(f, "sha512:{}:{}", print_bytes(salt), print_bytes(hash))
            }
            PasswordHash::Pbkdf2Sha256 {
                salt,
                iterations,
                hash,
            } => write!(
                f,
                "pbkdf2+sha256:{}:{}:{}",
                print_bytes(salt),
                iterations,
                print_bytes(hash)
            ),
            PasswordHash::Pbkdf2Sha512 {
                salt,
                iterations,
                hash,
            } => write!(
                f,
                "pbkdf2+sha512:{}:{}:{}",
                print_bytes(salt),
                iterations,
                print_bytes(hash)
            ),
        }
    }
}

/// The count of elements in an [HdataCommand].
///
/// Positive counts mean the next elements, negative counts mean the previous elements, a glob means the next elements to the end of the list.
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

/// A contable element in an [HdataCommand], with its count.
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

/// A [Pointer] or name in root of the path of an [HdataCommand].
pub enum PointerOrName {
    Pointer(Pointer),
    Name(StringArgument),
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

    #[test]
    fn test_string_argument() {
        let good_string = StrArgument::new("foo").expect("Failed to unwrap StringArgument");
        assert_eq!(good_string.to_string(), "foo");

        let bad_string = StrArgument::new("foo\nbar").expect_err("Bad argument didn't err");
        assert_eq!(bad_string, WeechatError::NewlineInArgument);

        const GOOD_STRING: StrArgument = StrArgument::const_new("foo");
        assert_eq!(GOOD_STRING.to_string(), "foo");

        // should fail to compile
        //const BAD_STRING: StrArgument = StrArgument::const_new("foo\nbar");

        let good_string = good_string.to_stringargument();
        assert_eq!(good_string.to_string(), "foo");

        let good_string =
            StringArgument::new("foo".to_string()).expect("Failed to unwrap StringArgument");
        assert_eq!(good_string.to_string(), "foo");

        let bad_string =
            StringArgument::new("foo\nbar".to_string()).expect_err("Bad argument didn't err");
        assert_eq!(bad_string, WeechatError::NewlineInArgument);

        let good_string = literal_stringarg!("foo");
        assert_eq!(good_string.to_string(), "foo");

        // should fail to compile
        //let bad_string = literal_stringarg!("foo\nbar");
    }

    // n.b. these tests only test the string commands they create,
    // not any kind of interaction with a server
    #[test]
    fn test_handshake() {
        use crate::basic_types::Compression;

        let default_handshake = HandshakeCommand::new(vec![], vec![]);
        let compression_handshake = HandshakeCommand::new(vec![], vec![Compression::Zstd]);
        let all_hash_algos = vec![
            PasswordHashAlgo::Plain,
            PasswordHashAlgo::Sha256,
            PasswordHashAlgo::Sha512,
            PasswordHashAlgo::Pbkdf2Sha256,
            PasswordHashAlgo::Pbkdf2Sha512,
        ];
        let full_handshake = HandshakeCommand::new(
            all_hash_algos,
            vec![Compression::Zstd, Compression::Zlib, Compression::Off],
        );

        let command = Command::new(None, default_handshake);
        assert_eq!(command.to_string(), "handshake\n");

        let command = Command::new(None, compression_handshake);
        assert_eq!(command.to_string(), "handshake compression=zstd\n");

        let command = Command::new(
            Some(StrArgument::const_new("Foo").to_stringargument()),
            full_handshake,
        );
        // FIXME: we shouldn't be testing the order of the options here,
        // but should make sure however we end up testing checks for proper formatting
        assert_eq!(command.to_string(), "(Foo) handshake password_hash_algo=plain:sha256:sha512:pbkdf2+sha256:pbkdf2+sha512,compression=zstd:zlib:off\n");
    }

    #[test]
    fn test_init() {
        let normal_password = InitCommand::new(Some(literal_stringarg!("mypass")), None, None);
        let password_with_commas =
            InitCommand::new(Some(literal_stringarg!("mypass,with,commas")), None, None);
        let password_with_totp = InitCommand::new(
            Some(literal_stringarg!("mypass")),
            None,
            Some(literal_stringarg!("123456")),
        );

        let salt = vec![
            0x85, 0xb1, 0xee, 0x00, 0x69, 0x5a, 0x5b, 0x25, 0x4e, 0x14, 0xf4, 0x88, 0x55, 0x38,
            0xdf, 0x0d, 0xa4, 0xb7, 0x32, 0x07, 0xf5, 0xaa, 0xe4,
        ];

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
        assert_eq!(command.to_string(), "init password_hash=sha256:85b1ee00695a5b254e14f4885538df0da4b73207f5aae4:2c6ed12eb0109fca3aedc03bf03d9b6e804cd60a23e1731fd17794da423e21db\n");

        let command = Command::new(None, sha512_password);
        assert_eq!(command.to_string(), "init password_hash=sha512:85b1ee00695a5b254e14f4885538df0da4b73207f5aae4:0a1f0172a542916bd86e0cbceebc1c38ed791f6be246120452825f0d74ef1078c79e9812de8b0ab3dfaf598b6ca14522374ec6a8653a46df3f96a6b54ac1f0f8\n");

        let command = Command::new(None, pbkdf2_password);
        assert_eq!(command.to_string(), "init password_hash=pbkdf2+sha256:85b1ee00695a5b254e14f4885538df0da4b73207f5aae4:100000:ba7facc3edb89cd06ae810e29ced85980ff36de2bb596fcf513aaab626876440\n");
    }

    #[test]
    fn test_hdata() {
        let hdata_buffers = HdataCommand::new(
            literal_stringarg!("buffer"),
            Countable::new(
                Some(Count::Glob),
                PointerOrName::Name(literal_stringarg!("gui_buffers")),
            ),
            vec![],
            vec![
                literal_stringarg!("number"),
                literal_stringarg!("full_name"),
            ],
        );

        let hdata_lines = HdataCommand::new(
            literal_stringarg!("buffer"),
            Countable::new(None, PointerOrName::Name(literal_stringarg!("gui_buffers"))),
            vec![
                Countable::new(None, literal_stringarg!("own_lines")),
                Countable::new(Some(Count::Glob), literal_stringarg!("first_line")),
                Countable::new(None, literal_stringarg!("data")),
            ],
            vec![],
        );

        let hdata_hotlist = HdataCommand::new(
            literal_stringarg!("hotlist"),
            Countable::new(
                Some(Count::Glob),
                PointerOrName::Name(literal_stringarg!("gui_hotlist")),
            ),
            vec![],
            vec![],
        );

        let command = Command::new(Some(literal_stringarg!("hdata_buffers")), hdata_buffers);
        assert_eq!(
            command.to_string(),
            "(hdata_buffers) hdata buffer:gui_buffers(*) number,full_name\n"
        );

        let command = Command::new(Some(literal_stringarg!("hdata_lines")), hdata_lines);
        assert_eq!(
            command.to_string(),
            "(hdata_lines) hdata buffer:gui_buffers/own_lines/first_line(*)/data\n"
        );

        let command = Command::new(Some(literal_stringarg!("hdata_hotlist")), hdata_hotlist);
        assert_eq!(
            command.to_string(),
            "(hdata_hotlist) hdata hotlist:gui_hotlist(*)\n"
        );
    }

    #[test]
    fn test_info() {
        let info = InfoCommand::new(literal_stringarg!("version"), vec![]);
        let command = Command::new(Some(literal_stringarg!("info_version")), info);
        assert_eq!(command.to_string(), "(info_version) info version\n");

        let info = InfoCommand::new(
            literal_stringarg!("nick_color"),
            vec![literal_stringarg!("foo")],
        );
        let command = Command::new(Some(literal_stringarg!("foo_color")), info);
        assert_eq!(command.to_string(), "(foo_color) info nick_color foo\n");
    }

    #[test]
    fn test_infolist() {
        let id = literal_stringarg!("infolist_buffer");
        let name = literal_stringarg!("buffer");
        let pointer = Pointer::new("1234abcd".as_bytes().to_vec()).expect("invalid pointer");
        let arguments = vec![literal_stringarg!("core.weechat")];

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
        let all_buffers = NicklistCommand::new(None);
        let one_buffer = NicklistCommand::new(Some(PointerOrName::Name(literal_stringarg!(
            "irc.libera.#weechat"
        ))));

        let command = Command::new(Some(literal_stringarg!("nicklist_all")), all_buffers);
        assert_eq!(command.to_string(), "(nicklist_all) nicklist\n");

        let command = Command::new(Some(literal_stringarg!("nicklist_weechat")), one_buffer);
        assert_eq!(
            command.to_string(),
            "(nicklist_weechat) nicklist irc.libera.#weechat\n"
        );
    }

    #[test]
    fn test_input() {
        let help = InputCommand::new(
            PointerOrName::Name(literal_stringarg!("core.weechat")),
            literal_stringarg!("/help filter"),
        );

        let hello = InputCommand::new(
            PointerOrName::Name(literal_stringarg!("irc.libera.#weechat")),
            literal_stringarg!("hello!"),
        );

        let command = Command::new(None, help);
        assert_eq!(command.to_string(), "input core.weechat /help filter\n");

        let command = Command::new(None, hello);
        assert_eq!(command.to_string(), "input irc.libera.#weechat hello!\n");
    }

    #[test]
    fn test_completion() {
        let completion_help = CompletionCommand::new(
            PointerOrName::Name(literal_stringarg!("core.weechat")),
            None,
            Some(literal_stringarg!("/help fi")),
        );

        let completion_query = CompletionCommand::new(
            PointerOrName::Name(literal_stringarg!("core.weechat")),
            Some(5),
            Some(literal_stringarg!("/quernick")),
        );

        let command = Command::new(Some(literal_stringarg!("completion_help")), completion_help);
        assert_eq!(
            command.to_string(),
            "(completion_help) completion core.weechat -1 /help fi\n"
        );

        let command = Command::new(
            Some(literal_stringarg!("completion_query")),
            completion_query,
        );
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
            vec![PointerOrName::Name(literal_stringarg!("core.buffer"))],
            SyncSomeBuffers::All,
        );

        let without_nicklist = SyncCommand::SomeBuffers(
            vec![PointerOrName::Name(literal_stringarg!(
                "irc.libera.#weechat"
            ))],
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
            vec![PointerOrName::Name(literal_stringarg!(
                "irc.libera.#weechat"
            ))],
            SyncSomeBuffers::Nicklist,
        );

        let all_signals = DesyncCommand::SomeBuffers(
            vec![PointerOrName::Name(literal_stringarg!(
                "irc.libera.#weechat"
            ))],
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
        let ping = PingCommand::new(literal_stringarg!("foo"));
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
