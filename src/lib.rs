//! weechat-relay-rs is a pure-Rust library for interfacing with a
//! [WeeChat Relay](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html),
//! including sending commands and receiving messages.

pub mod basic_types;
pub mod commands;
pub mod message_parser;
pub mod messages;

use basic_types::{Compression, PasswordHashAlgo};
use commands::{Command, CommandType, DynCommand, HandshakeCommand};
use message_parser::ParseMessageError;
use messages::{Message, WHashtable, WString};
use std::io::Write;
use std::net::TcpStream;
use std::string::String;

type NomError = nom::error::Error<Vec<u8>>;

#[derive(Debug)]
pub enum WeechatError {
    /// The client attempted to send an argument with a newline in an unescaped connection.
    NewlineInArgument,
    /// An IO error on the TCP stream.
    IOError(std::io::Error),
    /// An error was encountered in the structure of incoming messages.
    ParserError(ParseMessageError<NomError>),
    /// The server returned a valid message, but not one we expected.
    UnexpectedResponse(String),
    /// The handshake failed to negotiate viable parameters.
    FailedHandshake,
}

impl std::fmt::Display for WeechatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NewlineInArgument => writeln!(f, "newline found in unescaped argument"),
            Self::IOError(e) => e.fmt(f),
            Self::ParserError(e) => e.fmt(f),
            Self::UnexpectedResponse(s) => writeln!(f, "received unexpected message: {}", s),
            Self::FailedHandshake => writeln!(f, "handshake failed to negotiate parameters"),
        }
    }
}

impl std::error::Error for WeechatError {}

impl From<std::io::Error> for WeechatError {
    fn from(error: std::io::Error) -> Self {
        Self::IOError(error)
    }
}

impl From<ParseMessageError<NomError>> for WeechatError {
    fn from(error: ParseMessageError<NomError>) -> Self {
        Self::ParserError(error)
    }
}

impl From<std::string::FromUtf8Error> for WeechatError {
    fn from(_error: std::string::FromUtf8Error) -> Self {
        Self::UnexpectedResponse("non-UTF-8 message".to_string())
    }
}

impl From<std::str::Utf8Error> for WeechatError {
    fn from(_error: std::str::Utf8Error) -> Self {
        Self::UnexpectedResponse("non-UTF-8 message".to_string())
    }
}

/// A TCP connection to the WeeChat relay, along with the configuration for the connection,
/// likely negotiated in a
/// [handshake](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#command_handshake).
#[derive(Debug)]
pub struct Connection {
    pub stream: TcpStream,
    pub password_hash_algo: PasswordHashAlgo,
    pub password_hash_iterations: u32,
    pub totp: bool,
    pub nonce: Vec<u8>,
    pub compression: Compression,
    pub escape_commands: bool,
}

impl Connection {
    /// Using the given stream and handshake arguments, attempt to establish a connection.
    ///
    /// If a `handshake` is provided, this performs a [handshake](crate::commands::HandshakeCommand),
    /// so you should not attempt to send another after,
    /// but this does not perform the [init](crate::commands::InitCommand) regardless.
    pub fn new(
        mut stream: TcpStream,
        handshake: Option<HandshakeCommand>,
    ) -> Result<Self, WeechatError> {
        let Some(handshake) = handshake else {
            return Ok(Self {
                stream,
                password_hash_algo: PasswordHashAlgo::Plain,
                password_hash_iterations: 0,
                totp: false,
                nonce: vec![],
                compression: Compression::Off,
                escape_commands: false,
            });
        };

        stream.write_all(&Vec::<u8>::from(handshake.to_string()))?;
        stream.flush()?;

        let messages::Object::Htb(response) = message_parser::get_message::<NomError>(&mut stream)?
            .objects
            .into_iter()
            .next()
            .expect("shouldn't return without a response")
        else {
            return Err(WeechatError::UnexpectedResponse(
                "non-htb handshake".to_string(),
            ));
        };

        let WHashtable { keys, vals } = response;
        let messages::WArray::Str(skeys) = keys else {
            return Err(WeechatError::UnexpectedResponse(
                "non-str handshake keys".to_string(),
            ));
        };
        let messages::WArray::Str(svals) = vals else {
            return Err(WeechatError::UnexpectedResponse(
                "non-str handshake vals".to_string(),
            ));
        };
        let config = messages::to_hashmap(skeys, svals);
        let password_hash_algo = config
            .get(&WString::from_ref(b"password_hash_algo"))
            .ok_or(WeechatError::UnexpectedResponse(
                "handshake did not return a password_hash_algo".to_string(),
            ))?
            .bytes()
            .clone()
            .map(String::from_utf8)
            .transpose()?
            .and_then(|s| PasswordHashAlgo::parse(&s))
            .ok_or(WeechatError::FailedHandshake)?;

        let password_hash_iterations = match password_hash_algo {
            PasswordHashAlgo::Pbkdf2Sha256 | PasswordHashAlgo::Pbkdf2Sha512 => {
                let bytes = config
                    .get(&WString::from_ref(b"password_hash_algo"))
                    .and_then(|s| s.bytes().clone())
                    .ok_or(WeechatError::UnexpectedResponse(
                        "iterated hash selected, but no iteration count returned in handshake"
                            .to_string(),
                    ))?;
                let s = String::from_utf8(bytes)?;
                s.parse().or(Err(WeechatError::UnexpectedResponse(
                    "password_hash_iterations was non-numerical".to_string(),
                )))?
            }
            _ => 0,
        };

        let totp = config.get(&WString::from_ref(b"totp")) == Some(&WString::from_ref(b"on"));

        let nonce_hex = config
            .get(&WString::from_ref(b"nonce"))
            .and_then(|w| w.bytes().clone());
        let nonce = if let Some(hex) = nonce_hex {
            bytes_from_hex(&hex)?
        } else {
            vec![]
        };

        let compression = config
            .get(&WString::from_ref(b"compression"))
            .and_then(|w| w.bytes().clone())
            .map(String::from_utf8)
            .transpose()?;
        let compression = if let Some(compression) = compression {
            Compression::parse(&compression).ok_or(WeechatError::FailedHandshake)?
        } else {
            Compression::Off
        };

        let escape_commands =
            config.get(&WString::from_ref(b"escape_commands")) == Some(&WString::from_ref(b"on"));

        Ok(Self {
            stream,
            password_hash_algo,
            password_hash_iterations,
            totp,
            nonce,
            compression,
            escape_commands,
        })
    }

    fn check_unescaped_arg(arg: String) -> Result<String, WeechatError> {
        if !arg.is_empty() && arg[..arg.len() - 1].contains('\n') {
            return Err(WeechatError::NewlineInArgument);
        }
        Ok(arg)
    }

    /// Send a single command on the `Connection`.
    pub fn send_command<T: CommandType>(
        &mut self,
        command: &Command<T>,
    ) -> Result<(), WeechatError> {
        let string = if self.escape_commands {
            command.escaped()
        } else {
            Connection::check_unescaped_arg(command.to_string())?
        };
        self.stream.write_all(&Vec::<u8>::from(string))?;
        Ok(self.stream.flush()?)
    }

    /// Send a series of commands on the `Connection`.
    pub fn send_commands(
        &mut self,
        commands: &mut dyn Iterator<Item = &DynCommand>,
    ) -> Result<(), WeechatError> {
        let commands: String = if self.escape_commands {
            commands.map(DynCommand::escaped).collect()
        } else {
            commands
                .map(|c| Connection::check_unescaped_arg(c.to_string()))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .collect()
        };
        self.stream.write_all(&Vec::<u8>::from(commands))?;
        Ok(self.stream.flush()?)
    }

    /// Get a response on the `Connection`.
    pub fn get_message(&mut self) -> Result<Message, ParseMessageError<NomError>> {
        message_parser::get_message::<NomError>(&mut self.stream)
    }
}

fn bytes_from_hex(ascii_hex: &[u8]) -> Result<Vec<u8>, WeechatError> {
    let s = std::str::from_utf8(ascii_hex)?;
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .or(Err(WeechatError::UnexpectedResponse(
            "expected valid hexidecimal".to_string(),
        )))
}
