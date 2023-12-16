//! weechat-relay-rs is a pure-Rust library for interfacing with a
//! [WeeChat Relay](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html),
//! including sending commands and receiving messages.

pub mod basic_types;
pub mod commands;
pub mod message_parser;
pub mod messages;

use commands::{Command, CommandType, DynCommand};
use message_parser::ParseMessageError;
use messages::Message;
use std::io::Write;
use std::net::TcpStream;

pub struct Connection {
    pub stream: TcpStream,
}

impl Connection {
    pub fn send_command<T: CommandType>(
        &mut self,
        command: &Command<T>,
    ) -> Result<(), std::io::Error> {
        self.stream
            .write_all(&Vec::<u8>::from(command.to_string()))?;
        self.stream.flush()
    }

    pub fn send_commands(
        &mut self,
        commands: &mut dyn Iterator<Item = &DynCommand>,
    ) -> Result<(), std::io::Error> {
        let commands: String = commands.map(|c| c.to_string()).collect();
        self.stream.write_all(&Vec::<u8>::from(commands))?;
        self.stream.flush()
    }

    pub fn get_message(
        &mut self,
    ) -> Result<Message, ParseMessageError<Vec<u8>, nom::error::VerboseError<Vec<u8>>>> {
        message_parser::get_message_verbose_errors(&mut self.stream)
    }
}
