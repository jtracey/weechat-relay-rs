pub(crate) use weechat_relay_rs::apply_to_warray_with;
use weechat_relay_rs::basic_types::{Compression, PasswordHashAlgo, Pointer, PointerError};
use weechat_relay_rs::commands::{
    CommandType, CompletionCommand, Count, Countable, DesyncCommand, DynCommand, HandshakeCommand,
    HdataCommand, InfoCommand, InfolistCommand, InitCommand, InputCommand, NicklistCommand,
    PingCommand, PointerOrName, QuitCommand, SyncAllBuffers, SyncCommand, SyncSomeBuffers,
    TestCommand,
};
use weechat_relay_rs::messages::{
    GenericHdata, Identifier, MessageType, Object, ObjectRef, WArray, WHashtable, WInfo, WInfolist,
    WString,
};
use weechat_relay_rs::{Connection, WeechatError};

use std::io::Write;
use std::num::{ParseFloatError, ParseIntError};
use std::time::Duration;
use std::{fs, io};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Host the WeeChat relay is running on
    #[arg(long)]
    host: String,

    /// File containing commands to execute
    #[arg(short, long)]
    script: Option<String>,

    /// Handshake command to execute on launch
    #[arg(long)]
    handshake: Option<Option<String>>,

    /// Init command to execute on launch (after handshake)
    #[arg(short, long)]
    init: Option<String>,

    /// Set the timeout (in seconds) for waiting for a response
    #[arg(short, long)]
    timeout: Option<f64>,

    /// Parse escape sequences in commands (only `\\` and `\n`; you should set a handshake too)
    #[arg(short, long)]
    escape: bool,
}

#[derive(Debug)]
enum InputError {
    InvalidInt,
    InvalidFloat,
    InvalidStr,
    InvalidCountable,
    InvalidPtr,
    InvalidKeyVal,
    MissingArgument,
}

impl From<ParseIntError> for InputError {
    fn from(_: ParseIntError) -> Self {
        Self::InvalidInt
    }
}

impl From<ParseFloatError> for InputError {
    fn from(_: ParseFloatError) -> Self {
        Self::InvalidFloat
    }
}

impl From<WeechatError> for InputError {
    fn from(_: WeechatError) -> Self {
        Self::InvalidStr
    }
}

impl From<PointerError> for InputError {
    fn from(_: PointerError) -> Self {
        Self::InvalidPtr
    }
}

fn main() {
    let cli = Args::parse();

    let stream = std::net::TcpStream::connect(&cli.host).unwrap();
    if let Some(timeout) = cli.timeout {
        stream
            .set_read_timeout(Some(Duration::from_secs_f64(timeout)))
            .unwrap();
    }

    let handshake = cli.handshake.map(|handshake| {
        let handshake = handshake.unwrap_or_default();
        parse_handshake_command(&handshake).unwrap()
    });

    let mut connection = Connection::new(stream, handshake).unwrap();

    let contents;
    let mut script = if let Some(script) = cli.script {
        contents = fs::read_to_string(script).expect("Failed to read script.");
        Some(contents.lines())
    } else {
        None
    };

    let prompt = atty::is(atty::Stream::Stdin);

    let mut commands = vec![];
    let mut responses = 0;

    if let Some(init) = cli.init {
        let command = parse_init_command(&init).unwrap().0.unwrap();
        let command = DynCommand { id: None, command };
        commands.push(command);
    }

    loop {
        if !commands.is_empty() {
            connection.send_commands(&mut commands.iter()).unwrap();
            commands.clear();
        }

        for _ in 0..responses {
            let message = connection.get_message();
            match message {
                Ok(m) => {
                    println!("({})", WrappedId(&m.id));
                    for o in m.objects.iter() {
                        print_message(o);
                    }
                }
                Err(e) => eprintln!("{:?}", e),
            }
        }
        responses = 0;

        let command_in = if let Some(ref mut lines) = script {
            if let Some(ref command_in) = lines.next() {
                command_in.to_string()
            } else {
                return;
            }
        } else {
            if prompt {
                print!("> ");
                std::io::stdout().flush().unwrap();
            }

            let mut command_in = String::new();
            let read = io::stdin()
                .read_line(&mut command_in)
                .expect("Failed to read line");
            if read == 0 {
                return;
            }
            command_in.pop(); // remove trailing \n
            command_in
        };

        let (command, more_responses) = parse_command(&command_in, cli.escape);
        if let Some(command) = command {
            commands.push(command);
        }
        responses += more_responses;
    }
}

fn parse_command(input: &str, escape: bool) -> (Option<DynCommand>, u32) {
    let (id, input) = if let Some(stripped) = input.strip_prefix('(') {
        let Some((id, input)) = stripped.split_once(')') else {
            eprintln!("Malformed command: missing )");
            return (None, 0);
        };
        (Some(id.to_string()), input.trim_start())
    } else {
        (None, input)
    };

    let (command, mut args) = split_out_args(input);
    let escaped_args = if escape && !args.is_empty() {
        Some(args.replace("\\n", "\n").replace("\\\\", "\\"))
    } else {
        None
    };
    if let Some(escaped_args) = &escaped_args {
        args = escaped_args;
    }

    let res: Result<(Option<Box<dyn CommandType>>, u32), InputError> = match command {
        "init" => parse_init_command(args),
        "hdata" => parse_hdata_command(args),
        "info" => parse_info_command(args),
        "infolist" => parse_infolist_command(args),
        "nicklist" => parse_nicklist_command(args),
        "input" => parse_input_command(args),
        "completion" => parse_completion_command(args),
        "sync" => parse_sync_command(args),
        "desync" => parse_desync_command(args),
        "test" => parse_test_command(args),
        "ping" => parse_ping_command(args),
        "quit" => parse_quit_command(args),
        "_get" => parse_get_command(args),
        "_sleep" => parse_sleep_command(args),
        "_quit" => std::process::exit(0),
        _ => {
            eprintln!("Unknown command: {} (ignoring).", command);
            Ok((None, 0))
        }
    };
    match res {
        Err(e) => {
            eprintln!("Malformed command: {:?}", e);
            (None, 0)
        }
        Ok((None, i)) => (None, i),
        Ok((Some(command), i)) => (Some(DynCommand { id, command }), i),
    }
}

fn split_out_args(s: &str) -> (&str, &str) {
    match s.split_once(' ') {
        Some((s1, s2)) => (s1, s2.trim_start()),
        None => (s, ""),
    }
}

fn parse_get_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    if args.is_empty() {
        Ok((None, 1))
    } else {
        Ok((None, args.parse()?))
    }
}

fn parse_sleep_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    if args.is_empty() {
        Err(InputError::MissingArgument)
    } else {
        let seconds: f64 = args.parse()?;
        std::thread::sleep(Duration::from_secs_f64(seconds));
        Ok((None, 0))
    }
}

fn parse_handshake_command(args: &str) -> Result<HandshakeCommand, InputError> {
    let args = args.split_whitespace();
    let mut password_hash_algo = vec![PasswordHashAlgo::Plain];
    let mut escape_commands = false;

    for arg in args {
        let keyval = arg.split_once('=').ok_or(InputError::InvalidKeyVal)?;
        match keyval {
            ("password_hash_algo", val) => {
                password_hash_algo = val
                    .split(':')
                    .map(PasswordHashAlgo::parse)
                    .collect::<Option<Vec<_>>>()
                    .ok_or(InputError::InvalidKeyVal)?;
            }
            ("compression", _) => eprintln!("Compression is not (yet) supported. Ignoring flag."),
            ("escape_commands", "on") => escape_commands = true,
            ("escape_commands", "off") => escape_commands = false,
            _ => return Err(InputError::InvalidKeyVal),
        }
    }
    let handshake = HandshakeCommand {
        password_hash_algo,
        compression: vec![Compression::Off],
        escape_commands,
    };
    Ok(handshake)
}

fn parse_init_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let init = InitCommand {
        password: Some(args.to_string()),
        password_hash: None,
        totp: None,
    };
    Ok((Some(Box::new(init)), 0))
}

fn parse_countable(s: &str) -> Result<Countable<&str>, InputError> {
    let (s, c) = if s.ends_with(')') {
        let (s, count) = s.rsplit_once('(').ok_or(InputError::InvalidCountable)?;
        let count = &count[..count.len() - 1];
        let count = if count == "*" {
            Count::Glob
        } else {
            Count::Count(count.parse()?)
        };
        (s, Some(count))
    } else {
        (s, None)
    };
    Ok(Countable {
        count: c,
        object: s,
    })
}

fn parse_hdata_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let mut split = args.split_whitespace();
    let (name, rpath) = split
        .next()
        .ok_or(InputError::MissingArgument)?
        .split_once(':')
        .ok_or(InputError::MissingArgument)?;
    let name = name.to_string();
    let mut rpath = rpath.split('/').map(parse_countable);

    let pointer = rpath.next().ok_or(InputError::MissingArgument)??;
    let pointer = Countable {
        count: pointer.count,
        object: PointerOrName::Name(pointer.object.to_string()),
    };

    let vars = rpath
        .map(|countable| {
            let countable = countable?;
            Ok(Countable {
                count: countable.count,
                object: countable.object.to_string(),
            })
        })
        .collect::<Result<_, InputError>>()?;

    let keys = if let Some(s) = split.next() {
        s.split(',').map(String::from).collect()
    } else {
        vec![]
    };

    let hdata = HdataCommand {
        name,
        pointer,
        vars,
        keys,
    };
    Ok((Some(Box::new(hdata)), 1))
}

fn parse_info_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let mut split = args.split_whitespace().map(String::from);
    let name = split.next().ok_or(InputError::MissingArgument)?;
    let arguments = split.collect();
    let info = InfoCommand { name, arguments };
    Ok((Some(Box::new(info)), 1))
}

fn parse_infolist_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let mut split = args.split_whitespace().map(String::from);
    let name = split.next().ok_or(InputError::MissingArgument)?;
    let pointer = split
        .next()
        .map(|p| Pointer::new(p.as_bytes().to_vec()))
        .transpose()?;
    let arguments = split.collect();
    let info = InfolistCommand::new(name, pointer, arguments);
    Ok((Some(Box::new(info)), 1))
}

fn parse_nicklist_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let buffer = args
        .split_whitespace()
        .next()
        .map(|s| PointerOrName::Name(s.to_string()));
    let nicklist = NicklistCommand { buffer };
    Ok((Some(Box::new(nicklist)), 1))
}

fn parse_input_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let (buffer, data) = args.split_once(' ').ok_or(InputError::MissingArgument)?;
    let buffer = PointerOrName::Name(buffer.to_string());
    let data = data.to_string();
    let input = InputCommand { buffer, data };
    Ok((Some(Box::new(input)), 0))
}

fn parse_completion_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let (buffer, args) = args.split_once(' ').ok_or(InputError::MissingArgument)?;
    let buffer = PointerOrName::Name(buffer.to_string());
    let args = args.trim_start();

    let (position, data) = if let Some((position, args)) = args.split_once(' ') {
        (position, Some(args.trim_start().to_string()))
    } else {
        (args, None)
    };
    let position: i32 = position.parse()?;
    let position = if position.is_negative() {
        None
    } else {
        Some(position as u16)
    };

    let completion = CompletionCommand {
        buffer,
        position,
        data,
    };
    Ok((Some(Box::new(completion)), 1))
}

fn parse_sync_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let sync = if args.is_empty() || args.starts_with('*') {
        let options = if let Some((_, options)) = args.split_once(' ') {
            let options: Vec<_> = options.trim().split(',').collect();
            SyncAllBuffers {
                buffers: options.contains(&"buffers"),
                upgrade: options.contains(&"upgrade"),
                buffer: options.contains(&"buffer"),
                nicklist: options.contains(&"nicklist"),
            }
        } else {
            SyncAllBuffers {
                buffers: true,
                upgrade: true,
                buffer: true,
                nicklist: true,
            }
        };
        SyncCommand::AllBuffers(options)
    } else {
        let (buffers, options) = if let Some((buffers, options)) = args.split_once(' ') {
            let options: Vec<_> = options.trim().split(',').collect();
            let options = if options.contains(&"buffer") && options.contains(&"nicklist") {
                SyncSomeBuffers::All
            } else if options.contains(&"buffer") {
                SyncSomeBuffers::Buffer
            } else if options.contains(&"nicklist") {
                SyncSomeBuffers::Nicklist
            } else {
                SyncSomeBuffers::All
            };
            (buffers.split(','), options)
        } else {
            (args.split(','), SyncSomeBuffers::All)
        };
        let buffers = buffers
            .map(|s| PointerOrName::Name(s.to_string()))
            .collect();
        SyncCommand::SomeBuffers(buffers, options)
    };

    Ok((Some(Box::new(sync)), 0))
}

fn parse_desync_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let sync = if args.is_empty() || args.starts_with('*') {
        let options = if let Some((_, options)) = args.split_once(' ') {
            let options: Vec<_> = options.trim().split(',').collect();
            SyncAllBuffers {
                buffers: options.contains(&"buffers"),
                upgrade: options.contains(&"upgrade"),
                buffer: options.contains(&"buffer"),
                nicklist: options.contains(&"nicklist"),
            }
        } else {
            SyncAllBuffers {
                buffers: true,
                upgrade: true,
                buffer: true,
                nicklist: true,
            }
        };
        DesyncCommand::AllBuffers(options)
    } else {
        let (buffers, options) = if let Some((buffers, options)) = args.split_once(' ') {
            let options: Vec<_> = options.trim().split(',').collect();
            let options = if options.contains(&"buffer") && options.contains(&"nicklist") {
                SyncSomeBuffers::All
            } else if options.contains(&"buffer") {
                SyncSomeBuffers::Buffer
            } else if options.contains(&"nicklist") {
                SyncSomeBuffers::Nicklist
            } else {
                SyncSomeBuffers::All
            };
            (buffers.split(','), options)
        } else {
            (args.split(','), SyncSomeBuffers::All)
        };
        let buffers = buffers
            .map(|s| PointerOrName::Name(s.to_string()))
            .collect();
        DesyncCommand::SomeBuffers(buffers, options)
    };

    Ok((Some(Box::new(sync)), 0))
}

fn parse_test_command(_args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let test = TestCommand::default();
    Ok((Some(Box::new(test)), 1))
}

fn parse_ping_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let ping = PingCommand {
        argument: args.to_string(),
    };
    Ok((Some(Box::new(ping)), 1))
}

fn parse_quit_command(_args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let quit = QuitCommand::default();
    Ok((Some(Box::new(quit)), 0))
}

fn print_message(object: &Object) {
    let object = WrappedObject(object.object_ref());
    println!("{}", object);
}

struct WrappedObject<'a>(ObjectRef<'a>);

impl std::fmt::Display for WrappedObject<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            ObjectRef::Chr(o) => write!(f, "chr: {}", o),
            ObjectRef::Int(o) => write!(f, "int: {}", o),
            ObjectRef::Lon(o) => write!(f, "lon: {}", o),
            ObjectRef::Str(o) => fmt_str(o, f),
            ObjectRef::Buf(o) => write!(f, "buf: {:?}", o),
            ObjectRef::Ptr(o) => write!(f, "ptr: {}", o),
            ObjectRef::Tim(o) => write!(f, "tim: {}", o),
            ObjectRef::Htb(o) => fmt_htb(o, f),
            ObjectRef::Hda(o) => fmt_hda(o, f),
            ObjectRef::Inf(o) => fmt_inf(o, f),
            ObjectRef::Inl(o) => fmt_inl(o, f),
            ObjectRef::Arr(o) => fmt_arr(o, f),
        }
    }
}

fn to_utf8_lossy(ws: &WString) -> Option<std::borrow::Cow<'_, str>> {
    ws.bytes().as_ref().map(|k| String::from_utf8_lossy(k))
}

fn clean_string(ws: &WString) -> String {
    if let Some(s) = to_utf8_lossy(ws) {
        format!("{:?}", s) // Debug because we disambiguate the "None" string w/ quotes
    } else {
        "None".to_string()
    }
}

fn fmt_str(wstr: &WString, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if let Some(s) = to_utf8_lossy(wstr) {
        write!(f, "str: {:?}", s) // Debug because we disambiguate the "None" string w/ quotes
    } else {
        write!(f, "str: None")
    }
}

fn fmt_htb(htb: &WHashtable, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let keys = htb.keys.to_ref_vec();
    let vals = htb.vals.to_ref_vec();
    let keypairs = keys.into_iter().zip(vals);
    write!(f, "htb: {{")?;
    for (key, val) in keypairs {
        write!(f, "({} => {}),", WrappedObject(key), WrappedObject(val))?
    }
    write!(f, "}}")
}

fn fmt_hda(hda: &GenericHdata, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "hda: {{ hpath: {}, ", clean_string(&hda.hpath))?;
    let sets = hda.sets();
    for (i, set) in sets.into_iter().enumerate() {
        write!(f, "item {} => {{ ppath: ", i)?;
        fmt_slice(&hda.ppaths[i], f)?;
        write!(f, ", ")?;
        for (key, val) in set.into_iter() {
            write!(
                f,
                "{}: {}, ",
                String::from_utf8_lossy(key),
                WrappedObject(val)
            )?;
        }
        write!(f, "}}, ")?
    }
    write!(f, "}}")
}

fn fmt_inf(inf: &WInfo, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let name = clean_string(&inf.name);
    let value = clean_string(&inf.value);
    write!(f, "inf: ({}: {})", name, value)
}

fn fmt_inl(inl: &WInfolist, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    let name = clean_string(&inl.name);
    let items: Vec<_> = inl
        .items
        .iter()
        .map(|i| {
            i.variables
                .iter()
                .map(|v| {
                    (
                        clean_string(&v.name),
                        format!("{}", WrappedObject(v.value.object_ref())),
                    )
                })
                .collect::<Vec<(_, _)>>()
        })
        .collect();
    write!(f, "inl: {}: [", name)?;
    for item in items.iter() {
        write!(f, "[")?;
        for (key, val) in item.iter() {
            write!(f, "({} => {}), ", key, val)?;
        }
        write!(f, "],")?;
    }
    write!(f, "]")
}

fn fmt_slice<T: MessageType>(v: &[T], f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "[ ")?;
    for e in v.iter() {
        write!(f, "{}, ", WrappedObject(e.to_object_ref()))?;
    }
    write!(f, "]")
}

fn fmt_arr(arr: &WArray, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    write!(f, "arr: ")?;
    apply_to_warray_with!(arr, f, fmt_slice)
}

struct WrappedId<'a>(&'a Identifier);

impl std::fmt::Display for WrappedId<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Identifier::Client(bytes) => write!(f, "{}", String::from_utf8_lossy(bytes)),
            Identifier::Event(e) => write!(f, "{:?}", e),
        }
    }
}
