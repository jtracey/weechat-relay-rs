pub(crate) use weechat_relay_rs::apply_to_warray_with;
use weechat_relay_rs::basic_types::{Compression, PasswordHashAlgo, Pointer, PointerError};
use weechat_relay_rs::commands::{
    CommandType, CompletionCommand, Count, Countable, DesyncCommand, DynCommand, HandshakeCommand,
    HdataCommand, InfoCommand, InfolistCommand, InitCommand, InputCommand, NicklistCommand,
    PingCommand, PointerOrName, QuitCommand, StrArgument, SyncAllBuffers, SyncCommand,
    SyncSomeBuffers, TestCommand, WeechatError,
};
use weechat_relay_rs::messages::{
    GenericHdata, Identifier, MessageType, Object, ObjectRef, WArray, WHashtable, WInfo, WInfolist,
    WString,
};
use weechat_relay_rs::Connection;

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
    let mut connection = Connection { stream };

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

    if let Some(handshake) = cli.handshake {
        let handshake = handshake.unwrap_or_default();
        let command = parse_handshake_command(&handshake).unwrap().0.unwrap();
        let command = DynCommand { id: None, command };
        commands.push(command);
        responses += 1;
    }

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

        let (command, more_responses) = parse_command(&command_in);
        if let Some(command) = command {
            commands.push(command);
        }
        responses += more_responses;
    }
}

fn parse_command(input: &str) -> (Option<DynCommand>, u32) {
    let (id, input) = if let Some(stripped) = input.strip_prefix('(') {
        let (id, input) = stripped.split_once(')').unwrap();
        let id = StrArgument::new(id).unwrap().to_stringargument();
        (Some(id), input.trim_start())
    } else {
        (None, input)
    };
    let (command, args) = split_whitespace_once(input);
    let res: Result<(Option<Box<dyn CommandType>>, u32), InputError> = match command {
        "handshake" => parse_handshake_command(args),
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

fn split_whitespace_once(s: &str) -> (&str, &str) {
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

fn parse_handshake_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let args = args.split_whitespace();
    let mut password_hash_algo = vec![PasswordHashAlgo::Plain];

    fn parse_password_hash_algo(algo: &str) -> Result<PasswordHashAlgo, InputError> {
        match algo {
            "plain" => Ok(PasswordHashAlgo::Plain),
            "sha256" => Ok(PasswordHashAlgo::Sha256),
            "sha512" => Ok(PasswordHashAlgo::Sha512),
            "pbkdf2+sha256" => Ok(PasswordHashAlgo::Pbkdf2Sha256),
            "pbkdf2+sha512" => Ok(PasswordHashAlgo::Pbkdf2Sha512),
            _ => Err(InputError::InvalidKeyVal),
        }
    }

    for arg in args {
        let (key, val) = arg.split_once('=').ok_or(InputError::InvalidKeyVal)?;
        if key == "password_hash_algo" {
            password_hash_algo = val
                .split(':')
                .map(parse_password_hash_algo)
                .collect::<Result<Vec<_>, _>>()?;
        } else if key == "compression" {
            eprintln!("Compression is not (yet) supported. Ignoring flag.")
        } else {
            return Err(InputError::InvalidKeyVal);
        }
    }
    let handshake = HandshakeCommand::new(password_hash_algo, vec![Compression::Off]);
    Ok((Some(Box::new(handshake)), 1))
}

fn parse_init_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let init = InitCommand::new(
        Some(StrArgument::new(args)?.to_stringargument()),
        None,
        None,
    );
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
    let split: Vec<&str> = args.split_whitespace().collect();
    let (name, rpath) = split[0]
        .split_once(':')
        .ok_or(InputError::MissingArgument)?;
    let name = StrArgument::new(name)?.to_stringargument();
    let mut rpath = rpath
        .split('/')
        .map(parse_countable)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter();

    let pointer = rpath.next().ok_or(InputError::MissingArgument)?;
    let pointer = Countable {
        count: pointer.count,
        object: PointerOrName::Name(StrArgument::new(pointer.object)?.to_stringargument()),
    };

    let vars = rpath
        .map(|countable| {
            Ok(Countable {
                count: countable.count,
                object: StrArgument::new(countable.object)?.to_stringargument(),
            })
        })
        .collect::<Result<Vec<_>, InputError>>()?;

    let keys = if split.len() > 1 {
        split[1]
            .split(',')
            .map(|s| Ok(StrArgument::new(s)?.to_stringargument()))
            .collect::<Result<Vec<_>, InputError>>()?
    } else {
        vec![]
    };

    let hdata = HdataCommand::new(name, pointer, vars, keys);
    Ok((Some(Box::new(hdata)), 1))
}

fn parse_info_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let split: Vec<&str> = args.split_whitespace().collect();
    let arguments = if split.len() > 1 {
        split[1..]
            .iter()
            .map(|a| Ok(StrArgument::new(a)?.to_stringargument()))
            .collect::<Result<Vec<_>, InputError>>()?
    } else {
        vec![]
    };
    let info = InfoCommand::new(StrArgument::new(split[0])?.to_stringargument(), arguments);
    Ok((Some(Box::new(info)), 1))
}

fn parse_infolist_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let split: Vec<&str> = args.split_whitespace().collect();
    let pointer = if split.len() > 1 {
        Some(Pointer::new(split[1].as_bytes().to_vec())?)
    } else {
        None
    };
    let arguments = if split.len() > 2 {
        split[2..]
            .iter()
            .map(|a| Ok(StrArgument::new(a)?.to_stringargument()))
            .collect::<Result<Vec<_>, InputError>>()?
    } else {
        vec![]
    };
    let info = InfolistCommand::new(
        StrArgument::new(split[0])?.to_stringargument(),
        pointer,
        arguments,
    );
    Ok((Some(Box::new(info)), 1))
}

fn parse_nicklist_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let split: Vec<&str> = args.split_whitespace().collect();
    let buffer = if !split.is_empty() {
        Some(PointerOrName::Name(
            StrArgument::new(split[0])?.to_stringargument(),
        ))
    } else {
        None
    };
    let nicklist = NicklistCommand::new(buffer);
    Ok((Some(Box::new(nicklist)), 1))
}

fn parse_input_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let (buffer, data) = args.split_once(' ').ok_or(InputError::MissingArgument)?;
    let buffer = PointerOrName::Name(StrArgument::new(buffer)?.to_stringargument());
    let data = StrArgument::new(data.trim_start())?.to_stringargument();
    let input = InputCommand::new(buffer, data);
    Ok((Some(Box::new(input)), 0))
}

fn parse_completion_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let (buffer, args) = args.split_once(' ').ok_or(InputError::MissingArgument)?;
    let buffer = PointerOrName::Name(StrArgument::new(buffer)?.to_stringargument());
    let args = args.trim_start();

    let (position, data) = if let Some((position, args)) = args.split_once(' ') {
        (
            position,
            Some(StrArgument::new(args.trim_start())?.to_stringargument()),
        )
    } else {
        (args, None)
    };
    let position: i32 = position.parse()?;
    let position = if position.is_negative() {
        None
    } else {
        Some(position as u16)
    };

    let completion = CompletionCommand::new(buffer, position, data);
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
            .map(|s| {
                Ok(PointerOrName::Name(
                    StrArgument::new(s)?.to_stringargument(),
                ))
            })
            .collect::<Result<Vec<_>, InputError>>()?;
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
            .map(|s| {
                Ok(PointerOrName::Name(
                    StrArgument::new(s)?.to_stringargument(),
                ))
            })
            .collect::<Result<Vec<_>, InputError>>()?;
        DesyncCommand::SomeBuffers(buffers, options)
    };

    Ok((Some(Box::new(sync)), 0))
}

fn parse_test_command(_args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let test = TestCommand::default();
    Ok((Some(Box::new(test)), 1))
}

fn parse_ping_command(args: &str) -> Result<(Option<Box<dyn CommandType>>, u32), InputError> {
    let ping = PingCommand::new(StrArgument::new(args)?.to_stringargument());
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

impl<'a> std::fmt::Display for WrappedObject<'a> {
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
    let keys = htb.keys().to_ref_vec();
    let vals = htb.vals().to_ref_vec();
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

impl<'a> std::fmt::Display for WrappedId<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Identifier::Client(bytes) => write!(f, "{}", String::from_utf8_lossy(bytes)),
            Identifier::Event(e) => write!(f, "{:?}", e),
        }
    }
}
