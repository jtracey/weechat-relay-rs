pub use crate::basic_types::{Compression, PasswordHashAlgo, Pointer};
pub use crate::messages::{
    Event, GenericHdata, HdataValues, Identifier, InfolistItem, InfolistVariable, Message,
    MessageType, Object, ObjectType, WArray, WBuffer, WHashtable, WInfo, WInfolist, WString,
};

use nom::bytes::complete::{take, take_till};
use nom::combinator::{fail, rest};
use nom::error::{context, ContextError, ParseError};
use nom::number::complete::{be_i32, be_i8, be_u32, be_u8};
use nom::sequence::separated_pair;
use nom::IResult;
use nom::InputIter;
use nom::InputTakeAtPosition;
use nom::ParseTo;

use std::io::Read;
use std::net::TcpStream;

macro_rules! parser_for {
    (Chr) => {
        be_i8
    };
    (Int) => {
        be_i32
    };
    (Lon) => {
        parse_long
    };
    (Str) => {
        parse_string
    };
    (Buf) => {
        parse_wbuffer
    };
    (Ptr) => {
        parse_pointer
    };
    (Tim) => {
        parse_time
    };
    (Htb) => {
        parse_hashtable
    };
    (Hda) => {
        parse_hdata
    };
    (Inf) => {
        parse_info
    };
    (Inl) => {
        parse_infolist
    };
    (Arr) => {
        parse_array
    };
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ParseMessageError<E> {
    IO(std::io::Error),
    Parser(nom::Err<E>),
}

impl<E> From<std::io::Error> for ParseMessageError<E> {
    fn from(e: std::io::Error) -> Self {
        Self::IO(e)
    }
}

pub fn get_message(
    stream: &mut TcpStream,
) -> Result<Message, ParseMessageError<nom::error::Error<Vec<u8>>>> {
    let mut message_size = vec![0u8; 4];
    stream.read_exact(&mut message_size)?;
    let size_as_slice: &[u8] = &message_size;
    let res =
        be_u32::<_, _>(size_as_slice).map_err(|e: nom::Err<nom::error::Error<&[u8]>>| e.to_owned());
    let (i, message_size) = match res {
        Ok(m) => m,
        Err(e) => {
            return Err(ParseMessageError::Parser(e));
        }
    };
    debug_assert!(i.is_empty());

    let mut message = vec![0u8; message_size as usize - 4];
    stream.read_exact(&mut message)?;
    let message_as_slice: &[u8] = &message;
    let res = parse_message::<_, _>(message_as_slice)
        .map_err(|e: nom::Err<nom::error::Error<&[u8]>>| e.to_owned());
    let (i, message) = match res {
        Ok(m) => m,
        Err(e) => {
            return Err(ParseMessageError::Parser(e));
        }
    };
    debug_assert!(i.is_empty());
    Ok(message)
}

pub fn get_message_verbose_errors(
    stream: &mut TcpStream,
) -> Result<Message, ParseMessageError<nom::error::VerboseError<Vec<u8>>>> {
    let mut message_size = vec![0u8; 4];
    stream.read_exact(&mut message_size)?;
    let size_as_slice: &[u8] = &message_size;
    let res: Result<(_, _), nom::Err<nom::error::VerboseError<Vec<u8>>>> =
        be_u32::<_, _>(size_as_slice).map_err(|e: nom::Err<nom::error::VerboseError<&[u8]>>| {
            e.map(|e2| nom::error::VerboseError {
                errors: e2
                    .errors
                    .into_iter()
                    .map(|e3| (e3.0.to_owned(), e3.1))
                    .collect(),
            })
        });
    let (i, message_size) = match res {
        Ok(m) => m,
        Err(e) => {
            return Err(ParseMessageError::Parser(e));
        }
    };
    debug_assert!(i.is_empty());

    let mut message = vec![0u8; message_size as usize - 4];
    stream.read_exact(&mut message)?;
    let message_as_slice: &[u8] = &message;
    let res = parse_message::<_, _>(message_as_slice).map_err(
        |e: nom::Err<nom::error::VerboseError<&[u8]>>| {
            e.map(|e2| nom::error::VerboseError {
                errors: e2
                    .errors
                    .into_iter()
                    .map(|e3| (e3.0.to_owned(), e3.1))
                    .collect(),
            })
        },
    );
    let (i, message) = match res {
        Ok(m) => m,
        Err(e) => {
            return Err(ParseMessageError::Parser(e));
        }
    };
    debug_assert!(i.is_empty());
    Ok(message)
}

pub fn parse_message<I, E>(i: I) -> IResult<I, Message, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes
        + std::fmt::Debug
        + nom::InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: PartialEq<u8>,
{
    context("message", |i: I| {
        let (i, compression) = parse_compression(i)?;
        assert_eq!(
            compression,
            Compression::Off,
            "Only uncompressed data is supported"
        );

        let (i, id) = parse_identifier(i)?;

        let mut i = i;
        let mut objects = vec![];
        while i.input_len() > 0 {
            let message_type;
            (i, message_type) = parse_type(i)?;
            let object;
            (i, object) = object_parser(&message_type)(i)?;
            objects.push(object);
        }

        let message = Message::new(id, objects);
        Ok((i, message))
    })(i)
}

fn parse_compression<I, E>(i: I) -> IResult<I, Compression, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone + InputIter<Item = u8> + nom::InputLength + nom::Slice<std::ops::RangeFrom<usize>>,
{
    let (i, flag) = context("compression byte", be_u8)(i)?;
    match flag {
        0 => Ok((i, Compression::Off)),
        _ => context("compression unsupported", fail)(i), // FIXME
    }
}

fn parse_length<I, E>(i: I) -> IResult<I, Option<usize>, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake,
{
    context("length", |i| {
        let (i, length) = be_i32(i)?;
        match length {
            0.. => Ok((i, Some(length as usize))),
            -1 => Ok((i, None)),
            _ => fail(i),
        }
    })(i)
}

fn parse_buffer<I, E>(i: I) -> IResult<I, Option<I>, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake,
{
    context("buffer", |i| {
        let (i, length) = parse_length(i)?;
        if let Some(length) = length {
            let (i, ret) = take(length)(i)?;
            Ok((i, Some(ret)))
        } else {
            Ok((i, None))
        }
    })(i)
}

fn parse_wbuffer<I, E>(i: I) -> IResult<I, WBuffer, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes,
{
    context("wbuffer", |i: I| {
        let (i, buf) = parse_buffer(i)?;
        Ok((i, buf.map(|b| b.as_bytes().to_vec())))
    })(i)
}

fn parse_string<I, E>(i: I) -> IResult<I, WString, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes,
{
    context("string", |i: I| {
        let (i, buf) = parse_wbuffer(i)?;
        Ok((i, WString::new(buf)))
    })(i)
}

fn parse_identifier<I, E>(i: I) -> IResult<I, Identifier, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes,
{
    context("identifier", |i: I| {
        let (i, id) = parse_buffer(i)?;

        let Some(id) = id else {
            return Ok((i, Identifier::Client(vec![])));
        };
        let id = id.as_bytes();
        let id = if !id.is_empty() && id[0] == b'_' {
            match id {
                b"_buffer_opened" => Identifier::Event(Event::BufferOpened),
                b"_buffer_type_changed" => Identifier::Event(Event::BufferTypeChanged),
                b"_buffer_moved" => Identifier::Event(Event::BufferMoved),
                b"_buffer_merged" => Identifier::Event(Event::BufferMerged),
                b"_buffer_unmerged" => Identifier::Event(Event::BufferUnmerged),
                b"_buffer_hidden" => Identifier::Event(Event::BufferHidden),
                b"_buffer_unhidden" => Identifier::Event(Event::BufferUnhidden),
                b"_buffer_renamed" => Identifier::Event(Event::BufferRenamed),
                b"_buffer_title_changed" => Identifier::Event(Event::BufferTitleChanged),
                b"_buffer_localvar_added" => Identifier::Event(Event::BufferLocalvarAdded),
                b"_buffer_localvar_changed" => Identifier::Event(Event::BufferLocalvarChanged),
                b"_buffer_localvar_removed" => Identifier::Event(Event::BufferLocalvarRemoved),
                b"_buffer_closing" => Identifier::Event(Event::BufferClosing),
                b"_buffer_cleared" => Identifier::Event(Event::BufferCleared),
                b"_buffer_line_added" => Identifier::Event(Event::BufferLineAdded),
                b"_nicklist" => Identifier::Event(Event::Nicklist),
                b"_nicklist_diff" => Identifier::Event(Event::NicklistDiff),
                b"_pong" => Identifier::Event(Event::Pong),
                b"_upgrade" => Identifier::Event(Event::Upgrade),
                b"_upgrade_ended" => Identifier::Event(Event::UpgradeEnded),
                _ => {
                    eprintln!(
                        "weechat-relay-rs: Unrecognized reserved identifier\
                         (handling as client identifier): {}",
                        String::from_utf8_lossy(id)
                    );
                    Identifier::Client(id.to_vec())
                }
            }
        } else {
            Identifier::Client(id.to_vec())
        };
        Ok((i, id))
    })(i)
}

fn parse_type<I, E>(i: I) -> IResult<I, ObjectType, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone + InputIter + nom::InputTake + nom::InputLength + nom::AsBytes,
{
    context("identifier", |i: I| {
        let (i, type_bytes) = take(3usize)(i)?;
        let type_bytes = type_bytes.as_bytes();
        let message_type = match type_bytes {
            b"chr" => ObjectType::Chr,
            b"int" => ObjectType::Int,
            b"lon" => ObjectType::Lon,
            b"str" => ObjectType::Str,
            b"buf" => ObjectType::Buf,
            b"ptr" => ObjectType::Ptr,
            b"tim" => ObjectType::Tim,
            b"htb" => ObjectType::Htb,
            b"hda" => ObjectType::Hda,
            b"inf" => ObjectType::Inf,
            b"inl" => ObjectType::Inl,
            b"arr" => ObjectType::Arr,
            _ => return fail(i),
        };
        Ok((i, message_type))
    })(i)
}

// to ensure the type and parser match
macro_rules! object_parsers {
    ( $type:expr, $($possible_type:ident),* ) => {
        match $type {
            $(
                ObjectType::$possible_type => |i: I| -> IResult<I, Object, E> {
                    let (i, ret) = parser_for!($possible_type)(i)?;
                    Ok((i, ret.to_object()))
                },
            )*
        }
    };
}

fn object_parser<I, E>(object_type: &ObjectType) -> impl Fn(I) -> IResult<I, Object, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes
        + nom::InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: PartialEq<u8>,
{
    object_parsers!(
        object_type,
        Chr,
        Int,
        Lon,
        Str,
        Buf,
        Ptr,
        Tim,
        Htb,
        Hda,
        Inf,
        Inl,
        Arr
    )
}

fn parse_long<I, E>(i: I) -> IResult<I, i64, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes,
{
    context("long", |i: I| {
        let (i, len) = be_u8(i)?;
        let (i, buf) = take(len)(i)?;
        let int: Option<i64> = buf.as_bytes().parse_to();
        if let Some(int) = int {
            Ok((i, int))
        } else {
            fail(i)
        }
    })(i)
}

fn parse_pointer<I, E>(i: I) -> IResult<I, Pointer, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes,
{
    context("pointer", |i: I| {
        let (i, len) = be_u8(i)?;
        let (i, buf) = take(len)(i)?;
        let pointer = Pointer::new(buf.as_bytes().to_vec());
        let pointer = if let Ok(pointer) = pointer {
            pointer
        } else {
            return fail(i);
        };
        Ok((i, pointer))
    })(i)
}

fn parse_time<I, E>(i: I) -> IResult<I, u64, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes,
{
    context("time", |i: I| {
        let (i, len) = be_u8(i)?;
        let (i, buf) = take(len)(i)?;
        let int: Option<u64> = buf.as_bytes().parse_to();
        if let Some(tim) = int {
            Ok((i, tim))
        } else {
            fail(i)
        }
    })(i)
}

/*
=== Hashtable parsing ===

Hashtables end up being one of the harder things to parse, because they come as m copies of (a
priori unknown) two types, interleaved with each other. We lean on generics where we can, but
ultimately, we have to pass something back to a consumer who doesn't know those types, which means
an enum that somehow conveys |{ObjectType}|**2 possible variants. The consumer representation of
this is solved by being a struct with two members, each of which is a WArray (a vec of pairs may
seem more natural, but would require generics in the type, which again, we can't use; or enums,
which lose the type consistency). Here though, we still need to somehow call the correct generic
function, and force the result into this format. This means |{ObjectType}|**2 calls we need to match
against, which is... unwieldy. To make the best of it, we rely on macros that generate nested match
statements. For details, see the code itself.
*/

fn apply_hashtable_parsers<I, E, M, N>(
    i: I,
    key_parser: impl Fn(I) -> IResult<I, M, E>,
    val_parser: impl Fn(I) -> IResult<I, N, E>,
) -> IResult<I, Vec<(M, N)>, E>
where
    E: ParseError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>,
{
    let (i, count) = be_u32(i)?;
    let count = count as usize;
    nom::multi::count(
        |i| {
            let (i, key) = key_parser(i)?;
            let (i, val) = val_parser(i)?;
            Ok((i, (key, val)))
        },
        count,
    )(i)
}

fn pairs_to_hashtable<M, N>(pairs: Vec<(M, N)>) -> WHashtable
where
    M: MessageType + Clone,
    N: MessageType + Clone,
{
    let (left, right): (Vec<M>, Vec<N>) = pairs.into_iter().unzip();
    WHashtable {
        keys: MessageType::to_warray(left),
        vals: MessageType::to_warray(right),
    }
}

fn apply_and_gen_hashtable<J, M, N, E>(
    i: J,
    key_parser: impl Fn(J) -> IResult<J, M, E>,
    val_parser: impl Fn(J) -> IResult<J, N, E>,
) -> IResult<J, WHashtable, E>
where
    E: ParseError<J> + ContextError<J>,
    J: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>,
    M: MessageType + Clone,
    N: MessageType + Clone,
{
    let (i, pairs) = apply_hashtable_parsers(i, key_parser, val_parser)?;
    Ok((i, pairs_to_hashtable(pairs)))
}

macro_rules! parse_hashtable_match_val {
    ( $i:expr, $type_keys:ident, $type_vals:expr, $($possible_type:ident),* ) => {
        match $type_vals {
            $(
                ObjectType::$possible_type => apply_and_gen_hashtable(
                    $i, parser_for!($type_keys), parser_for!($possible_type)
                ),
            )*
        }
    };
}

macro_rules! parse_hashtable_match_key {
    ( $i:expr, $type_keys:expr, $type_vals:expr, $($possible_type:ident),* ) => {
        match $type_keys {
            $(
                ObjectType::$possible_type => parse_hashtable_match_val!(
                    $i, $possible_type, $type_vals,
                    Chr, Int, Lon, Str, Buf, Ptr, Tim, Htb, Hda, Inf, Inl, Arr
                ),
            )*
        }
    };
}

fn parse_hashtable<I, E>(i: I) -> IResult<I, WHashtable, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes
        + nom::InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: PartialEq<u8>,
{
    context("time", |i: I| {
        let (i, type_keys) = parse_type(i)?;
        let (i, type_vals) = parse_type(i)?;

        parse_hashtable_match_key!(
            i, type_keys, type_vals, Chr, Int, Lon, Str, Buf, Ptr, Tim, Htb, Hda, Inf, Inl, Arr
        )
    })(i)
}

macro_rules! parse_and_pusher {
    ( $i:expr, $warr:expr, $($possible_type:ident),* ) => {
        match $warr {
            $(
                WArray::$possible_type(v) => {
                    let (i, r) = parser_for!($possible_type)($i)?;
                    Ok((i, v.push(r)))
                },
            )*
        }
    };
}

fn parse_and_push<I, E>(i: I, a: &mut WArray) -> IResult<I, (), E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes
        + nom::InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: PartialEq<u8>,
{
    parse_and_pusher!(i, a, Chr, Int, Lon, Str, Buf, Ptr, Tim, Htb, Hda, Inf, Inl, Arr)
}

fn parse_hdata<I, E>(i: I) -> IResult<I, GenericHdata, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes
        + nom::InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: PartialEq<u8>,
{
    context("hdata", |i: I| {
        let (i, hpath) = parse_string(i)?;
        let (i, raw_keys) = parse_buffer(i)?;
        let (i, count) = be_u32(i)?;

        let path_depth = if let Some(ref hpath) = hpath.bytes() {
            hpath.iter().filter(|&b| *b == b'/').count() + 1
        } else {
            0
        };
        let key_pairs = if let Some(raw_keys) = raw_keys {
            nom::multi::separated_list0(take(1_usize), take_till(|c| c == b','))(raw_keys)?.1
        } else {
            vec![]
        };
        let count = count as usize;

        let mut key_data = key_pairs
            .into_iter()
            .map(separated_pair(
                take_till(|c| c == b':'),
                take(1_usize),
                rest,
            ))
            .map(|r| {
                r.and_then(|(_, (k, t))| {
                    let t = parse_type(t)?.1;
                    Ok((k, t.new_warray(count)))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut ppaths = Vec::with_capacity(count);
        let mut i = i;
        for _ in 0..count {
            let ppath;
            (i, ppath) = nom::multi::count(parse_pointer, path_depth)(i)?;
            ppaths.push(ppath);
            for k in key_data.iter_mut() {
                (i, _) = parse_and_push(i, &mut k.1)?;
            }
        }

        let set_values: Vec<_> = key_data
            .into_iter()
            .map(|(k, v)| HdataValues {
                key: k.as_bytes().to_vec(),
                values: v,
            })
            .collect();

        Ok((
            i,
            GenericHdata {
                hpath,
                ppaths,
                set_values,
            },
        ))
    })(i)
}

fn parse_info<I, E>(i: I) -> IResult<I, WInfo, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes,
{
    context("info", |i: I| {
        let (i, name) = parse_string(i)?;
        let (i, value) = parse_string(i)?;
        Ok((i, WInfo { name, value }))
    })(i)
}

fn parse_infolist_variable<I, E>(i: I) -> IResult<I, InfolistVariable, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes
        + nom::InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: PartialEq<u8>,
{
    context("infolist variable", |i: I| {
        let (i, name) = parse_string(i)?;
        let (i, value_type) = parse_type(i)?;
        let (i, value) = object_parser(&value_type)(i)?;
        Ok((i, InfolistVariable { name, value }))
    })(i)
}

fn parse_infolist_item<I, E>(i: I) -> IResult<I, InfolistItem, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes
        + nom::InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: PartialEq<u8>,
{
    context("infolist item", |i: I| {
        let (i, count) = be_u32(i)?;
        let count = count as usize;
        let (i, variables) = nom::multi::count(parse_infolist_variable, count)(i)?;
        Ok((i, InfolistItem { variables }))
    })(i)
}

fn parse_infolist<I, E>(i: I) -> IResult<I, WInfolist, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes
        + nom::InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: PartialEq<u8>,
{
    context("infolist", |i: I| {
        let (i, name) = parse_string(i)?;
        let (i, count) = be_u32(i)?;
        let count = count as usize;
        let (i, items) = nom::multi::count(parse_infolist_item, count)(i)?;
        Ok((i, WInfolist { name, items }))
    })(i)
}

fn parse_array_with<I, E, M>(i: I, parser: impl Fn(I) -> IResult<I, M, E>) -> IResult<I, WArray, E>
where
    E: ParseError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes,
    M: MessageType + Clone,
{
    let (i, count) = be_u32(i)?;
    let count = count as usize;
    let (i, res) = nom::multi::count(parser, count)(i)?;
    Ok((i, MessageType::to_warray(res)))
}

// to ensure the type and the parser match
macro_rules! parse_array_for {
    ( $i:expr, $type:expr, $($possible_type:ident),* ) => {
        match $type {
            $(
                ObjectType::$possible_type => parse_array_with($i, parser_for!($possible_type)),
            )*
        }
    };
}

fn parse_array<I, E>(i: I) -> IResult<I, WArray, E>
where
    E: ParseError<I> + ContextError<I>,
    I: Clone
        + PartialEq
        + InputIter<Item = u8>
        + nom::InputLength
        + nom::Slice<std::ops::RangeFrom<usize>>
        + nom::InputTake
        + nom::AsBytes
        + nom::InputTakeAtPosition,
    <I as InputTakeAtPosition>::Item: PartialEq<u8>,
{
    context("array", |i: I| {
        let (i, item_type) = parse_type(i)?;
        parse_array_for!(i, item_type, Chr, Int, Lon, Str, Buf, Ptr, Tim, Htb, Hda, Inf, Inl, Arr)
    })(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chr_parsing() {
        let bytes = [b'A'];
        let res: IResult<_, _> = parser_for!(Chr)(&bytes[..]);
        let c = res.unwrap().1;
        assert_eq!(c, b'A' as i8);
    }

    #[test]
    fn int_parsing() {
        let bytes = [0x00, 0x01, 0xE2, 0x40];
        let res: IResult<_, _> = parser_for!(Int)(&bytes[..]);
        let i = res.unwrap().1;
        assert_eq!(i, 123456);

        let bytes = [0xFF, 0xFE, 0x1D, 0xC0];
        let res: IResult<_, _> = parser_for!(Int)(&bytes[..]);
        let i = res.unwrap().1;
        assert_eq!(i, -123456);
    }

    #[test]
    fn lon_parsing() {
        let bytes = [
            0x0A, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
        ];
        let res: IResult<_, _> = parser_for!(Lon)(&bytes[..]);
        let i = res.unwrap().1;
        assert_eq!(i, 1234567890);

        let bytes = [
            0x0B, b'-', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0',
        ];
        let res: IResult<_, _> = parser_for!(Lon)(&bytes[..]);
        let i = res.unwrap().1;
        assert_eq!(i, -1234567890);
    }

    #[test]
    fn str_parsing() {
        let bytes = [0x00, 0x00, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let res: IResult<_, _> = parser_for!(Str)(&bytes[..]);
        let s = res.unwrap().1;
        assert_eq!(s, WString::new(Some(b"hello".to_vec())));

        let bytes = [0x00, 0x00, 0x00, 0x00];
        let res: IResult<_, _> = parser_for!(Str)(&bytes[..]);
        let s = res.unwrap().1;
        assert_eq!(s, WString::new(Some(b"".to_vec())));

        let bytes = [0xFF, 0xFF, 0xFF, 0xFF];
        let res: IResult<_, _> = parser_for!(Str)(&bytes[..]);
        let s = res.unwrap().1;
        assert_eq!(s, WString::new(None));
    }

    #[test]
    fn buf_parsing() {
        let bytes = [0x00, 0x00, 0x00, 0x06, b'b', b'u', b'f', b'f', b'e', b'r'];
        let res: IResult<_, _> = parser_for!(Buf)(&bytes[..]);
        let b = res.unwrap().1;
        assert_eq!(b, Some(b"buffer".to_vec()));

        let bytes = [0xFF, 0xFF, 0xFF, 0xFF];
        let res: IResult<_, _> = parser_for!(Buf)(&bytes[..]);
        let b = res.unwrap().1;
        assert_eq!(b, None);
    }

    #[test]
    fn ptr_parsing() {
        let bytes = [0x09, b'1', b'a', b'2', b'b', b'3', b'c', b'4', b'd', b'5'];
        let res: IResult<_, _> = parser_for!(Ptr)(&bytes[..]);
        let p = res.unwrap().1;
        assert_eq!(p, Pointer::new(b"1a2b3c4d5".to_vec()).unwrap());

        let bytes = [0x01, b'0'];
        let res: IResult<_, _> = parser_for!(Ptr)(&bytes[..]);
        let p = res.unwrap().1;
        assert_eq!(p, Pointer::new(b"0".to_vec()).unwrap());
    }

    #[test]
    fn tim_parsing() {
        let bytes = [
            0x0A, b'1', b'3', b'2', b'1', b'9', b'9', b'3', b'4', b'5', b'6',
        ];
        let res: IResult<_, _> = parser_for!(Tim)(&bytes[..]);
        let t = res.unwrap().1;
        assert_eq!(t, 1321993456);
    }

    #[test]
    fn arr_parsing() {
        let bytes = [
            b's', b't', b'r', // array type
            0x00, 0x00, 0x00, 0x02, // array length
            0x00, 0x00, 0x00, 0x03, b'a', b'b', b'c', // element 1
            0x00, 0x00, 0x00, 0x02, b'd', b'e', // element 2
        ];
        let res: IResult<_, _> = parser_for!(Arr)(&bytes[..]);
        let a = res.unwrap().1;
        assert_eq!(
            a,
            WArray::Str(vec![
                WString::new(Some(b"abc".to_vec())),
                WString::new(Some(b"de".to_vec()))
            ])
        );

        let bytes = [
            b'i', b'n', b't', 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x7B, 0x00, 0x00, 0x01,
            0xC8, 0x00, 0x00, 0x03, 0x15,
        ];
        let res: IResult<_, _> = parser_for!(Arr)(&bytes[..]);
        let a = res.unwrap().1;
        assert_eq!(a, WArray::Int(vec![123, 456, 789]));

        let bytes = [b's', b't', b'r', 0x00, 0x00, 0x00, 0x00];
        let res: IResult<_, _> = parser_for!(Arr)(&bytes[..]);
        let a = res.unwrap().1;
        assert_eq!(a, WArray::Str(vec![]));
    }

    #[test]
    fn hashtable_parsing() {
        let bytes = [
            b's', b't', b'r', // key type
            b's', b't', b'r', // val type
            0x00, 0x00, 0x00, 0x02, // number of key-val pairs
            0x00, 0x00, 0x00, 0x04, b'k', b'e', b'y', b'1', // key 1
            0x00, 0x00, 0x00, 0x03, b'a', b'b', b'c', // val 1
            0x00, 0x00, 0x00, 0x04, b'k', b'e', b'y', b'2', // key 2
            0x00, 0x00, 0x00, 0x03, b'd', b'e', b'f', // val 2
        ];
        let res: IResult<_, _> = parser_for!(Htb)(&bytes[..]);
        let h = res.unwrap().1;
        assert_eq!(
            h,
            WHashtable {
                keys: WArray::Str(vec![
                    WString::new(Some(b"key1".to_vec())),
                    WString::new(Some(b"key2".to_vec()))
                ]),
                vals: WArray::Str(vec![
                    WString::new(Some(b"abc".to_vec())),
                    WString::new(Some(b"def".to_vec()))
                ])
            }
        );
    }

    #[test]
    fn hdata_parsing() {
        let bytes = [
            0x00, 0x00, 0x00, 0x06, // h-path length
            b'b', b'u', b'f', b'f', b'e', b'r', // h-path
            0x00, 0x00, 0x00, 0x18, // full keys length
            b'n', b'u', b'm', b'b', b'e', b'r', b':', // key1 name
            b'i', b'n', b't', b',', // key1 type
            b'f', b'u', b'l', b'l', b'_', b'n', b'a', b'm', b'e', b':', // key2 name
            b's', b't', b'r', // key2 type
            0x00, 0x00, 0x00, 0x02, // count
            0x05, b'1', b'2', b'3', b'4', b'5', // p-path 1
            0x00, 0x00, 0x00, 0x01, // buffer 1 val 1
            0x00, 0x00, 0x00, 0x0C, // buffer 1 val 2 length
            b'c', b'o', b'r', b'e', b'.', b'w', b'e', b'e', b'c', b'h', b'a', b't', 0x05, b'6',
            b'7', b'8', b'9', b'a', // p-path 2
            0x00, 0x00, 0x00, 0x02, // buffer 2 val 1
            0x00, 0x00, 0x00, 0x11, // buffer 2 val 2 length
            b'i', b'r', b'c', b'.', b's', b'e', b'r', b'v', b'e', b'r', b'.', b'l', b'i', b'b',
            b'e', b'r', b'a', // buffer 2 val 2
        ];
        let res: IResult<_, _> = parser_for!(Hda)(&bytes[..]);
        let h = res.unwrap().1;
        assert_eq!(
            h,
            GenericHdata {
                hpath: WString::new(Some(b"buffer".to_vec())),
                ppaths: vec![
                    vec![Pointer::new(b"12345".to_vec()).unwrap()],
                    vec![Pointer::new(b"6789a".to_vec()).unwrap()]
                ],
                set_values: vec![
                    HdataValues {
                        key: b"number".to_vec(),
                        values: WArray::Int(vec![1, 2])
                    },
                    HdataValues {
                        key: b"full_name".to_vec(),
                        values: WArray::Str(vec![
                            WString::new(Some(b"core.weechat".to_vec())),
                            WString::new(Some(b"irc.server.libera".to_vec()))
                        ])
                    }
                ]
            }
        );

        // FIXME: there are two more complicated hdatas in the proto docs to test

        let bytes = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        ];
        let res: IResult<_, _> = parser_for!(Hda)(&bytes[..]);
        let h = res.unwrap().1;
        assert_eq!(
            h,
            GenericHdata {
                hpath: WString::new(None),
                ppaths: vec![],
                set_values: vec![]
            }
        );
    }

    #[test]
    fn info_parsing() {
        let bytes = [
            0x00, 0x00, 0x00, 0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n', // name
            0x00, 0x00, 0x00, 0x11, b'W', b'e', b'e', b'C', b'h', b'a', b't', b' ', b'0', b'.',
            b'3', b'.', b'7', b'-', b'd', b'e', b'v', //value
        ];
        let res: IResult<_, _> = parser_for!(Inf)(&bytes[..]);
        let i = res.unwrap().1;
        assert_eq!(
            i,
            WInfo {
                name: WString::new(Some(b"version".to_vec())),
                value: WString::new(Some(b"WeeChat 0.3.7-dev".to_vec()))
            }
        )
    }

    #[test]
    fn infolist_parsing() {
        let bytes = [
            0x00, 0x00, 0x00, 0x06, b'b', b'u', b'f', b'f', b'e', b'r', // name
            0x00, 0x00, 0x00, 0x02, // count
            0x00, 0x00, 0x00, 0x01, // item 1 count
            0x00, 0x00, 0x00, 0x07, b'p', b'o', b'i', b'n', b't', b'e',
            b'r', // item 1 val 1 name
            b'p', b't', b'r', // item 1 val 1 type
            0x05, b'1', b'2', b'3', b'4', b'5', // item 1 val 1
            0x00, 0x00, 0x00, 0x01, // item 2 count
            0x00, 0x00, 0x00, 0x07, b'p', b'o', b'i', b'n', b't', b'e',
            b'r', // item 2 val 1 name
            b'p', b't', b'r', // item 2 val 1 type
            0x05, b'6', b'7', b'8', b'9', b'a', // item 2 val 1
        ];
        let res: IResult<_, _> = parser_for!(Inl)(&bytes[..]);
        let i = res.unwrap().1;
        assert_eq!(
            i,
            WInfolist {
                name: WString::new(Some(b"buffer".to_vec())),
                items: vec![
                    InfolistItem {
                        variables: vec![InfolistVariable {
                            name: WString::new(Some(b"pointer".to_vec())),
                            value: Pointer::new(b"12345".to_vec()).unwrap().to_object(),
                        }]
                    },
                    InfolistItem {
                        variables: vec![InfolistVariable {
                            name: WString::new(Some(b"pointer".to_vec())),
                            value: Pointer::new(b"6789a".to_vec()).unwrap().to_object(),
                        }]
                    },
                ]
            }
        );
    }

    #[test]
    fn compression_parsing() {
        let bytes = [0_u8];
        let res: IResult<_, _> = parse_compression(&bytes[..]);
        let c = res.unwrap().1;
        assert_eq!(c, Compression::Off);
    }

    #[test]
    fn identifier_parsing() {
        let bytes = [0x00, 0x00, 0x00, 0x03, b'f', b'o', b'o'];
        let res: IResult<_, _> = parse_identifier(&bytes[..]);
        let i = res.unwrap().1;
        assert_eq!(i, Identifier::Client(b"foo".to_vec()));

        let bytes = [0x00, 0x00, 0x00, 0x05, b'_', b'p', b'o', b'n', b'g'];
        let res: IResult<_, _> = parse_identifier(&bytes[..]);
        let i = res.unwrap().1;
        assert_eq!(i, Identifier::Event(Event::Pong));
    }

    #[test]
    fn message_parsing() {
        let bytes = [
            0x00, // compression
            0x00, 0x00, 0x00, 0x00, // id length
            b'c', b'h', b'r', // type 1
            0xFF, // object 1
            b'i', b'n', b't', // type 2
            0x01, 0x03, 0x01, 0x02, // object 2
        ];
        let res: IResult<_, _> = parse_message(&bytes[..]);
        let m = res.unwrap().1;
        assert_eq!(
            m,
            Message::new(
                Identifier::Client(b"".to_vec()),
                vec![Object::Chr(-1), Object::Int(0x01030102)]
            )
        );
    }
}
