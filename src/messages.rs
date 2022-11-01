pub use crate::basic_types::{Compression, PasswordHashAlgo, Pointer};
use std::collections::HashMap;

/// A message recieved from WeeChat.
#[derive(Debug, PartialEq, Eq)]
pub struct Message {
    pub id: Identifier,
    pub objects: Vec<Object>,
}

impl Message {
    /// Constructor for a new `Message`. You are unlikely to need to call this directly, typically a message is created via parser.
    pub fn new(id: Identifier, objects: Vec<Object>) -> Self {
        Self { id, objects }
    }
}

/// Any type that can be an object in a message.
pub trait MessageType {
    fn to_object(self) -> Object;
    fn to_object_ref(&self) -> ObjectRef;
    fn to_warray(vec: Vec<Self>) -> WArray
    where
        Self: Sized;
}

/// A WeeChat [Char](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_char).
/// Note that WeeChat Char types are signed.
pub type WChar = i8;
/// A WeeChat [Integer](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_integer).
pub type WInteger = i32;
/// A WeeChat [Long integer](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_long_integer).
pub type WLongInteger = i64;
/// A WeeChat [String](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_string).
///
/// This type would be identical to the [WBuffer] type, except that it is intended to be a human-readable string.
/// It is not just a Rust String because there is no way, at the protocol level, to know what the encoding of the string is (it is the job of the application to know this).
///  The `None` variant represents a `NULL` string.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct WString {
    bytes: Option<Vec<u8>>,
}

impl WString {
    pub fn new(bytes: Option<Vec<u8>>) -> Self {
        Self { bytes }
    }

    /// Get the bytes representing this string.
    pub fn bytes(&self) -> &Option<Vec<u8>> {
        &self.bytes
    }
}

/// A WeeChat [Buffer](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_buffer).
///  The `None` variant represents a `NULL` buffer.
pub type WBuffer = Option<Vec<u8>>;
/// A WeeChat [Time](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_time) (i.e., number of seconds).
pub type WTime = u64;

/** A WeeChat [Hashtable](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_hashtable).

  Why is this not just a HashMap?
While we do provide a [function to create a true HashMap](to_hashmap) from this object, we do not use one by
default because the spec is underspecified as to how valid such a transformation is. Namely, the
spec does not detail whether it is valid for a hashtable to contain multiple instances of the same
key, or whether ordering is/can be significant. While the answer is almost certainly "keys cannot
be duplicated and ordering is not significant", as is the case in Rust's HashMap (so you probably
almost always want to convert this immediately), it's possible that custom extensions could violate
these assumptions without violating the spec, so we opt to defer to the safer interpretation.
*/
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct WHashtable {
    keys: WArray,
    vals: WArray,
}

impl WHashtable {
    pub fn new(keys: WArray, vals: WArray) -> Self {
        debug_assert_eq!(keys.len(), vals.len());
        Self { keys, vals }
    }

    pub fn keys(&self) -> &WArray {
        &self.keys
    }

    pub fn vals(&self) -> &WArray {
        &self.vals
    }
}

/// A generic WeeChat [Hdata](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_hdata).
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct GenericHdata {
    pub hpath: WString, // FIXME: this should prolly be some kind of "path" type
    pub ppaths: Vec<Vec<Pointer>>,
    // in order to preserve type information better, we represent sets "column-wise"
    // (i.e., the n'th HdataValues represents the n'th values of each set),
    // as opposed to the "row-wise" order they are sent in (set1, set2, etc.)
    pub set_values: Vec<HdataValues>,
}

impl GenericHdata {
    /// Returns a Vec of the object sets in the Hdata.
    ///
    /// This renders some of the type consistency inaccessible to the compiler,
    /// so only use this in more general cases, where you're not actually doing
    /// anything with the particular Hdata.
    pub fn sets(&self) -> Vec<HashMap<&Vec<u8>, ObjectRef>> {
        let mut ret = vec![HashMap::new(); self.set_values[0].values.len()];
        for hdata_values in self.set_values.iter() {
            let values = hdata_values.values.to_ref_vec();
            for (i, v) in values.into_iter().enumerate() {
                ret[i].insert(&hdata_values.key, v);
            }
        }
        ret
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct HdataValues {
    pub key: Vec<u8>,
    pub values: WArray,
}

/// A WeeChat [Info](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_info).
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct WInfo {
    pub name: WString,
    pub value: WString,
}

/// A WeeChat [Infolist](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_infolist).
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct WInfolist {
    pub name: WString,
    pub items: Vec<InfolistItem>,
}

/// An [Infolist](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_infolist) item---an element of an Infolist.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct InfolistItem {
    pub variables: Vec<InfolistVariable>,
}

/// An [Infolist](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_infolist) variable---an element of an Infolist item.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct InfolistVariable {
    pub name: WString,
    pub value: Object,
}

impl MessageType for WChar {
    fn to_object(self) -> Object {
        Object::Chr(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Chr(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Chr(vec)
    }
}
impl MessageType for WInteger {
    fn to_object(self) -> Object {
        Object::Int(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Int(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Int(vec)
    }
}
impl MessageType for WLongInteger {
    fn to_object(self) -> Object {
        Object::Lon(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Lon(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Lon(vec)
    }
}
impl MessageType for WString {
    fn to_object(self) -> Object {
        Object::Str(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Str(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Str(vec)
    }
}
impl MessageType for WBuffer {
    fn to_object(self) -> Object {
        Object::Buf(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Buf(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Buf(vec)
    }
}
impl MessageType for Pointer {
    fn to_object(self) -> Object {
        Object::Ptr(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Ptr(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Ptr(vec)
    }
}
impl MessageType for WTime {
    fn to_object(self) -> Object {
        Object::Tim(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Tim(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Tim(vec)
    }
}
impl MessageType for WHashtable {
    fn to_object(self) -> Object {
        Object::Htb(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Htb(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Htb(vec)
    }
}
impl MessageType for GenericHdata {
    fn to_object(self) -> Object {
        Object::Hda(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Hda(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Hda(vec)
    }
}
impl MessageType for WInfo {
    fn to_object(self) -> Object {
        Object::Inf(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Inf(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Inf(vec)
    }
}
impl MessageType for WInfolist {
    fn to_object(self) -> Object {
        Object::Inl(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Inl(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Inl(vec)
    }
}
impl MessageType for WArray {
    fn to_object(self) -> Object {
        Object::Arr(self)
    }
    fn to_object_ref(&self) -> ObjectRef {
        ObjectRef::Arr(self)
    }
    fn to_warray(vec: Vec<Self>) -> WArray {
        WArray::Arr(vec)
    }
}

/// A WeeChat [identifier](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#message_identifier).
#[derive(Debug, PartialEq, Eq)]
pub enum Identifier {
    Client(Vec<u8>),
    Event(Event),
}

/// A WeeChat [event](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#message_identifier)---i.e., a reserved identifier.
#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    BufferOpened,
    BufferTypeChanged,
    BufferMoved,
    BufferMerged,
    BufferUnmerged,
    BufferHidden,
    BufferUnhidden,
    BufferRenamed,
    BufferTitleChanged,
    BufferLocalvarAdded,
    BufferLocalvarChanged,
    BufferLocalvarRemoved,
    BufferClosing,
    BufferCleared,
    BufferLineAdded,
    Nicklist,
    NicklistDiff,
    Pong,
    Upgrade,
    UpgradeEnded,
}

/// The possible object types (but not the objects themselves).
#[derive(Clone, Copy)]
pub enum ObjectType {
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
    Arr,
}

impl ObjectType {
    pub fn new_warray(&self, capacity: usize) -> WArray {
        match self {
            Self::Chr => WArray::Chr(Vec::with_capacity(capacity)),
            Self::Int => WArray::Int(Vec::with_capacity(capacity)),
            Self::Lon => WArray::Lon(Vec::with_capacity(capacity)),
            Self::Str => WArray::Str(Vec::with_capacity(capacity)),
            Self::Buf => WArray::Buf(Vec::with_capacity(capacity)),
            Self::Ptr => WArray::Ptr(Vec::with_capacity(capacity)),
            Self::Tim => WArray::Tim(Vec::with_capacity(capacity)),
            Self::Htb => WArray::Htb(Vec::with_capacity(capacity)),
            Self::Hda => WArray::Hda(Vec::with_capacity(capacity)),
            Self::Inf => WArray::Inf(Vec::with_capacity(capacity)),
            Self::Inl => WArray::Inl(Vec::with_capacity(capacity)),
            Self::Arr => WArray::Arr(Vec::with_capacity(capacity)),
        }
    }
}

/// One of the valid WeeChat [Objects](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#objects).
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Object {
    Chr(WChar),
    Int(WInteger),
    Lon(WLongInteger),
    Str(WString),
    Buf(WBuffer),
    Ptr(Pointer),
    Tim(WTime),
    Htb(WHashtable),
    Hda(GenericHdata),
    Inf(WInfo),
    Inl(WInfolist),
    Arr(WArray),
    // ^ WArrays look a lot like this enum, but are Vecs over the possible types,
    // to better preserve the type information than a Vec<Object> would be able
}

impl Object {
    fn vec_to_object_vec<T: MessageType>(v: Vec<T>) -> Vec<Self> {
        v.into_iter().map(|o: T| o.to_object()).collect()
    }

    pub fn object_ref(&self) -> ObjectRef {
        match self {
            Self::Chr(v) => ObjectRef::Chr(v),
            Self::Int(v) => ObjectRef::Int(v),
            Self::Lon(v) => ObjectRef::Lon(v),
            Self::Str(v) => ObjectRef::Str(v),
            Self::Buf(v) => ObjectRef::Buf(v),
            Self::Ptr(v) => ObjectRef::Ptr(v),
            Self::Tim(v) => ObjectRef::Tim(v),
            Self::Htb(v) => ObjectRef::Htb(v),
            Self::Hda(v) => ObjectRef::Hda(v),
            Self::Inf(v) => ObjectRef::Inf(v),
            Self::Inl(v) => ObjectRef::Inl(v),
            Self::Arr(v) => ObjectRef::Arr(v),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum ObjectRef<'a> {
    Chr(&'a WChar),
    Int(&'a WInteger),
    Lon(&'a WLongInteger),
    Str(&'a WString),
    Buf(&'a WBuffer),
    Ptr(&'a Pointer),
    Tim(&'a WTime),
    Htb(&'a WHashtable),
    Hda(&'a GenericHdata),
    Inf(&'a WInfo),
    Inl(&'a WInfolist),
    Arr(&'a WArray),
}

impl<'a> ObjectRef<'a> {
    fn vec_to_object_ref_vec<T: MessageType + 'a>(v: &'a [T]) -> Vec<Self> {
        v.iter().map(|o: &T| o.to_object_ref()).collect()
    }
}

/// A WeeChat [Array](https://weechat.org/files/doc/devel/weechat_relay_protocol.en.html#object_array)---a vec of a single WeeChat type.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum WArray {
    Chr(Vec<WChar>),
    Int(Vec<WInteger>),
    Lon(Vec<WLongInteger>),
    Str(Vec<WString>),
    Buf(Vec<WBuffer>),
    Ptr(Vec<Pointer>),
    Tim(Vec<WTime>),
    Htb(Vec<WHashtable>),
    Hda(Vec<GenericHdata>),
    Inf(Vec<WInfo>),
    Inl(Vec<WInfolist>),
    Arr(Vec<WArray>),
}

/// Apply an expression to any variant of a [WArray].
///
/// Each variant of a WArray holds a different type, so there is no way to generically apply an identical expression to all variants.
/// However, sometimes we don't care about the type, and just want to apply an expression with the same syntax and analagous semantics regardless (e.g., we want to know the length).
/// This macro does just that.
/// This obviously means the expression must resolve to valid code when called on any of the particular types.
/// The expression is applied as a function call.
///
/// E.g., `len` is defined as
/// `
/// pub fn len(&self) -> usize {
///     apply_to_warray!(self, Vec::len)
/// }
/// `
#[macro_export]
macro_rules! apply_to_warray {
    ( $warray:expr, $function:expr ) => {
        match $warray {
            WArray::Chr(v) => $function(v),
            WArray::Int(v) => $function(v),
            WArray::Lon(v) => $function(v),
            WArray::Str(v) => $function(v),
            WArray::Buf(v) => $function(v),
            WArray::Ptr(v) => $function(v),
            WArray::Tim(v) => $function(v),
            WArray::Htb(v) => $function(v),
            WArray::Hda(v) => $function(v),
            WArray::Inf(v) => $function(v),
            WArray::Inl(v) => $function(v),
            WArray::Arr(v) => $function(v),
        }
    };
}

/// Apply an expression to any variant of a [WArray], with auxilliary data.
///
/// This is the same as [apply_to_warray], but with the second argument given as the second argument to the function call.
#[macro_export]
macro_rules! apply_to_warray_with {
    ( $warray:expr, $data:expr, $function:expr ) => {
        match $warray {
            WArray::Chr(v) => $function(v, $data),
            WArray::Int(v) => $function(v, $data),
            WArray::Lon(v) => $function(v, $data),
            WArray::Str(v) => $function(v, $data),
            WArray::Buf(v) => $function(v, $data),
            WArray::Ptr(v) => $function(v, $data),
            WArray::Tim(v) => $function(v, $data),
            WArray::Htb(v) => $function(v, $data),
            WArray::Hda(v) => $function(v, $data),
            WArray::Inf(v) => $function(v, $data),
            WArray::Inl(v) => $function(v, $data),
            WArray::Arr(v) => $function(v, $data),
        }
    };
}

impl WArray {
    pub fn len(&self) -> usize {
        apply_to_warray!(self, Vec::len)
    }

    pub fn is_empty(&self) -> bool {
        apply_to_warray!(self, Vec::is_empty)
    }

    pub fn to_vec(self) -> Vec<Object> {
        apply_to_warray!(self, Object::vec_to_object_vec)
    }

    pub fn to_ref_vec(&self) -> Vec<ObjectRef> {
        apply_to_warray!(self, ObjectRef::vec_to_object_ref_vec)
    }
}

/// For converting a WHashtable into a HashMap
pub fn to_hashmap<K, V>(keys: Vec<K>, vals: Vec<V>) -> HashMap<K, V>
where
    K: Eq + std::hash::Hash,
{
    keys.into_iter()
        .zip(vals.into_iter())
        .collect::<HashMap<K, V>>()
}
