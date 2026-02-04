use std::borrow::Cow;
use std::ops::{AddAssign, MulAssign};

use serde::{de, Deserialize};
use serde::de::IntoDeserializer;
use crate::Tag;

// TODO: revert Iterator<Item=XmlRes> to this if trait_alias stabilizes
// pub trait XMLIter = Iterator<Item=xml::reader::Result<xml::reader::XmlEvent>>;
type XmlRes = xml::reader::Result<xml::reader::XmlEvent>;

pub struct Deserializer<I: Iterator<Item=XmlRes>> {
    reader: itertools::MultiPeek<I>,
    depth: u64,
    is_map_value: bool,
    is_seq_value: bool,
    is_greedy: bool,
    is_value: bool,
    reset_peek_offset: u64,
}

fn new_reader<I: IntoIterator<Item=XmlRes>>(iter: I) -> itertools::MultiPeek<impl Iterator<Item=XmlRes>> {
    itertools::multipeek(Box::new(iter.into_iter().filter(|e| match e {
        &Ok(xml::reader::XmlEvent::ProcessingInstruction { ..}) => {
            trace!("discarding processing instruction: {:?}", e.as_ref().unwrap());
            false
        },
        _ => true,
    })))
}

pub fn from_str<'a, T: Deserialize<'a>>(s: &'a str) -> crate::Result<T> {
    let conf = xml::ParserConfig::new()
        .trim_whitespace(true)
        .whitespace_to_characters(true)
        .replace_unknown_entity_references(true);
    let mut event_reader = xml::reader::EventReader::new_with_config(s.as_bytes(), conf);
    match event_reader.next()? {
        xml::reader::XmlEvent::StartDocument {
            version,
            encoding,
            standalone
        } => {
            trace!("start_document({:?}, {:?}, {:?})", version, encoding, standalone);
        }
        o => {
            trace!("unknown_start({:?})", o);
            return Err(crate::Error::ExpectedElement)
        }
    }
    let mut deserializer = Deserializer {
        reader: new_reader(event_reader),
        depth: 0,
        is_map_value: false,
        is_seq_value: false,
        is_greedy: true,
        is_value: false,
        reset_peek_offset: 0,
    };
    let t = T::deserialize(&mut deserializer)?;
    Ok(t)
}

pub fn from_string<'a, T: Deserialize<'a>>(s: String) -> crate::Result<T> {
    let conf = xml::ParserConfig::new()
        .trim_whitespace(true)
        .whitespace_to_characters(true)
        .replace_unknown_entity_references(true);
    let mut event_reader = xml::reader::EventReader::new_with_config(s.as_bytes(), conf);
    match event_reader.next()? {
        xml::reader::XmlEvent::StartDocument {
            version,
            encoding,
            standalone
        } => {
            trace!("start_document({:?}, {:?}, {:?})", version, encoding, standalone);
        }
        _ => return Err(crate::Error::ExpectedElement)
    }
    let mut deserializer = Deserializer {
        reader: new_reader(event_reader),
        depth: 0,
        is_map_value: false,
        is_seq_value: false,
        is_greedy: true,
        is_value: false,
        reset_peek_offset: 0,
    };
    let t = T::deserialize(&mut deserializer)?;
    Ok(t)
}

pub fn from_events<'a, T: Deserialize<'a>>(s: &[xml::reader::Result<xml::reader::XmlEvent>]) -> crate::Result<T> {
    let mut reader = new_reader(s.into_iter().map(|r| r.to_owned()));
    if let Ok(xml::reader::XmlEvent::StartDocument { .. }) = reader.peek().ok_or(crate::Error::ExpectedElement)? {
        match reader.next() {
            Some(Ok(xml::reader::XmlEvent::StartDocument {
                     version,
                     encoding,
                     standalone
                 })) => {
                trace!("start_document({:?}, {:?}, {:?})", version, encoding, standalone);
            }
            _ => unreachable!()
        }
    }
    reader.reset_peek();
    let mut deserializer = Deserializer {
        reader,
        depth: 0,
        is_map_value: false,
        is_seq_value: false,
        is_greedy: true,
        is_value: false,
        reset_peek_offset: 0,
    };
    let t = T::deserialize(&mut deserializer)?;
    Ok(t)
}

impl<I: Iterator<Item=XmlRes>> Deserializer<I> {
    fn set_map_value(&mut self) {
        trace!("set_map_value()");
        self.is_map_value = true;
    }

    pub fn unset_map_value(&mut self) -> bool {
        trace!("unset_map_value()");
        self.is_value = false;
        std::mem::replace(&mut self.is_map_value, false)
    }

    fn set_seq_value(&mut self) {
        trace!("set_seq_value()");
        self.is_seq_value = true;
    }

    pub fn unset_seq_value(&mut self) -> bool {
        trace!("unset_seq_value()");
        std::mem::replace(&mut self.is_seq_value, false)
    }

    fn set_is_value(&mut self) {
        trace!("set_is_value()");
        self.is_value = true;
    }

    pub fn unset_is_value(&mut self) -> bool {
        trace!("unset_is_value()");
        std::mem::replace(&mut self.is_value, false)
    }

    fn set_not_greedy(&mut self) {
        trace!("set_not_greedy()");
        self.is_greedy = false;
    }

    pub fn unset_not_greedy(&mut self) -> bool {
        trace!("unset_not_greedy()");
        self.reset_peek_offset = 0;
        std::mem::replace(&mut self.is_greedy, true)
    }

    fn peek(&mut self) -> crate::Result<&xml::reader::XmlEvent> {
        let next = match match self.reader.peek() {
            Some(n) => n,
            None => return Ok(&xml::reader::XmlEvent::EndDocument)
        } {
            Ok(n) => n,
            Err(e) => return Err(e.into())
        };
        trace!("peek() -> {:?}", next);
        Ok(next)
    }

    fn reset_peek(&mut self) {
        trace!("reset_peek()");
        self.reader.reset_peek();
        for _ in 0..self.reset_peek_offset {
            self.reader.peek();
        }
    }

    fn next(&mut self) -> crate::Result<xml::reader::XmlEvent> {
        let next = match self.reader.next() {
            Some(n) => n,
            None => return Err(crate::Error::ExpectedElement)
        }?;
        match next {
            xml::reader::XmlEvent::StartElement { .. } => {
                self.depth += 1;
            }
            xml::reader::XmlEvent::EndElement { .. } => {
                self.depth -= 1;
            }
            _ => {}
        }
        trace!("next() -> {:?}; depth = {}", next, self.depth);
        Ok(next)
    }

    fn read_inner_value<T, F: FnOnce(&mut Self) -> crate::Result<T>>(&mut self, f: F) -> crate::Result<T> {
        trace!("read_inner_value()");
        let old_greedy = self.is_greedy;
        let ret = if self.unset_map_value() {
            match self.next()? {
                xml::reader::XmlEvent::StartElement { name, .. } => {
                    let result = f(self)?;
                    self.expect_end_element(name)?;
                    Ok(result)
                }
                _ => Err(crate::Error::ExpectedElement)
            }
        } else {
            f(self)
        };
        self.is_greedy = old_greedy;
        ret
    }

    fn read_inner_value_attrs<T, F: FnOnce(&mut Self, Vec<xml::attribute::OwnedAttribute>) -> crate::Result<T>>(&mut self, f: F) -> crate::Result<T> {
        trace!("read_inner_value()");
        let old_greedy = self.is_greedy;
        let ret = if self.unset_map_value() {
            match self.next()? {
                xml::reader::XmlEvent::StartElement { name, attributes, .. } => {
                    let result = f(self, attributes)?;
                    self.expect_end_element(name)?;
                    Ok(result)
                }
                _ => Err(crate::Error::ExpectedElement)
            }
        } else {
            f(self, vec![])
        };
        self.is_greedy = old_greedy;
        ret
    }

    fn expect_end_element(&mut self, old_name: xml::name::OwnedName) -> crate::Result<()> {
        trace!("expect_end_element({:?})", old_name);
        match self.next()? {
            xml::reader::XmlEvent::EndElement { name } => {
                if name == old_name {
                    Ok(())
                } else {
                    Err(crate::Error::ExpectedElement)
                }
            }
            _ => Err(crate::Error::ExpectedElement)
        }
    }

    fn step_over(&mut self) -> crate::Result<()> {
        if self.is_greedy {
            let depth = self.depth;
            loop {
                self.next()?;
                if self.depth == depth {
                    break;
                }
            }
        } else {
            let mut depth = 0;
            loop {
                let next = self.peek()?;
                match next {
                    xml::reader::XmlEvent::StartElement { .. } => {
                        depth += 1;
                    }
                    xml::reader::XmlEvent::EndElement { .. } => {
                        depth -= 1;
                    }
                    _ => {}
                }
                self.reset_peek_offset += 1;
                if depth == 0 {
                    break;
                }
            }
        }
        Ok(())
    }

    fn parse_string(&mut self) -> crate::Result<String> {
        trace!("parse_string()");
        self.read_inner_value(|this| {
            match this.peek()? {
                xml::reader::XmlEvent::EndElement {
                    ..
                } => return Ok(String::new()),
                _ => {}
            }
            match this.next()? {
                xml::reader::XmlEvent::CData(s) | xml::reader::XmlEvent::Characters(s) => {
                    Ok(s)
                }
                xml::reader::XmlEvent::StartElement {
                    name,
                    attributes,
                    namespace
                } => {
                    let mut output: Vec<u8> = Vec::new();
                    let conf = xml::writer::EmitterConfig::new()
                        .perform_indent(false)
                        .write_document_declaration(false)
                        .normalize_empty_elements(true)
                        .cdata_to_characters(false)
                        .keep_element_names_stack(false)
                        .pad_self_closing(false);
                    let mut writer = conf.create_writer(&mut output);
                    writer.write(xml::writer::XmlEvent::StartElement {
                        name: name.borrow(),
                        attributes: attributes.iter().map(|a| a.borrow()).collect(),
                        namespace: std::borrow::Cow::Borrowed(&namespace),
                    }).unwrap();
                    let depth = this.depth - 1;
                    loop {
                        let event = this.next()?;
                        trace!("{:?}; {}; {}", event, this.depth, depth);
                        if this.depth == depth {
                            break;
                        }
                        if let Some(e) = event.as_writer_event() {
                            trace!("{:?}; {}; {}", event, this.depth, depth);
                            writer.write(e).unwrap();
                        }
                    }
                    writer.write(xml::writer::XmlEvent::EndElement {
                        name: Some(name.borrow())
                    }).unwrap();
                    Ok(String::from_utf8(output).unwrap())
                }
                _ => Err(crate::Error::ExpectedString)
            }
        })
    }

    fn parse_bool(&mut self) -> crate::Result<bool> {
        let s = self.parse_string()?;
        match s.to_lowercase().as_str() {
            "true" | "1" | "y" => Ok(true),
            "false" | "0" | "n" => Ok(false),
            _ => Err(crate::Error::ExpectedBool)
        }
    }

    fn parse_int<T: AddAssign<T> + MulAssign<T> + std::str::FromStr>(&mut self) -> crate::Result<T> {
        let s = self.parse_string()?;
        match s.parse::<T>() {
            Ok(i) => Ok(i),
            Err(_) => Err(crate::Error::ExpectedInt)
        }
    }
}

impl<'de, 'a, I: Iterator<Item=XmlRes>> de::Deserializer<'de> for &'a mut Deserializer<I> {
    type Error = crate::Error;

    fn deserialize_any<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_any()");
        if self.is_map_value && !self.unset_seq_value() {
            self.reset_peek();
            if let xml::reader::XmlEvent::StartElement { name: name1, .. } = self.peek()? {
                let name1 = name1.to_owned();
                self.reset_peek();
                self.set_not_greedy();
                self.step_over()?;
                self.reset_peek_offset = 0;
                if let xml::reader::XmlEvent::StartElement { name: name2, .. } = self.peek()? {
                    if name1 == *name2 {
                        self.reset_peek_offset = 0;
                        self.reset_peek();
                        self.set_map_value();
                        return visitor.visit_seq(Seq::new(&mut self)?);
                    }
                }
            }
        }
        let is_map = self.is_map_value;
        self.read_inner_value_attrs(|this, attrs| {
            if let xml::reader::XmlEvent::CData(_) | xml::reader::XmlEvent::Characters(_) = this.peek()? {
                let s = match this.next()? {
                    xml::reader::XmlEvent::CData(s) | xml::reader::XmlEvent::Characters(s) => s,
                    _ => unreachable!()
                };
                visitor.visit_string(s)
            } else {
                if !is_map {
                    match this.next()? {
                        xml::reader::XmlEvent::StartElement { name, .. } => {
                            let result = visitor.visit_map(Map::new(this, attrs, &[]))?;
                            this.expect_end_element(name)?;
                            Ok(result)
                        }
                        _ => Err(crate::Error::ExpectedElement)
                    }
                } else {
                    this.reset_peek();
                    visitor.visit_map(Map::new(this, attrs, &[]))
                }
            }
        })
        // self.peek();
        // Err(crate::Error::Unsupported)
    }

    fn deserialize_bool<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_bool(self.parse_bool()?)
    }

    fn deserialize_i8<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_i8(self.parse_int()?)
    }

    fn deserialize_i16<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_i16(self.parse_int()?)
    }

    fn deserialize_i32<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_i32(self.parse_int()?)
    }

    fn deserialize_i64<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_i64(self.parse_int()?)
    }

    fn deserialize_u8<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_u8(self.parse_int()?)
    }

    fn deserialize_u16<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_u16(self.parse_int()?)
    }

    fn deserialize_u32<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_u32(self.parse_int()?)
    }

    fn deserialize_u64<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_u64(self.parse_int()?)
    }

    fn deserialize_f32<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_u64(self.parse_int()?)
    }

    fn deserialize_f64<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_u64(self.parse_int()?)
    }

    fn deserialize_char<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        use std::str::FromStr;

        let s = self.parse_string()?;
        if s.len() == 1 {
            visitor.visit_char(match char::from_str(&s) {
                Ok(c) => c,
                Err(_) => return Err(crate::Error::ExpectedChar)
            })
        } else {
            Err(crate::Error::ExpectedChar)
        }
    }

    fn deserialize_str<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_string(self.parse_string()?)
    }

    fn deserialize_string<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V: serde::de::Visitor<'de>>(self, _visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_bytes()");
        Err(crate::Error::Unsupported)
    }

    fn deserialize_byte_buf<V: serde::de::Visitor<'de>>(self, _visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_byte_buf()");
        Err(crate::Error::Unsupported)
    }

    fn deserialize_option<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_option()");
        if self.is_map_value {
            if let xml::reader::XmlEvent::StartElement { attributes, .. } = self.peek()? {
                if !attributes.is_empty() {
                    self.reset_peek();
                    return visitor.visit_some(self);
                }
            }
        }
        if let xml::reader::XmlEvent::EndElement { .. } = self.peek()? {
            if self.unset_map_value() {
                self.next()?;
            }
            self.next()?;
            visitor.visit_none()
        } else {
            self.reset_peek();
            visitor.visit_some(self)
        }
    }

    fn deserialize_unit<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: serde::de::Visitor<'de>>(self, name: &'static str, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_unit_struct({:?})", name);
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: serde::de::Visitor<'de>>(self, name: &'static str, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_newtype_struct({:?})", name);
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V: serde::de::Visitor<'de>>(mut self, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_seq()");
        let res = visitor.visit_seq(Seq::new(&mut self)?)?;
        self.unset_seq_value();
        Ok(res)
    }

    fn deserialize_tuple<V: serde::de::Visitor<'de>>(self, len: usize, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_tuple({:?})", len);
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: serde::de::Visitor<'de>>(self, name: &'static str, len: usize, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_tuple_struct({:?}, {:?})", name, len);
        self.deserialize_seq(visitor)
    }

    fn deserialize_map<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_map()");
        self.read_inner_value_attrs(|this, attrs| {
            visitor.visit_map(Map::new(this, attrs, &[]))
        })
    }

    fn deserialize_struct<V: serde::de::Visitor<'de>>(self, name: &'static str, fields: &'static [&'static str], visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_struct({:?}, {:?})", name, fields);
        self.read_inner_value_attrs(|this, attrs| {
            visitor.visit_map(Map::new(this, attrs, fields))
        })
    }

    fn deserialize_enum<V: serde::de::Visitor<'de>>(self, name: &'static str, variants: &'static [&'static str], visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_enum({:?}, {:?})", name, variants);
        if self.unset_is_value() {
            visitor.visit_enum(Enum::new(self, variants))
        } else {
            self.read_inner_value(|this| {
                visitor.visit_enum(Enum::new(this, variants))
            })
        }
    }

    fn deserialize_identifier<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_identifier()");
        self.deserialize_str(visitor)
    }

    fn deserialize_ignored_any<V: serde::de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_ignored_any()");
        self.step_over()?;
        visitor.visit_unit()
    }
}

struct Seq<'a, I: Iterator<Item=XmlRes>> {
    de: &'a mut Deserializer<I>,
    expected_name: Option<xml::name::OwnedName>,
}

impl<'a, I: Iterator<Item=XmlRes>> Seq<'a, I> {
    fn new(de: &'a mut Deserializer<I>) -> crate::Result<Self> {
        trace!("Seq::new()");
        let name = if de.unset_map_value() {
            let val = match de.peek()? {
                xml::reader::XmlEvent::StartElement { name, .. } => {
                    Some(name.clone())
                }
                _ => return Err(crate::Error::ExpectedElement)
            };
            de.reset_peek();
            val
        } else {
            None
        };
        Ok(Self {
            de,
            expected_name: name,
        })
    }
}

impl<'de, 'a, I: Iterator<Item=XmlRes>> de::SeqAccess<'de> for Seq<'a, I> {
    type Error = crate::Error;

    fn next_element_seed<T: de::DeserializeSeed<'de>>(&mut self, seed: T) -> crate::Result<Option<T::Value>> {
        trace!("next_element_seed()");
        let more = match (self.de.peek()?, self.expected_name.as_ref()) {
            (xml::reader::XmlEvent::StartElement { ref name, .. }, Some(expected_name)) => {
                name == expected_name
            }
            (xml::reader::XmlEvent::EndElement { .. }, None) | (_, Some(_)) | (xml::reader::XmlEvent::EndDocument { .. }, _) => false,
            (_, None) => true,
        };
        self.de.reset_peek();
        if more {
            if self.expected_name.is_some() {
                self.de.set_map_value();
            } else {
                self.de.unset_map_value();
            }
            self.de.set_seq_value();
            seed.deserialize(&mut *self.de).map(Some)
        } else {
            Ok(None)
        }
    }
}

struct Fields {
    fields: &'static[Field],
    inner_value: bool,
    num_value: u64,
    value_used: u64,
}

#[derive(Clone)]
struct Field {
    namespace: Option<&'static str>,
    local_name: &'static str,
    name: &'static str,
    attr: bool,
}

impl From<&&'static str> for Field {
    fn from(from: &&'static str) -> Self {
        let mut attr = false;
        let name = if from.starts_with("$attr:") {
            attr = true;
            &from[6..]
        } else {
            from
        };

        let Tag{
            e: local_name,
            n: namespace,
            ..
        } = crate::Tag::from_static(name);

        Field {
            namespace,
            local_name,
            name,
            attr,
        }
    }
}

impl From<&'static [&'static str]> for Fields {
    fn from(from: &'static [&'static str]) -> Self {
        use once_cell::sync::OnceCell;
        use std::sync::Mutex;
        use std::collections::btree_map::{BTreeMap,Entry};

        let (fields, num_value) = {
            // Make a single global BTreeMap to act as a cache
            static CACHE: OnceCell<Mutex<BTreeMap<usize, (&'static [Field], u64)>>> = OnceCell::new();
            let mut cache = CACHE.get_or_init(|| {
                Mutex::new(BTreeMap::new())
            }).lock().unwrap();

            // Look up the pointer address of our &'static [&'static str] in the cache
            match cache.entry((*from).as_ptr() as usize) {
                Entry::Vacant(e) => {
                    // Miss
                    // Convert the str slice into a Vec<Field>
                    let fields: Vec<Field> = from.iter().map(|f| f.into()).collect();

                    // Convert the Vec into a &'static [Field]
                    let fields = Box::leak(fields.into_boxed_slice());

                    // Count how many $value fields we have
                    let num_value = from.iter().filter(|f| f.starts_with(&"$value")).count() as u64;

                    // Add it to the cache
                    *e.insert((fields, num_value))
                }
                Entry::Occupied(e) => {
                    // Hit
                    // Use the existing slice and count
                    *e.get()
                }
            }
        };

        Fields {
            fields,
            inner_value: num_value >= 1,
            num_value,
            value_used: 0,
        }
    }
}

impl Fields {
    fn match_field(&mut self, name: &xml::name::OwnedName) -> Cow<'static, str> {
        for field in self.fields.iter() {
            if field.local_name == name.local_name && field.namespace == name.namespace.as_deref() && !field.attr {
                trace!("match_field({:?}) -> {:?}", name, field.name);
                return field.name.into();
            }
        }
        let name_str = if self.inner_value && self.value_used < self.num_value {
            self.value_used += 1;
            if self.num_value == 1 {
                "$value".to_string()
            } else {
                format!("$value{}", self.value_used)
            }
        } else {
            match &name.namespace {
                Some(n) => format!("{{{}}}{}", n, name.local_name),
                None => name.local_name.clone()
            }
        };
        trace!("match_field({:?}) -> {:?}", name, name_str);
        name_str.into()
    }

    fn match_attr(&self, name: &xml::name::OwnedName) -> Cow<'static, str> {
        for field in self.fields.iter() {
            if field.local_name == name.local_name && field.namespace == name.namespace.as_deref() && field.attr {
                let name_str = format!("$attr:{}", field.name);
                trace!("match_attr({:?}) -> {:?}", name, name_str);
                return name_str.into();
            }
        }
        let name_str = match &name.namespace {
            Some(n) => format!("{{{}}}{}", n, name.local_name),
            None => name.local_name.clone()
        };
        let name_str = format!("$attr:{}", name_str);
        trace!("match_attr({:?}) -> {:?}", name, name_str);
        name_str.into()
    }
}

struct Map<'a, I: Iterator<Item=XmlRes>> {
    de: &'a mut Deserializer<I>,
    attrs: Vec<xml::attribute::OwnedAttribute>,
    fields: Fields,
    next_value: Option<String>,
    inner_value: bool,
    next_is_value: bool,
}

impl<'a, I: Iterator<Item=XmlRes>> Map<'a, I> {
    fn new(de: &'a mut Deserializer<I>, attrs: Vec<xml::attribute::OwnedAttribute>, fields: &'static [&'static str]) -> Self {
        trace!("Map::new({:?})", fields);
        Self {
            de,
            attrs,
            fields: fields.into(),
            next_value: None,
            inner_value: true,
            next_is_value: false,
        }
    }
}

impl<'de, 'a, I: Iterator<Item=XmlRes>> de::MapAccess<'de> for Map<'a, I> {
    type Error = crate::Error;

    fn next_key_seed<K: de::DeserializeSeed<'de>>(&mut self, seed: K) -> crate::Result<Option<K::Value>> {
        trace!("next_key_seed(); attrs = {:?}", self.attrs);
        match self.attrs.pop() {
            Some(xml::attribute::OwnedAttribute { name, value }) => {
                let name = self.fields.match_attr(&name);
                self.next_value = Some(value);
                self.next_is_value = false;
                seed.deserialize(name.as_ref().into_deserializer()).map(Some)
            }
            None => {
                let val = match *self.de.peek()? {
                    xml::reader::XmlEvent::StartElement {
                        ref name, ..
                    } => {
                        let name = self.fields.match_field(name);
                        self.inner_value = name.starts_with(&"$value");
                        self.next_is_value = name.starts_with(&"$value");
                        seed.deserialize(name.as_ref().into_deserializer()).map(Some)
                    }
                    xml::reader::XmlEvent::Characters(_) | xml::reader::XmlEvent::CData(_) => {
                        self.next_is_value = true;
                        seed.deserialize("$value".into_deserializer()).map(Some)
                    }
                    _ => Ok(None)
                };
                self.de.reset_peek();
                val
            }
        }
    }

    fn next_value_seed<V: de::DeserializeSeed<'de>>(&mut self, seed: V) -> crate::Result<V::Value> {
        trace!("next_value_seed(); next_value = {:?}; next_is_value = {}", self.next_value, self.next_is_value);
        match self.next_value.take() {
            Some(val) => seed.deserialize(AttrValueDeserializer(val)),
            None => {
                if !std::mem::replace(&mut self.inner_value, false) {
                    self.de.set_map_value();
                }
                if self.next_is_value {
                    self.de.set_is_value();
                }
                let greedy = self.next_is_value && self.fields.fields.len() > 1;
                if greedy {
                    self.de.set_not_greedy();
                }
                let val = seed.deserialize(&mut *self.de)?;
                if greedy {
                    self.de.unset_not_greedy();
                    self.de.reset_peek();
                }
                Ok(val)
            }
        }
    }
}

pub struct Enum<'a, I: Iterator<Item=XmlRes>> {
    de: &'a mut Deserializer<I>,
    fields: Fields,
}

impl<'a, I: Iterator<Item=XmlRes>> Enum<'a, I> {
    pub fn new(de: &'a mut Deserializer<I>, fields: &'static [&'static str]) -> Self {
        trace!("Enum::new({:?})", fields);
        Self {
            de,
            fields: fields.into(),
        }
    }
}

impl<'de, 'a, I: Iterator<Item=XmlRes>> de::EnumAccess<'de> for Enum<'a, I> {
    type Error = crate::Error;
    type Variant = Self;

    fn variant_seed<V: de::DeserializeSeed<'de>>(mut self, seed: V) -> crate::Result<(V::Value, Self::Variant)> {
        trace!("variant_seed()");
        let val = match self.de.peek()? {
            xml::reader::XmlEvent::StartElement {
                name, ..
            } => {
                let name_str = self.fields.match_field(name);
                if !name_str.starts_with(&"$value") {
                    self.de.set_map_value();
                }
                let name_str: serde::de::value::CowStrDeserializer<crate::Error> = name_str.into_deserializer();
                Ok(seed.deserialize(name_str)?)
            }
            xml::reader::XmlEvent::Characters(s) | xml::reader::XmlEvent::CData(s) => {
                let name: serde::de::value::StrDeserializer<crate::Error> = s.as_str().into_deserializer();
                Ok(seed.deserialize(name)?)
            }
            _ => Err(crate::Error::ExpectedString)
        }?;
        self.de.reset_peek();
        Ok((val, self))
    }
}

impl<'de, 'a, I: Iterator<Item=XmlRes>> de::VariantAccess<'de> for Enum<'a, I> {
    type Error = crate::Error;

    fn unit_variant(self) -> crate::Result<()> {
        trace!("unit_variant()");
        self.de.unset_map_value();
        match self.de.next()? {
            xml::reader::XmlEvent::StartElement {
                name, attributes, ..
            } => if attributes.is_empty() {
                self.de.expect_end_element(name)
            } else {
                Err(crate::Error::ExpectedElement)
            },
            xml::reader::XmlEvent::Characters(_) | xml::reader::XmlEvent::CData(_) => Ok(()),
            _ => unreachable!()
        }
    }

    fn newtype_variant_seed<T: de::DeserializeSeed<'de>>(self, seed: T) -> crate::Result<T::Value> {
        trace!("newtype_variant_seed()");
        seed.deserialize(self.de)
    }

    fn tuple_variant<V: de::Visitor<'de>>(self, len: usize, visitor: V) -> crate::Result<V::Value> {
        trace!("tuple_variant({:?})", len);
        use serde::de::Deserializer;
        self.de.deserialize_tuple(len, visitor)
    }

    fn struct_variant<V: de::Visitor<'de>>(self, fields: &'static [&'static str], visitor: V) -> crate::Result<V::Value> {
        trace!("struct_variant({:?})", fields);
        use serde::de::Deserializer;
        self.de.deserialize_struct("", fields, visitor)
    }
}

struct AttrValueDeserializer(String);

macro_rules! deserialize_type_attr {
    ($deserialize:ident => $visit:ident) => {
        fn $deserialize<V: de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
            visitor.$visit(match self.0.parse() {
                Ok(v) => v,
                Err(_) => return Err(crate::Error::ExpectedInt)
            })
        }
    }
}

impl<'de> serde::de::Deserializer<'de> for AttrValueDeserializer {
    type Error = crate::Error;

    fn deserialize_any<V: de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_string(self.0)
    }

    deserialize_type_attr!(deserialize_i8 => visit_i8);
    deserialize_type_attr!(deserialize_i16 => visit_i16);
    deserialize_type_attr!(deserialize_i32 => visit_i32);
    deserialize_type_attr!(deserialize_i64 => visit_i64);
    deserialize_type_attr!(deserialize_u8 => visit_u8);
    deserialize_type_attr!(deserialize_u16 => visit_u16);
    deserialize_type_attr!(deserialize_u32 => visit_u32);
    deserialize_type_attr!(deserialize_u64 => visit_u64);
    deserialize_type_attr!(deserialize_f32 => visit_f32);
    deserialize_type_attr!(deserialize_f64 => visit_f64);

    fn deserialize_enum<V: de::Visitor<'de>>(self, name: &str, variants: &'static [&'static str], visitor: V) -> crate::Result<V::Value> {
        trace!("deserialize_enum({:?}, {:?})", name, variants);
        visitor.visit_enum(self.0.into_deserializer())
    }

    fn deserialize_option<V: de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        visitor.visit_some(self)
    }

    fn deserialize_bool<V: de::Visitor<'de>>(self, visitor: V) -> crate::Result<V::Value> {
        match self.0.to_lowercase().as_str() {
            "true" | "1" | "y" => visitor.visit_bool(true),
            "false" | "0" | "n" => visitor.visit_bool(false),
            _ => Err(crate::Error::ExpectedBool),
        }
    }

    serde::forward_to_deserialize_any! {
        char str string unit seq bytes map unit_struct newtype_struct tuple_struct
        struct identifier tuple ignored_any byte_buf
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn deserialize_element_into_struct() {
        #[derive(Debug, PartialEq, Deserialize)]
        struct Foo {
            #[serde(rename = "{urn:foo}foo:bar")]
            bar: String,
        }

        assert_eq!(
            crate::from_str::<Foo>(
                r#"
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<foo:bar xmlns:foo="urn:foo">baz</foo:bar>
            "#
            )
                .unwrap(),
            Foo {
                bar: "baz".to_string()
            }
        );
    }

    #[test]
    fn deserialize_element_with_processing_instruction_into_struct() {
        #[derive(Debug, PartialEq, Deserialize)]
        struct Foo {
            #[serde(rename = "{urn:foo}foo:bar")]
            bar: String,
        }

        assert_eq!(
            crate::from_str::<Foo>(
                r#"
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<?xml-stylesheet href='foo.xsl' type='text/xsl'?>
<foo:bar xmlns:foo="urn:foo">baz</foo:bar>
            "#
            )
                .unwrap(),
            Foo {
                bar: "baz".to_string()
            }
        );
    }
}
