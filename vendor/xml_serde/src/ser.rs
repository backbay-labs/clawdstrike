//! Custom serde XML serializer
//!
//! The special serde tag name `$value` equates to the inner value of an XML element.
//! Tags starting with `$attr:` will be encoded as attributes rather than new elements.
//! Namespaces and prefixes can be set using the tag name format `{namespace}prefix:tag-name`.

use std::borrow::Cow;
use serde::{ser, Serialize};
use crate::Tag;

pub struct Serializer;

trait EventWriter {
    fn write<'a, E: Into<xml::writer::XmlEvent<'a>>>(&mut self, event: E) -> xml::writer::Result<()>;
}

struct EmitterWriter<W: std::io::Write>(xml::writer::EventWriter<W>);

impl<W: std::io::Write> EventWriter for EmitterWriter<W> {
    fn write<'a, E: Into<xml::writer::XmlEvent<'a>>>(&mut self, event: E) -> xml::writer::Result<()> {
        self.0.write(event)
    }
}

struct ListWriter(Vec<xml::reader::XmlEvent>);

impl EventWriter for ListWriter {
    fn write<'a, E: Into<xml::writer::XmlEvent<'a>>>(&mut self, event: E) -> xml::writer::Result<()> {
        let e = event.into();
        let re = match e {
            xml::writer::XmlEvent::StartDocument { version, encoding, standalone } => {
                xml::reader::XmlEvent::StartDocument {
                    version,
                    encoding: encoding.unwrap_or("UTF-8").to_string(),
                    standalone,
                }
            }
            xml::writer::XmlEvent::ProcessingInstruction { name, data } => {
                xml::reader::XmlEvent::ProcessingInstruction {
                    name: name.to_string(),
                    data: data.map(Into::into),
                }
            }
            xml::writer::XmlEvent::StartElement { name, attributes, namespace } => {
                xml::reader::XmlEvent::StartElement {
                    name: name.to_owned(),
                    attributes: (*attributes).iter().map(|a| a.to_owned()).collect(),
                    namespace: (*namespace).clone(),
                }
            }
            xml::writer::XmlEvent::EndElement { name } => {
                xml::reader::XmlEvent::EndElement {
                    name: match name {
                        Some(n) => n.to_owned(),
                        None => unreachable!()
                    },
                }
            }
            xml::writer::XmlEvent::CData(s) => {
                xml::reader::XmlEvent::CData(s.into())
            }
            xml::writer::XmlEvent::Characters(s) => {
                xml::reader::XmlEvent::Characters(s.into())
            }
            xml::writer::XmlEvent::Comment(s) => {
                xml::reader::XmlEvent::Comment(s.into())
            }
        };
        self.0.push(re);
        Ok(())
    }
}

pub struct Options {
  pub include_schema_location: bool
}

impl Default for Options {
  fn default() -> Self {
    Self {
      include_schema_location: true
    }
  }
}

/// Serialise serde item to XML
///
/// # Arguments
/// * `value` - The value to be serialised
pub fn to_string<T>(value: &T) -> Result<String, crate::Error>
    where
        T: Serialize,
{
    to_string_custom(value, Options::default())
}

/// Serialise serde item to XML, with custom options
///
/// # Arguments
/// * `value` - The value to be serialised
/// * `options` - Custom options for the serializer
pub fn to_string_custom<T>(value: &T, options: Options) -> Result<String, crate::Error>
    where
        T: Serialize,
{
    let mut conf = xml::writer::EmitterConfig::new()
        .perform_indent(true)
        .write_document_declaration(true)
        .normalize_empty_elements(true)
        .cdata_to_characters(true)
        .keep_element_names_stack(true)
        .pad_self_closing(false);
    conf.perform_escaping = false;

    let c = std::io::Cursor::new(Vec::new());
    let mut writer = EmitterWriter(conf.create_writer(c));
    let mut serializer = Serializer;
    let val = value.serialize(&mut serializer)?;
    let mut state = _SerializerState {
        raw_output: false,
        ns_stack: vec![],
        include_schema_location: options.include_schema_location,
    };
    format_data(&mut writer, &val, &mut state)?;
    Ok(String::from_utf8(writer.0.into_inner().into_inner()).unwrap())
}

/// Serialise serde item to a list of XML events
///
/// # Arguments
/// * `value` - The value to be serialised
pub fn to_events<T>(value: &T) -> Result<Vec<xml::reader::XmlEvent>, crate::Error>
    where
        T: Serialize,
{
    to_events_custom(value, Options::default())
}

/// Serialise serde item to a list of XML events, with custom options
///
/// # Arguments
/// * `value` - The value to be serialised
/// * `options` - Custom options for the serializer
pub fn to_events_custom<T>(value: &T, options: Options) -> Result<Vec<xml::reader::XmlEvent>, crate::Error>
    where
        T: Serialize,
{
    let mut writer = ListWriter(vec![]);
    let mut serializer = Serializer;
    let val = value.serialize(&mut serializer)?;
    let mut state = _SerializerState {
        raw_output: false,
        ns_stack: vec![],
        include_schema_location: options.include_schema_location,
    };
    format_data(&mut writer, &val, &mut state)?;
    Ok(writer.0)
}

#[derive(Debug)]
pub enum _SerializerData {
    CData(String),
    String(String),
    Seq(Vec<_SerializerData>),
    Struct { attrs: Vec<(Cow<'static, str>, String)>, contents: Vec<(Cow<'static, str>, _SerializerData)> },
}

impl _SerializerData {
    fn as_str(&self) -> String {
        match self {
            _SerializerData::CData(s) => s.clone(),
            _SerializerData::String(s) => s.clone(),
            _SerializerData::Seq(s) => s.iter().map(|d| d.as_str()).collect::<Vec<_>>().join(","),
            _SerializerData::Struct { contents, .. } => contents.iter().map(|(_, d)| d.as_str()).collect::<Vec<_>>().join(","),
        }
    }
}

struct _SerializerState {
    raw_output: bool,
    ns_stack: Vec<String>,
    include_schema_location: bool,
}

fn format_data<W: EventWriter>(writer: &mut W, val: &_SerializerData, state: &mut _SerializerState) -> Result<(), crate::Error> {
    match val {
        _SerializerData::CData(s) => {
            writer.write(xml::writer::XmlEvent::cdata(&match state.raw_output {
                true => s.to_string(),
                false => xml::escape::escape_str_pcdata(s).to_string()
            }))?
        }
        _SerializerData::String(s) => {
            writer.write(xml::writer::XmlEvent::characters(&match state.raw_output {
                true => s.to_string(),
                false => xml::escape::escape_str_pcdata(s).to_string()
            }))?
        }
        _SerializerData::Seq(s) => {
            for d in s {
                format_data(writer, &d, state)?;
            }
        }
        _SerializerData::Struct {
            contents,
            ..
        } => {
            for (tag, d) in contents {
                if *tag == "$valueRaw" {
                    let old_val = state.raw_output;
                    state.raw_output = true;
                    format_data(writer, &d, state)?;
                    state.raw_output = old_val;
                } else if tag.starts_with(&"$value") {
                    format_data(writer, &d, state)?;
                } else {
                    let parsed_tag = Tag::from_cow(&tag);
                    let base_name = parsed_tag.e;
                    let name = match parsed_tag.p {
                        Some(p) => format!("{}:{}", p, base_name),
                        None => base_name.to_string()
                    };

                    match d {
                        _SerializerData::Seq(s) => {
                            for d in s {
                                let attrs = match d {
                                    _SerializerData::Struct {
                                        attrs,
                                        ..
                                    } => attrs.to_owned(),
                                    _ => vec![]
                                };
                                let attrs = attrs.iter().map(|(attr_k, attr_v)| {
                                    (xml::name::Name::from(Tag::from_cow(attr_k)), attr_v)
                                }).collect::<Vec<_>>();
                                let mut elm = xml::writer::XmlEvent::start_element(name.as_str());
                                if state.include_schema_location {
                                    elm = elm.ns("xsi", "http://www.w3.org/2001/XMLSchema-instance");
                                }
                                let mut loc = String::new();
                                let mut should_pop = false;
                                if let Some(n) = parsed_tag.n {
                                    match parsed_tag.p {
                                        Some(p) => elm = elm.ns(p, n),
                                        None => elm = elm.default_ns(n)
                                    };
                                    if !state.ns_stack.iter().any(|ns| ns == n) {
                                        if let Some(l) = parsed_tag.l {
                                            if !l.is_empty() {
                                                loc.push_str(&format!("{} {}", n, l));
                                            }
                                        } else {
                                            let last_n = n.rsplit(':').next().unwrap();
                                            loc.push_str(&format!("{} {}.xsd", n, last_n));
                                        }
                                        if state.include_schema_location && !loc.is_empty() {
                                            elm = elm.attr(xml::name::Name {
                                                namespace: None,
                                                local_name: "schemaLocation",
                                                prefix: Some("xsi"),
                                            }, &loc);
                                        }
                                        state.ns_stack.push(n.to_string());
                                        should_pop = true;
                                    }
                                }
                                for (name, attr_v) in attrs.clone() {
                                    elm = elm.attr(name, attr_v);
                                }

                                writer.write(elm)?;
                                format_data(writer, &d, state)?;
                                writer.write(xml::writer::XmlEvent::end_element())?;
                                if should_pop {
                                    state.ns_stack.pop();
                                }
                            }
                        }
                        d => {
                            let attrs = match d {
                                _SerializerData::Struct {
                                    attrs,
                                    ..
                                } => attrs.to_owned(),
                                _ => vec![]
                            };
                            let attrs = attrs.iter().map(|(attr_k, attr_v)| {
                                (xml::name::Name::from(Tag::from_cow(attr_k)), attr_v)
                            }).collect::<Vec<_>>();

                            let mut elm = xml::writer::XmlEvent::start_element(name.as_str());
                            if state.include_schema_location {
                                elm = elm.ns("xsi", "http://www.w3.org/2001/XMLSchema-instance");
                            }
                            let mut loc = String::new();
                            let mut should_pop = false;
                            if let Some(n) = parsed_tag.n {
                                match parsed_tag.p {
                                    Some(p) => elm = elm.ns(p, n),
                                    None => elm = elm.default_ns(n)
                                };
                                if !state.ns_stack.iter().any(|ns| ns == n) {
                                    if let Some(l) = parsed_tag.l {
                                        if !l.is_empty() {
                                            loc.push_str(&format!("{} {}", n, l));
                                        }
                                    } else {
                                        let last_n = n.rsplit(':').next().unwrap();
                                        loc.push_str(&format!("{} {}.xsd", n, last_n));
                                    }
                                    if state.include_schema_location && !loc.is_empty() {
                                        elm = elm.attr(xml::name::Name {
                                            namespace: None,
                                            local_name: "schemaLocation",
                                            prefix: Some("xsi"),
                                        }, &loc);
                                    }
                                    state.ns_stack.push(n.to_string());
                                    should_pop = true;
                                }
                            }
                            for (name, attr_v) in attrs {
                                elm = elm.attr(name, attr_v);
                            }

                            writer.write(elm)?;
                            format_data(writer, &d, state)?;
                            writer.write(xml::writer::XmlEvent::end_element())?;
                            if should_pop {
                                state.ns_stack.pop();
                            }
                        }
                    };
                }
            }
        }
    }
    Ok(())
}

impl<'a> ser::Serializer for &'a mut Serializer {
    type Ok = _SerializerData;
    type Error = crate::Error;
    type SerializeSeq = SeqSerializer<'a>;
    type SerializeTuple = SeqSerializer<'a>;
    type SerializeTupleStruct = SeqSerializer<'a, >;
    type SerializeTupleVariant = SeqSerializer<'a>;
    type SerializeMap = MapSerializer<'a>;
    type SerializeStruct = StructSerializer<'a>;
    type SerializeStructVariant = StructVariantSerializer<'a>;

    fn serialize_bool(self, v: bool) -> Result<_SerializerData, Self::Error> {
        let val = if v { "true" } else { "false" };
        Ok(_SerializerData::String(val.to_string()))
    }

    fn serialize_i8(self, v: i8) -> Result<_SerializerData, Self::Error> {
        self.serialize_i64(i64::from(v))
    }

    fn serialize_i16(self, v: i16) -> Result<_SerializerData, Self::Error> {
        self.serialize_i64(i64::from(v))
    }

    fn serialize_i32(self, v: i32) -> Result<_SerializerData, Self::Error> {
        self.serialize_i64(i64::from(v))
    }

    fn serialize_i64(self, v: i64) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::String(v.to_string()))
    }

    fn serialize_u8(self, v: u8) -> Result<_SerializerData, Self::Error> {
        self.serialize_u64(u64::from(v))
    }

    fn serialize_u16(self, v: u16) -> Result<_SerializerData, Self::Error> {
        self.serialize_u64(u64::from(v))
    }

    fn serialize_u32(self, v: u32) -> Result<_SerializerData, Self::Error> {
        self.serialize_u64(u64::from(v))
    }

    fn serialize_u64(self, v: u64) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::String(v.to_string()))
    }

    fn serialize_f32(self, v: f32) -> Result<_SerializerData, Self::Error> {
        self.serialize_f64(f64::from(v))
    }

    fn serialize_f64(self, v: f64) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::String(v.to_string()))
    }

    fn serialize_char(self, v: char) -> Result<_SerializerData, Self::Error> {
        self.serialize_str(&v.to_string())
    }

    fn serialize_str(self, v: &str) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::CData(v.to_string()))
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::String(hex::encode(v)))
    }

    fn serialize_none(self) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::String("".to_string()))
    }

    fn serialize_some<T>(self, value: &T) -> Result<_SerializerData, Self::Error>
        where
            T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<_SerializerData, Self::Error> {
        self.serialize_none()
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<_SerializerData, Self::Error> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
    ) -> Result<_SerializerData, Self::Error> {
        self.serialize_str(variant)
    }

    fn serialize_newtype_struct<T>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<_SerializerData, Self::Error>
        where
            T: ?Sized + Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T>(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<_SerializerData, Self::Error>
        where
            T: ?Sized + Serialize,
    {
        let value = value.serialize(&mut *self)?;
        Ok(_SerializerData::Struct {
            attrs: vec![],
            contents: vec![(variant.into(), value)],
        })
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        Ok(SeqSerializer {
            parent: self,
            output: vec![],
        })
    }

    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        _variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.serialize_seq(Some(len))
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        Ok(MapSerializer {
            parent: self,
            keys: vec![],
            cur_key: String::new(),
        })
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(StructSerializer {
            parent: self,
            attrs: vec![],
            keys: vec![],
        })
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _variant_index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        Ok(StructVariantSerializer {
            parent: self,
            attrs: vec![],
            keys: vec![],
            tag: variant.to_string(),
        })
    }
}

pub struct SeqSerializer<'a> {
    parent: &'a mut Serializer,
    output: Vec<_SerializerData>,
}

impl<'a> ser::SerializeSeq for SeqSerializer<'a> {
    type Ok = _SerializerData;
    type Error = crate::Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
    {
        let val = value.serialize(&mut *self.parent)?;
        self.output.push(val);
        Ok(())
    }

    fn end(self) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::Seq(self.output))
    }
}

impl<'a> ser::SerializeTuple for SeqSerializer<'a> {
    type Ok = _SerializerData;
    type Error = crate::Error;

    fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
    {
        let val = value.serialize(&mut *self.parent)?;
        self.output.push(val);
        Ok(())
    }

    fn end(self) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::Seq(self.output))
    }
}

impl<'a> ser::SerializeTupleStruct for SeqSerializer<'a> {
    type Ok = _SerializerData;
    type Error = crate::Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
    {
        let val = value.serialize(&mut *self.parent)?;
        self.output.push(val);
        Ok(())
    }

    fn end(self) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::Seq(self.output))
    }
}

impl<'a> ser::SerializeTupleVariant for SeqSerializer<'a> {
    type Ok = _SerializerData;
    type Error = crate::Error;

    fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
    {
        let val = value.serialize(&mut *self.parent)?;
        self.output.push(val);
        Ok(())
    }

    fn end(self) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::Seq(self.output))
    }
}

pub struct MapSerializer<'a> {
    parent: &'a mut Serializer,
    keys: Vec<(Cow<'static, str>, _SerializerData)>,
    cur_key: String,
}

impl<'a> ser::SerializeMap for MapSerializer<'a> {
    type Ok = _SerializerData;
    type Error = crate::Error;

    fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
    {
        let val = key.serialize(&mut *self.parent)?;
        self.cur_key = val.as_str();
        Ok(())
    }

    fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
    {
        let val = value.serialize(&mut *self.parent)?;
        self.keys.push((self.cur_key.clone().into(), val));
        Ok(())
    }

    fn end(self) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::Struct {
            attrs: vec![],
            contents: self.keys.into_iter().map(|(k,v)| (Cow::from(k), v)).collect(),
        })
    }
}

pub struct StructSerializer<'a> {
    parent: &'a mut Serializer,
    attrs: Vec<(&'static str, String)>,
    keys: Vec<(&'static str, _SerializerData)>,
}

impl<'a> ser::SerializeStruct for StructSerializer<'a> {
    type Ok = _SerializerData;
    type Error = crate::Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
    {
        let val = value.serialize(&mut *self.parent)?;
        if key.starts_with("$attr:") {
            self.attrs.push((&key[6..], val.as_str()));
        } else {
            self.keys.push((key, val));
        }
        Ok(())
    }

    fn end(self) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::Struct {
            attrs: self.attrs.into_iter().map(|(k,v)| (k.into(), v)).collect(),
            contents: self.keys.into_iter().map(|(k,v)| (k.into(), v)).collect(),
        })
    }
}

pub struct StructVariantSerializer<'a> {
    parent: &'a mut Serializer,
    attrs: Vec<(Cow<'static, str>, String)>,
    keys: Vec<(Cow<'static, str>, _SerializerData)>,
    tag: String,
}

impl<'a> ser::SerializeStructVariant for StructVariantSerializer<'a> {
    type Ok = _SerializerData;
    type Error = crate::Error;

    fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
        where
            T: ?Sized + Serialize,
    {
        let val = value.serialize(&mut *self.parent)?;
        if key.starts_with("$attr:") {
            self.attrs.push((key[6..].into(), val.as_str()));
        } else {
            self.keys.push((key.into(), val));
        }
        Ok(())
    }

    fn end(self) -> Result<_SerializerData, Self::Error> {
        Ok(_SerializerData::Struct {
            attrs: vec![],
            contents: vec![(self.tag.into(), _SerializerData::Struct {
                attrs: self.attrs,
                contents: self.keys,
            })],
        })
    }
}
