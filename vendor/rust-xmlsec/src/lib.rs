#[macro_use]
extern crate serde_derive;

pub mod proto;
pub mod c14n;

#[inline]
pub fn x509_name_to_string(name: &openssl::x509::X509NameRef) -> String {
    name.entries()
        .map(|e| {
            format!("{}=\"{}\"",
                    e.object().nid().short_name().unwrap_or_default(),
                    match e.data().as_utf8() {
                        Ok(d) => d.to_string(),
                        Err(_) => String::new()
                    }
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[inline]
pub fn events_to_string(events: &[xml::reader::XmlEvent]) -> String {
    let mut output = Vec::new();
    let mut output_writer = xml::writer::EventWriter::new_with_config(
        &mut output,
        xml::writer::EmitterConfig {
            perform_indent: false,
            perform_escaping: false,
            write_document_declaration: true,
            autopad_comments: false,
            cdata_to_characters: true,
            line_separator: std::borrow::Cow::Borrowed("\n"),
            normalize_empty_elements: false,
            ..std::default::Default::default()
        },
    );

    for event in events {
        if let Some(e) = event.as_writer_event() {
            output_writer.write(e).unwrap();
        }
    }

    String::from_utf8_lossy(&output).to_string()
}

fn decode_key(key_info: &proto::ds::KeyInfo) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, String> {
    match key_info.keys_info.first() {
        Some(proto::ds::KeyInfoType::X509Data(x509data)) => {
            for x509_datum in &x509data.x509_data {
                match x509_datum {
                    proto::ds::X509Datum::Certificate(c) => {
                        let c_bin = match base64::decode_config(c.replace("\r", "").replace("\n", ""), base64::STANDARD_NO_PAD) {
                            Ok(d) => d,
                            Err(e) => {
                                return Err(format!("error decoding X509 cert: {}", e));
                            }
                        };
                        let key = match openssl::x509::X509::from_der(&c_bin) {
                            Ok(d) => d,
                            Err(e) => {
                                return Err(format!("error decoding X509 cert: {}", e));
                            }
                        };
                        let pkey = match key.public_key() {
                            Ok(d) => d,
                            Err(e) => {
                                return Err(format!("error decoding X509 cert: {}", e));
                            }
                        };
                        return Ok(pkey);
                    }
                    _ => {}
                }
            }
            Err(format!("unsupported key: {:?}", x509data))
        }
        k => {
            Err(format!("unsupported key: {:?}", k))
        }
    }
}

fn find_events_slice_by_id<'a>(events: &'a [xml::reader::XmlEvent], id: &str) -> Option<&'a [xml::reader::XmlEvent]> {
    let mut i = 0;
    let mut elm_i = events.len();
    let mut elm_end_i = elm_i;
    let mut elm_name = None;
    for evt in events {
        match evt {
            xml::reader::XmlEvent::StartElement {
                name, attributes, ..
            } => {
                let elm_id = attributes.iter()
                    .filter_map(|a|
                        if a.name.prefix.is_none() && a.name.namespace.is_none()
                            && a.name.local_name.to_lowercase() == "id" {
                            Some(&a.value)
                        } else {
                            None
                        }
                    ).next();
                if let Some(elm_id) = elm_id {
                    if elm_name.is_none() && elm_id == id {
                        elm_i = i;
                        elm_name = Some(name.clone());
                    }
                }
            }
            xml::reader::XmlEvent::EndElement {
                name, ..
            } => {
                if let Some(elm_name) = &elm_name {
                    if name == elm_name {
                        elm_end_i = i;
                        break;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    if elm_i == events.len() {
        return None;
    }

    Some(&events[elm_i..elm_end_i + 1])
}

fn find_signed_info<'a>(events: &'a [xml::reader::XmlEvent]) -> Option<&'a [xml::reader::XmlEvent]> {
    let mut i = 0;
    let mut elm_i = events.len();
    let mut elm_end_i = elm_i;
    let mut elm_name = None;
    for evt in events {
        match evt {
            xml::reader::XmlEvent::StartElement {
                name, ..
            } => {
                if elm_name.is_none() && name.namespace.as_deref() == Some("http://www.w3.org/2000/09/xmldsig#") && &name.local_name == "SignedInfo" {
                    elm_i = i;
                    elm_name = Some(name.clone());
                }
            }
            xml::reader::XmlEvent::EndElement {
                name, ..
            } => {
                if let Some(elm_name) = &elm_name {
                    if name == elm_name {
                        elm_end_i = i;
                        break;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    if elm_i == events.len() {
        return None;
    }

    Some(&events[elm_i..elm_end_i + 1])
}

enum InnerAlgorithmData<'a> {
    NodeSet(&'a [xml::reader::XmlEvent]),
    OctetStream(&'a str),
}

#[derive(Debug)]
enum AlgorithmData<'a> {
    NodeSet(&'a [xml::reader::XmlEvent]),
    OctetStream(&'a str),
    OwnedNodeSet(Vec<xml::reader::XmlEvent>),
    OwnedOctetStream(String),
}

impl<'a> AlgorithmData<'a> {
    fn into_inner_data(&'a self) -> InnerAlgorithmData<'a> {
        match self {
            AlgorithmData::NodeSet(n) => InnerAlgorithmData::NodeSet(n),
            AlgorithmData::OwnedNodeSet(n) => InnerAlgorithmData::NodeSet(n),
            AlgorithmData::OctetStream(o) => InnerAlgorithmData::OctetStream(o),
            AlgorithmData::OwnedOctetStream(o) => InnerAlgorithmData::OctetStream(o),
        }
    }
}

fn transform_canonical_xml_1_0<'a>(events: AlgorithmData<'a>) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for canonical XML 1.0".to_string())
    };

    let canon_output = c14n::canonical_rfc3076(events, false, 0, false)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_canonical_xml_1_0_with_comments<'a>(events: AlgorithmData<'a>) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for canonical XML 1.0 (with comments)".to_string())
    };

    let canon_output = c14n::canonical_rfc3076(events, true, 0, false)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_canonical_xml_1_1<'a>(events: AlgorithmData<'a>) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for canonical XML 1.1".to_string())
    };

    let canon_output = c14n::canonical_rfc3076(events, false, 0, false)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_canonical_xml_1_1_with_comments<'a>(events: AlgorithmData<'a>) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for canonical XML 1.1 (with comments)".to_string())
    };

    let canon_output = c14n::canonical_rfc3076(events, true, 0, false)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_exclusive_canonical_xml_1_0<'a>(events: AlgorithmData<'a>) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for exclusive canonical XML 1.0".to_string())
    };

    let canon_output = c14n::canonical_rfc3076(events, false, 0, true)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_exclusive_canonical_xml_1_0_with_comments<'a>(events: AlgorithmData<'a>) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for exclusive canonical XML 1.0 (with comments)".to_string())
    };

    let canon_output = c14n::canonical_rfc3076(events, true, 0, true)?;

    Ok(AlgorithmData::OwnedOctetStream(canon_output))
}

fn transform_enveloped_signature<'a>(events: AlgorithmData<'a>) -> Result<AlgorithmData, String> {
    let events = match events.into_inner_data() {
        InnerAlgorithmData::NodeSet(e) => e,
        _ => return Err("unsupported input format for envelopd signature transform".to_string())
    };

    let mut level = 0;
    let mut output = vec![];
    let mut should_output = true;

    for evt in events {
        match evt {
            xml::reader::XmlEvent::StartElement {
                name, attributes, namespace
            } => {
                level += 1;
                if level == 2 && name.namespace.as_deref() == Some("http://www.w3.org/2000/09/xmldsig#") && name.local_name == "Signature" {
                    should_output = false
                }
                if should_output {
                    output.push(xml::reader::XmlEvent::StartElement {
                        name: name.to_owned(),
                        attributes: attributes.to_vec(),
                        namespace: namespace.to_owned(),
                    });
                }
            }
            xml::reader::XmlEvent::EndElement {
                name
            } => {
                if should_output {
                    output.push(xml::reader::XmlEvent::EndElement {
                        name: name.to_owned(),
                    });
                }
                if level == 2 && name.namespace.as_deref() == Some("http://www.w3.org/2000/09/xmldsig#") && name.local_name == "Signature" {
                    should_output = true;
                }
                level -= 1;
            }
            e => {
                if should_output {
                    output.push(e.to_owned());
                }
            }
        }
    }

    Ok(AlgorithmData::OwnedNodeSet(output))
}

pub const DIGEST_SHA1: &'static str = "http://www.w3.org/2000/09/xmldsig#sha1";
pub const DIGEST_SHA256: &'static str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub const DIGEST_SH224: &'static str = "http://www.w3.org/2001/04/xmldsig-more#sha224";
pub const DIGEST_SHA384: &'static str = "http://www.w3.org/2001/04/xmldsig-more#sha384";
pub const DIGEST_SHA512: &'static str = "http://www.w3.org/2001/04/xmlenc#sha512";

pub const TRANSFORM_ENVELOPED_SIGNATURE: &'static str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

pub const CANONICAL_1_0: &'static str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
pub const CANONICAL_1_0_COMMENTS: &'static str = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments";
pub const CANONICAL_1_1: &'static str = "http://www.w3.org/2006/10/xml-c14n11";
pub const CANONICAL_1_1_COMMENTS: &'static str = "http://www.w3.org/2006/10/xml-c14n11#WithComments";
pub const CANONICAL_EXCLUSIVE_1_0: &'static str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub const CANONICAL_EXCLUSIVE_1_0_COMMENTS: &'static str = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments";

pub const SIGNATURE_RSA_MD5: &'static str = "http://www.w3.org/2001/04/xmldsig-more#rsa-md5";
pub const SIGNATURE_RSA_SHA1: &'static str = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
pub const SIGNATURE_RSA_SHA224: &'static str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224";
pub const SIGNATURE_RSA_SHA256: &'static str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub const SIGNATURE_RSA_SHA384: &'static str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";
pub const SIGNATURE_RSA_SHA512: &'static str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";
pub const SIGNATURE_RSA_RIPEMD160: &'static str = "http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160";
pub const SIGNATURE_ECDSA_SHA1: &'static str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1";
pub const SIGNATURE_ECDSA_SHA224: &'static str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224";
pub const SIGNATURE_ECDSA_SHA256: &'static str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";
pub const SIGNATURE_ECDSA_SHA384: &'static str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384";
pub const SIGNATURE_ECDSA_SHA512: &'static str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512";
pub const SIGNATURE_ECDSA_RIPEMD160: &'static str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-ripemd160";
pub const SIGNATURE_DSA_SHA1: &'static str = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
pub const SIGNATURE_DSA_SHA256: &'static str = "http://www.w3.org/2009/xmldsig11#dsa-sha256";

fn apply_transforms<'a>(reference: &proto::ds::Reference, mut signed_data: AlgorithmData<'a>) -> Result<String, String> {
    if let Some(transforms) = &reference.transforms {
        for transform in &transforms.transforms {
            match transform.algorithm.as_str() {
                TRANSFORM_ENVELOPED_SIGNATURE => {
                    signed_data = transform_enveloped_signature(signed_data)?;
                }
                CANONICAL_1_0 => {
                    signed_data = transform_canonical_xml_1_0(signed_data)?;
                }
                CANONICAL_1_0_COMMENTS => {
                    signed_data = transform_canonical_xml_1_0_with_comments(signed_data)?;
                }
                CANONICAL_1_1 => {
                    signed_data = transform_canonical_xml_1_1(signed_data)?;
                }
                CANONICAL_1_1_COMMENTS => {
                    signed_data = transform_canonical_xml_1_1_with_comments(signed_data)?;
                }
                CANONICAL_EXCLUSIVE_1_0 => {
                    signed_data = transform_exclusive_canonical_xml_1_0(signed_data)?;
                }
                CANONICAL_EXCLUSIVE_1_0_COMMENTS => {
                    signed_data = transform_exclusive_canonical_xml_1_0_with_comments(signed_data)?;
                }
                u => {
                    return Err(format!("unsupported transformation: {}", u));
                }
            }
        }
    }

    Ok(match signed_data.into_inner_data() {
        InnerAlgorithmData::OctetStream(o) => o.to_string(),
        _ => return Err("transforms did not output octet stream".to_string())
    })
}

fn map_digest(dm: &proto::ds::DigestMethod) -> Result<openssl::hash::MessageDigest, String> {
    match dm.algorithm.as_str() {
        DIGEST_SHA1 => Ok(openssl::hash::MessageDigest::sha1()),
        DIGEST_SHA256 => Ok(openssl::hash::MessageDigest::sha256()),
        DIGEST_SH224 => Ok(openssl::hash::MessageDigest::sha224()),
        DIGEST_SHA384 => Ok(openssl::hash::MessageDigest::sha384()),
        DIGEST_SHA512 => Ok(openssl::hash::MessageDigest::sha512()),
        u => {
            return Err(format!("unsupported digest: {}", u));
        }
    }
}

fn verify_signature(sm: &proto::ds::SignatureMethod, pkey: &openssl::pkey::PKeyRef<openssl::pkey::Public>, sig: &[u8], data: &[u8]) -> bool {
    let dm = match sm.algorithm.as_str() {
        SIGNATURE_RSA_MD5 => {
            if pkey.rsa().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::md5()
        }
        SIGNATURE_RSA_SHA1 => {
            if pkey.rsa().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha1()
        }
        SIGNATURE_RSA_SHA224 => {
            if pkey.rsa().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha224()
        }
        SIGNATURE_RSA_SHA256 => {
            if pkey.rsa().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha256()
        }
        SIGNATURE_RSA_SHA384 => {
            if pkey.rsa().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha384()
        }
        SIGNATURE_RSA_SHA512 => {
            if pkey.rsa().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha512()
        }
        SIGNATURE_RSA_RIPEMD160 => {
            if pkey.rsa().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::ripemd160()
        }
        SIGNATURE_ECDSA_SHA1 => {
            if pkey.ec_key().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha1()
        }
        SIGNATURE_ECDSA_SHA224 => {
            if pkey.ec_key().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha224()
        }
        SIGNATURE_ECDSA_SHA256 => {
            if pkey.ec_key().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha256()
        }
        SIGNATURE_ECDSA_SHA384 => {
            if pkey.ec_key().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha384()
        }
        SIGNATURE_ECDSA_SHA512 => {
            if pkey.ec_key().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha512()
        }
        SIGNATURE_ECDSA_RIPEMD160 => {
            if pkey.ec_key().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::ripemd160()
        }
        SIGNATURE_DSA_SHA1 => {
            if pkey.dsa().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha1()
        }
        SIGNATURE_DSA_SHA256 => {
            if pkey.dsa().is_err() {
                return false;
            }
            openssl::hash::MessageDigest::sha256()
        }
        _ => return false
    };

    let mut verifier = match openssl::sign::Verifier::new(
        dm, pkey,
    ) {
        Ok(v) => v,
        Err(_) => return false
    };

    match verifier.verify_oneshot(sig, data) {
        Ok(v) => v,
        Err(_) => false
    }
}

#[derive(Debug)]
pub enum Output {
    Verified {
        references: Vec<String>,
        pkey: openssl::pkey::PKey<openssl::pkey::Public>,
    },
    Unsigned(String),
}

pub fn decode_and_verify_signed_document(source_xml: &str) -> Result<Output, String> {
    let reader = xml::reader::EventReader::new_with_config(
        source_xml.as_bytes(),
        xml::ParserConfig::new()
            .ignore_comments(false)
            .trim_whitespace(false)
            .coalesce_characters(false)
            .ignore_root_level_whitespace(true),
    ).into_iter().collect::<Result<Vec<_>, _>>().map_err(|e| format!("unable to decode XML: {}", e))?;

    let mut i = 0;
    let mut level = 0;
    let mut seen_level = reader.len();
    let mut sig_i = seen_level;
    let mut sig_end_i = seen_level;
    for evt in &reader {
        match evt {
            xml::reader::XmlEvent::StartElement {
                name, ..
            } => {
                level += 1;
                if level < seen_level && name.namespace.as_deref() == Some("http://www.w3.org/2000/09/xmldsig#") && &name.local_name == "Signature" {
                    seen_level = level;
                    sig_i = i;
                }
            }
            xml::reader::XmlEvent::EndElement {
                name, ..
            } => {
                if level == seen_level && name.namespace.as_deref() == Some("http://www.w3.org/2000/09/xmldsig#") && &name.local_name == "Signature" {
                    seen_level = level;
                    sig_end_i = i;
                }
                level -= 1;
            }
            _ => {}
        }
        i += 1;
    }

    if sig_i == reader.len() {
        return Ok(Output::Unsigned(source_xml.to_string()));
    }

    let sig_elems = reader[sig_i..sig_end_i + 1].iter().map(|e| xml::reader::Result::Ok(e.to_owned())).collect::<Vec<_>>();
    let sig: proto::ds::OuterSignatre = match xml_serde::from_events(sig_elems.as_slice()) {
        Ok(s) => s,
        Err(e) => return Err(format!("unable to decode XML signature: {}", e))
    };

    let mut verified_outputs = vec![];

    for reference in &sig.signature.signed_info.reference {
        let u = reference.uri.as_deref().unwrap_or_default();
        let signed_data = apply_transforms(reference, AlgorithmData::NodeSet(if u == "" {
            reader.as_slice()
        } else if u.starts_with("#") {
            match find_events_slice_by_id(&reader, &u[1..]) {
                Some(e) => e,
                None => return Err(format!("unable to find signed element: {}", u))
            }
        } else {
            return Err(format!("unsupported reference URI: {}", u));
        }))?;

        let provided_digest = match base64::decode(&reference.digest_value) {
            Ok(d) => d,
            Err(e) => {
                return Err(format!("invalid disest base64: {}", e));
            }
        };

        let dm = map_digest(&reference.digest_method)?;
        let digest = match openssl::hash::hash(dm, signed_data.as_bytes()) {
            Ok(d) => d,
            Err(e) => {
                return Err(format!("openssl error: {}", e));
            }
        };

        if digest.as_ref() != provided_digest {
            return Err("digest does not match".to_string());
        }

        verified_outputs.push(signed_data);
    }

    let signed_info_events = AlgorithmData::NodeSet(find_signed_info(&reader[sig_i..sig_end_i + 1]).unwrap());
    let signed_info_data = match match sig.signature.signed_info.canonicalization_method.algorithm.as_str() {
        CANONICAL_1_0 => {
            transform_canonical_xml_1_0(signed_info_events)?
        }
        CANONICAL_1_0_COMMENTS => {
            transform_canonical_xml_1_0_with_comments(signed_info_events)?
        }
        CANONICAL_1_1 => {
            transform_canonical_xml_1_1(signed_info_events)?
        }
        CANONICAL_1_1_COMMENTS => {
            transform_canonical_xml_1_1_with_comments(signed_info_events)?
        }
        CANONICAL_EXCLUSIVE_1_0 => {
            transform_exclusive_canonical_xml_1_0(signed_info_events)?
        }
        CANONICAL_EXCLUSIVE_1_0_COMMENTS => {
            transform_exclusive_canonical_xml_1_0_with_comments(signed_info_events)?
        }
        u => return Err(format!("unsupported canonicalisation method: {}", u))
    }.into_inner_data() {
        InnerAlgorithmData::OctetStream(o) => o.to_string(),
        _ => unreachable!()
    };

    let pkey = if let Some(ki) = &sig.signature.key_info {
        decode_key(ki)?
    } else {
        return Err("key info not specified".to_string());
    };

    let sig_data = match base64::decode(
        &sig.signature.signature_value.value.replace("\r", "").replace("\n", "")
    ) {
        Ok(s) => s,
        Err(e) => {
            return Err(format!("error decoding signature: {}", e));
        }
    };

    if !verify_signature(
        &sig.signature.signed_info.signature_method,
        &pkey,
        &sig_data,
        signed_info_data.as_bytes(),
    ) {
        return Err("signature does not verify".to_string());
    }

    Ok(Output::Verified {
        references: verified_outputs,
        pkey,
    })
}

pub fn sign_document(
    events: &[xml::reader::XmlEvent],
    pub_key: &openssl::x509::X509Ref,
    priv_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> Result<String, String> {
    let pub_pkey = match pub_key.public_key() {
        Ok(d) => d,
        Err(e) => {
            return Err(format!("openssl error: {}", e));
        }
    };
    if !priv_key.public_eq(&pub_pkey) {
        return Err("public and private key don't match".to_string());
    }

    let canonicalisied_events = match transform_exclusive_canonical_xml_1_0(AlgorithmData::NodeSet(events))?.into_inner_data() {
        InnerAlgorithmData::OctetStream(s) => s.to_string(),
        _ => unreachable!()
    };

    let digest = match openssl::hash::hash(openssl::hash::MessageDigest::sha256(), canonicalisied_events.as_bytes()) {
        Ok(d) => d,
        Err(e) => {
            return Err(format!("openssl error: {}", e));
        }
    };

    let reference = proto::ds::Reference {
        transforms: Some(proto::ds::Transforms {
            transforms: vec![proto::ds::Transform {
                algorithm: TRANSFORM_ENVELOPED_SIGNATURE.to_string(),
            }, proto::ds::Transform {
                algorithm: CANONICAL_EXCLUSIVE_1_0.to_string(),
            }]
        }),
        digest_method: proto::ds::DigestMethod {
            algorithm: DIGEST_SHA256.to_string()
        },
        digest_value: base64::encode(digest),
        id: None,
        uri: Some("".to_string()),
        ref_type: None,
    };

    let key_format = priv_key.id();
    let (signature_method, digest_method) = match key_format {
        openssl::pkey::Id::RSA => (SIGNATURE_RSA_SHA256, openssl::hash::MessageDigest::sha256()),
        openssl::pkey::Id::DSA => (SIGNATURE_DSA_SHA256, openssl::hash::MessageDigest::sha256()),
        openssl::pkey::Id::EC => (SIGNATURE_ECDSA_SHA512, openssl::hash::MessageDigest::sha512()),
        f => return Err(format!("unsupported key format {:?}", f))
    };

    let signed_info = proto::ds::SignedInfo {
        id: None,
        canonicalization_method: proto::ds::CanonicalizationMethod {
            algorithm: CANONICAL_EXCLUSIVE_1_0.to_string()
        },
        signature_method: proto::ds::SignatureMethod {
            algorithm: signature_method.to_string()
        },
        reference: vec![reference],
    };

    let signed_info_events = xml_serde::to_events(&signed_info).unwrap();
    let canonicalisied_signed_info_events = match transform_exclusive_canonical_xml_1_0(AlgorithmData::NodeSet(&signed_info_events))?.into_inner_data() {
        InnerAlgorithmData::OctetStream(s) => s.to_string(),
        _ => unreachable!()
    };

    let mut signer = match openssl::sign::Signer::new(digest_method, priv_key) {
        Ok(d) => d,
        Err(e) => {
            return Err(format!("openssl error: {}", e));
        }
    };

    if let Err(e) = signer.update(canonicalisied_signed_info_events.as_bytes()) {
        return Err(format!("openssl error: {}", e));
    }

    let signature = match signer.sign_to_vec() {
        Ok(d) => d,
        Err(e) => {
            return Err(format!("openssl error: {}", e));
        }
    };

    let signature = proto::ds::OuterSignatre {
        signature: proto::ds::Signature {
            signed_info: signed_info,
            signature_value: proto::ds::SignatureValue {
                value: base64::encode(&signature),
                id: None,
            },
            key_info: Some(proto::ds::KeyInfo {
                keys_info: vec![proto::ds::KeyInfoType::X509Data(proto::ds::X509Data {
                    x509_data: vec![proto::ds::X509Datum::SubjectName(
                        x509_name_to_string(pub_key.subject_name())
                    ), proto::ds::X509Datum::Certificate(
                        base64::encode(pub_key.to_der().unwrap())
                    )]
                })]
            }),
        }
    };

    let signature_events = xml_serde::to_events(&signature).unwrap();

    let start_i = match events
        .iter()
        .enumerate()
        .find_map(|(i, e)| if matches!(e, xml::reader::XmlEvent::StartElement { .. }) {
            Some(i)
        } else {
            None
        }) {
        Some(i) => i + 1,
        None => return Ok("".to_string())
    };

    let mut final_events = vec![];
    final_events.extend_from_slice(&events[..start_i]);
    final_events.extend(signature_events.into_iter());
    final_events.extend_from_slice(&events[start_i..]);

    Ok(events_to_string(&final_events))
}

#[cfg(test)]
mod tests {
    #[test]
    fn sig_1() {
        pretty_env_logger::init();

        let source_xml = r##"<?xml version="1.0" encoding="UTF-8" standalone="no"?><saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://as207960-neptune.eu.ngrok.io/saml2/assertion_consumer" ID="_63e92115c9dbe3c22e06a6f3c311392b" InResponseTo="test" IssueInstant="2021-07-29T12:34:42.465Z" Version="2.0"><saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://accounts.google.com/o/saml2?idpid=C01n8o8t6</saml2:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:Reference URI="#_63e92115c9dbe3c22e06a6f3c311392b"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>HH+SiZfyXcyu7bSW7HzeR42JaHaAeACAkFIFK4X10LI=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>X7NJmvYyYpqqxdl2CUbI55a23BuekWiqJmLbLAzNR0IQfMZ2xCJf2Dcs3XWD0VEvtE1Mhrw905lK
xoQ6IoUDo09bc5Om7ECE48V1MG90+Ds0fNKwGl+bXJp7/64H2qA1wucBfo1q4MrXpN15Z4tITLv7
d1MI+4zeKtalCJflY0gmTrt1GjJ65mz2gUxLvNBnbzt6yfngqvQs1XcBL0Coot+YMJZeUmvPrYbT
zWFYlDdxp79AjG0pM/IcDul0PxKwSctSaGaGxEmz1oJnrkw5EDvRBPdwhKm1e1sUXr/aCOzH1GYm
fq2E4zhhTCjsvIW8zyH7ABk64+7w28rNmK/suw==</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509SubjectName>ST=California,C=US,OU=Google For Work,CN=Google,L=Mountain View,O=Google Inc.</ds:X509SubjectName><ds:X509Certificate>MIIDdDCCAlygAwIBAgIGAXI4fvJmMA0GCSqGSIb3DQEBCwUAMHsxFDASBgNVBAoTC0dvb2dsZSBJ
bmMuMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ8wDQYDVQQDEwZHb29nbGUxGDAWBgNVBAsTD0dv
b2dsZSBGb3IgV29yazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEwHhcNMjAwNTIx
MTgyOTAxWhcNMjUwNTIwMTgyOTAxWjB7MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEWMBQGA1UEBxMN
TW91bnRhaW4gVmlldzEPMA0GA1UEAxMGR29vZ2xlMRgwFgYDVQQLEw9Hb29nbGUgRm9yIFdvcmsx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEA399ymOjRthGk6J0whLP4GfxnkWXp8jL8ywpftyymO3k82zXSVZWXQEin1BbUiU1g
iG+93pTu1s2cSFTPyGOpNqUPYwMfP2NPJPvN9AQKZq6tDWWP/KyvQumcmmK2nFezHqGvRLZDGOqM
HjGq/XzwQSXX7eRGkexrKXvKOOhRUAgRmmZvrNqXmMpthj4S55uAP88814z96fMDnvP4U0qvN7zS
MtA/aD/C8YcliSvBS1gA9EIYeklc8gL0btIxPHRY2tViU3TRq/Nl6OGee5n3oz1e9pG7Aj5klDYu
uUaLXo9quzi8g8jcgnX5roPhnvtSkPbsRdGPq3YqDF8+Rq/wBwIDAQABMA0GCSqGSIb3DQEBCwUA
A4IBAQBw42j9N6/1vEsxK4WTavsLuQzcuHomP4JiHIps31sThyKTolnu8v6J7ArznDUZz2k/PUqA
Bi+gsU5C1/fibcbQ6xL8/TMlC3Rnwl33naWjph1pgfHU58zegSQB9nSvFtqIJqu5vdeLBbkX8+Ez
PxqqTMVahAuXBHdDexvSk3tLpxbzhgfTYS4aGbGKTamnhkby66S9Ct1ugrWXg5xzNFDHMBkg6d+w
kO9N4axmKDI4W6XWtxTRifLySfnklNqn20MEF1PstW18lwkKCAninmVorqil5MKoXKjuFrBJv06u
3JTAEGYtBo4aAIrQFJlAIEUV4H0jbYAKo+drHEA86yqE</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml2p:Status><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_3381066a8dfd537274b2f43fea8bec4c" IssueInstant="2021-07-29T12:34:42.465Z" Version="2.0"><saml2:Issuer>https://accounts.google.com/o/saml2?idpid=C01n8o8t6</saml2:Issuer><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">q@as207960.net</saml2:NameID><saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml2:SubjectConfirmationData InResponseTo="test" NotOnOrAfter="2021-07-29T12:39:42.465Z" Recipient="https://as207960-neptune.eu.ngrok.io/saml2/assertion_consumer"/></saml2:SubjectConfirmation></saml2:Subject><saml2:Conditions NotBefore="2021-07-29T12:29:42.465Z" NotOnOrAfter="2021-07-29T12:39:42.465Z"><saml2:AudienceRestriction><saml2:Audience>https://neptune.as207960.net/entity</saml2:Audience></saml2:AudienceRestriction></saml2:Conditions><saml2:AuthnStatement AuthnInstant="2021-07-28T21:51:07.000Z" SessionIndex="_3381066a8dfd537274b2f43fea8bec4c"><saml2:AuthnContext><saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef></saml2:AuthnContext></saml2:AuthnStatement></saml2:Assertion></saml2p:Response>"##;

        let verified = super::decode_and_verify_signed_document(source_xml).unwrap();
        println!("{:#?}", verified);
        assert_eq!(verified.references.len(), 1);
    }
}
