fn canon_attr_map<'a>(a: &'a xml::attribute::OwnedAttribute) -> (xml::name::Name<'a>, String) {
    let attribute_re = regex::Regex::new(r"[ \r\n\t]").unwrap();

    (
        a.name.borrow(),
        attribute_re
            .replace_all(&a.value, " ")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace("\"", "&quot;")
            .replace("\r", "&#xD;")
    )
}

pub fn canonical_rfc3076(events: &[xml::reader::XmlEvent], include_comments: bool, offset: usize, exclusive: bool) -> Result<String, String> {
    let mut output = Vec::new();
    let mut output_writer = xml::writer::EventWriter::new_with_config(
        &mut output,
        xml::writer::EmitterConfig {
            perform_indent: false,
            perform_escaping: false,
            write_document_declaration: false,
            autopad_comments: false,
            cdata_to_characters: true,
            line_separator: std::borrow::Cow::Borrowed("\n"),
            normalize_empty_elements: false,
            ..std::default::Default::default()
        },
    );

    let mut level: usize = 0;
    let mut xml_ns_attrs = vec![];
    let mut exc_ns_stack = xml::namespace::NamespaceStack::default();
    for (i, event) in events.iter().enumerate() {
        match match event {
            xml::reader::XmlEvent::StartDocument { .. } => Ok(()),
            xml::reader::XmlEvent::EndDocument { .. } => Ok(()),
            xml::reader::XmlEvent::ProcessingInstruction {
                name, data
            } => {
                if i >= offset {
                    output_writer.write(xml::writer::XmlEvent::ProcessingInstruction {
                        name,
                        data: data.as_deref(),
                    })
                } else {
                    Ok(())
                }
            }
            xml::reader::XmlEvent::StartElement {
                name, attributes, namespace
            } => {
                let new_xms_ns_attrs =
                    attributes
                        .iter()
                        .filter(|a| a.name.namespace.as_deref() == Some("http://www.w3.org/XML/1998/namespace"))
                        .collect::<Vec<_>>();
                let cur_xml_ns_attrs = xml_ns_attrs.clone();
                xml_ns_attrs.push(new_xms_ns_attrs);

                if i >= offset {
                    level += 1;

                    let attribute_prefixes = attributes.iter().map(|a| a.name.prefix.as_deref()).collect::<Vec<_>>();
                    exc_ns_stack.push_empty();
                    exc_ns_stack.extend(namespace.0.iter().filter(|n| {
                        name.prefix.as_deref() == Some(&n.0) || attribute_prefixes.contains(&Some(n.1))
                    }).map(|n| (n.0.as_str(), n.1.as_str())).collect::<Vec<_>>());

                    let mut mapped_attr = if i == offset && !exclusive {
                        let existing_xms_ns_attrs = attributes.iter().filter_map(|a| if a.name.namespace.as_deref() == Some("http://www.w3.org/XML/1998/namespace") {
                            Some(a.name.local_name.clone())
                        } else {
                            None
                        }).collect::<Vec<_>>();
                        attributes.iter().chain(
                            cur_xml_ns_attrs.iter().flatten()
                                .filter(|a| !existing_xms_ns_attrs.contains(&a.name.local_name))
                                .map(|a| *a)
                        ).map(canon_attr_map).collect()
                    } else {
                        attributes.iter().map(canon_attr_map).collect::<Vec<_>>()
                    };
                    mapped_attr.sort_by(|a, b| {
                        match (a.0.prefix, b.0.prefix) {
                            (None, None) => {
                                a.0.local_name.cmp(b.0.local_name)
                            }
                            (None, Some(_)) => {
                                std::cmp::Ordering::Less
                            }
                            (Some(_), Some(_)) => {
                                let a_ns = a.0.namespace.unwrap_or_default();
                                let b_ns = b.0.namespace.unwrap_or_default();
                                if a_ns == b_ns {
                                    a.0.local_name.cmp(b.0.local_name)
                                } else {
                                    a_ns.cmp(b_ns)
                                }
                            }
                            (Some(_), None) => {
                                std::cmp::Ordering::Greater
                            }
                        }
                    });
                    output_writer.write(xml::writer::XmlEvent::StartElement {
                        name: name.borrow(),
                        attributes: mapped_attr.iter().map(|a| xml::attribute::Attribute {
                            name: a.0,
                            value: &a.1,
                        }).collect(),
                        namespace: if exclusive {
                            std::borrow::Cow::Owned(exc_ns_stack.squash())
                        } else {
                            std::borrow::Cow::Borrowed(&namespace)
                        },
                    })
                } else {
                    Ok(())
                }
            }
            xml::reader::XmlEvent::EndElement {
                name
            } => {
                xml_ns_attrs.pop();

                if i >= offset {
                    level -= 1;

                    exc_ns_stack.try_pop();

                    match output_writer.write(xml::writer::XmlEvent::EndElement {
                        name: Some(name.borrow()),
                    }) {
                        Ok(_) => {
                            if level == 0 {
                                break;
                            }
                            Ok(())
                        }
                        Err(e) => Err(e)
                    }
                } else {
                    Ok(())
                }
            }
            xml::reader::XmlEvent::CData(data) => {
                if i >= offset {
                    output_writer.write(xml::writer::XmlEvent::Characters(
                        &data
                            .replace("\r\n", "\n")
                            .replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\r", "&#xD;")
                    ))
                } else {
                    Ok(())
                }
            }
            xml::reader::XmlEvent::Comment(data) => {
                if i >= offset && include_comments {
                    output_writer.write(xml::writer::XmlEvent::Comment(
                        &data.replace("\r\n", "\n")
                    ))
                } else {
                    Ok(())
                }
            }
            xml::reader::XmlEvent::Whitespace(data) => {
                if i >= offset && include_comments {
                    output_writer.write(xml::writer::XmlEvent::Characters(
                        &data.replace("\r\n", "\n")
                    ))
                } else {
                    Ok(())
                }
            }
            xml::reader::XmlEvent::Characters(data) => {
                if i >= offset {
                    output_writer.write(xml::writer::XmlEvent::Characters(
                        &data
                            .replace("\r\n", "\n")
                            .replace("&", "&amp;")
                            .replace("<", "&lt;")
                            .replace(">", "&gt;")
                            .replace("\r", "&#xD;")
                    ))
                } else {
                    Ok(())
                }
            }
        } {
            Ok(_) => {}
            Err(e) => return Err(e.to_string())
        }
    }

    Ok(String::from_utf8_lossy(&output).to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn c14n_1() {
        let source_xml = r#"
<?xml version="1.0" encoding="ISO-8859-1"?>

<Envelope>
<!-- some comment -->
  <Body>
    Olá mundo
  </Body>

</Envelope>
"#;
        let canon_xml = r#"<Envelope>

  <Body>
    Olá mundo
  </Body>

</Envelope>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        let canon = super::canonical_rfc3076(&reader, false, 0, false).unwrap();
        assert_eq!(canon, canon_xml);
    }

    #[test]
    fn c14n_2() {
        let source_xml = r#"<DigestMethod Algorithm="http:...#sha1" />"#;
        let canon_xml = r#"<DigestMethod Algorithm="http:...#sha1"></DigestMethod>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        let canon = super::canonical_rfc3076(&reader, false, 0, false).unwrap();
        assert_eq!(canon, canon_xml);
    }

    #[test]
    fn c14n_3() {
        let source_xml = r#"<e1   a='one'
  b  = 'two'  />"#;
        let canon_xml = r#"<e1 a="one" b="two"></e1>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        let canon = super::canonical_rfc3076(&reader, false, 0, false).unwrap();
        assert_eq!(canon, canon_xml);
    }

    #[test]
    fn c14n_4() {
        let source_xml = r#"<e2 C=' letter
	A ' />"#;
        let canon_xml = r#"<e2 C=" letter  A "></e2>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        let canon = super::canonical_rfc3076(&reader, false, 0, false).unwrap();
        assert_eq!(canon, canon_xml);
    }

    #[test]
    fn c14n_5() {
        let source_xml = r#"<e b:attr="sorted" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all"  a:attr="out" a:attr2="now" xmlns="http://example.org" xmlns:a="http://www.w3.org" ></e>"#;
        let canon_xml = r#"<e xmlns="http://example.org" xmlns:a="http://www.w3.org" xmlns:b="http://www.ietf.org" attr="I'm" attr2="all" b:attr="sorted" a:attr="out" a:attr2="now"></e>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();
        let canon = super::canonical_rfc3076(&reader, false, 0, false).unwrap();
        assert_eq!(canon, canon_xml);
    }

    #[test]
    fn c14n_6() {
        let source_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://www.example.com">
  <Part xmlns:ab="http://www.ab.com">
    <Doc Id="P666">
    ...
    </Doc>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
      <SignedInfo>
        <Reference URI="P666" />
      </SignedInfo>
      ...
    </Signature>
  </Part>
</Envelope>"#;
        let canon_xml = r#"<Doc xmlns="http://www.example.com" xmlns:ab="http://www.ab.com" Id="P666">
    ...
    </Doc>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();

        let mut i = 0;
        for evt in &reader {
            if let xml::reader::XmlEvent::StartElement {
                name, ..
            } = evt {
                if name.local_name == "Doc" {
                    break;
                }
            }
            i += 1;
        }

        let canon = super::canonical_rfc3076(&reader, false, i, false).unwrap();
        assert_eq!(canon, canon_xml);
    }

    #[test]
    fn c14n_7() {
        let source_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
      <n0:local xmlns:n0="foo:bar"
                xmlns:n3="ftp://example.org">
         <n1:elem2 xmlns:n1="http://example.net"
                   xml:lang="en">
             <n3:stuff xmlns:n3="ftp://example.org"/>
         </n1:elem2>
      </n0:local>"#;
        let canon_xml = r#"<n1:elem2 xmlns:n0="foo:bar" xmlns:n1="http://example.net" xmlns:n3="ftp://example.org" xml:lang="en">
             <n3:stuff></n3:stuff>
         </n1:elem2>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();

        let mut i = 0;
        for evt in &reader {
            if let xml::reader::XmlEvent::StartElement {
                name, ..
            } = evt {
                if name.local_name == "elem2" {
                    break;
                }
            }
            i += 1;
        }

        let canon = super::canonical_rfc3076(&reader, false, i, false).unwrap();
        assert_eq!(canon, canon_xml);
    }

    #[test]
    fn c14n_8() {
        let source_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
      <n2:pdu xmlns:n1="http://example.com"
              xmlns:n2="http://foo.example"
              xml:lang="fr"
              xml:space="retain">

         <n1:elem2 xmlns:n1="http://example.net"
                   xml:lang="en">
             <n3:stuff xmlns:n3="ftp://example.org"/>
         </n1:elem2>
      </n2:pdu>"#;
        let canon_xml = r#"<n1:elem2 xmlns:n1="http://example.net" xmlns:n2="http://foo.example" xml:lang="en" xml:space="retain">
             <n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>
         </n1:elem2>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();

        let mut i = 0;
        for evt in &reader {
            if let xml::reader::XmlEvent::StartElement {
                name, ..
            } = evt {
                if name.local_name == "elem2" {
                    break;
                }
            }
            i += 1;
        }

        let canon = super::canonical_rfc3076(&reader, false, i, false).unwrap();
        assert_eq!(canon, canon_xml);
    }

    #[test]
    fn c14n_9() {
        let source_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
      <n0:local xmlns:n0="foo:bar"
                xmlns:n3="ftp://example.org">
         <n1:elem2 xmlns:n1="http://example.net"
                   xml:lang="en">
             <n3:stuff xmlns:n3="ftp://example.org"/>
         </n1:elem2>
      </n0:local>"#;
        let canon_xml = r#"<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
             <n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>
         </n1:elem2>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();

        let mut i = 0;
        for evt in &reader {
            if let xml::reader::XmlEvent::StartElement {
                name, ..
            } = evt {
                if name.local_name == "elem2" {
                    break;
                }
            }
            i += 1;
        }

        let canon = super::canonical_rfc3076(&reader, false, i, true).unwrap();
        assert_eq!(canon, canon_xml);
    }

    #[test]
    fn c14n_10() {
        let source_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
      <n2:pdu xmlns:n1="http://example.com"
              xmlns:n2="http://foo.example"
              xml:lang="fr"
              xml:space="retain">

         <n1:elem2 xmlns:n1="http://example.net"
                   xml:lang="en">
             <n3:stuff xmlns:n3="ftp://example.org"/>
         </n1:elem2>
      </n2:pdu>"#;
        let canon_xml = r#"<n1:elem2 xmlns:n1="http://example.net" xml:lang="en">
             <n3:stuff xmlns:n3="ftp://example.org"></n3:stuff>
         </n1:elem2>"#;
        let reader = xml::reader::EventReader::new_with_config(
            source_xml.as_bytes(),
            xml::ParserConfig::new()
                .ignore_comments(false)
                .trim_whitespace(false)
                .coalesce_characters(false)
                .ignore_root_level_whitespace(true),
        ).into_iter().collect::<Result<Vec<_>, _>>().unwrap();

        let mut i = 0;
        for evt in &reader {
            if let xml::reader::XmlEvent::StartElement {
                name, ..
            } = evt {
                if name.local_name == "elem2" {
                    break;
                }
            }
            i += 1;
        }

        let canon = super::canonical_rfc3076(&reader, false, i, true).unwrap();
        assert_eq!(canon, canon_xml);
    }
}
