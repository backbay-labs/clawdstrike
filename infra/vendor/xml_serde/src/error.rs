#[derive(Debug)]
pub enum Error {
    XMLWError(xml::writer::Error),
    XMLRError(xml::reader::Error),
    Message(String),
    ExpectedString,
    ExpectedChar,
    ExpectedBool,
    ExpectedInt,
    ExpectedElement,
    Unsupported
}

pub type Result<T> = std::result::Result<T, Error>;

impl serde::ser::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl serde::de::Error for Error {
    fn custom<T: std::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Message(msg) => formatter.write_str(msg),
            Error::XMLWError(err) => formatter.write_str(&err.to_string()),
            Error::XMLRError(err) => formatter.write_str(&err.to_string()),
            Error::ExpectedString => formatter.write_str("expected a string"),
            Error::ExpectedChar => formatter.write_str("expected a char"),
            Error::ExpectedBool => formatter.write_str("expected a bool"),
            Error::ExpectedInt => formatter.write_str("expected a number"),
            Error::ExpectedElement => formatter.write_str("expected an element"),
            Error::Unsupported => formatter.write_str("unsupported operation"),
        }
    }
}

impl std::error::Error for Error {}

impl From<xml::writer::Error> for Error {
    fn from(err: xml::writer::Error) -> Self {
        Error::XMLWError(err)
    }
}

impl From<xml::reader::Error> for Error {
    fn from(err: xml::reader::Error) -> Self {
        Error::XMLRError(err)
    }
}

impl From<&xml::reader::Error> for Error {
    fn from(err: &xml::reader::Error) -> Self {
        Error::XMLRError(err.clone())
    }
}