#[allow(unused_imports)]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
extern crate core;

mod de;
mod ser;
mod error;
mod tag;

pub(crate) use tag::Tag;

pub use ser::{to_string, to_string_custom, to_events, to_events_custom, Serializer, Options};
pub use de::{from_str, from_string, from_events, Deserializer};
pub use error::{Error, Result};

#[cfg(test)]
mod tests {

    #[derive(Debug, Serialize, Deserialize)]
    pub enum EPPMessageType {
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}hello", skip_deserializing)]
        Hello {},
        // #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}greeting", skip_serializing)]
        // Greeting(EPPGreeting),
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}command", skip_deserializing)]
        Command(EPPCommand),
        // #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}response", skip_serializing)]
        // Response(EPPResponse),
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EPPMessage {
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}epp")]
        pub message: EPPMessageType,
    }


    #[derive(Debug, Serialize)]
    pub struct EPPCommand {
        #[serde(rename = "$valueRaw")]
        pub command: String,
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}clTRID", skip_serializing_if = "Option::is_none")]
        pub client_transaction_id: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub enum EPPCommandType {
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}login")]
        Login(EPPLogin),
    }

    #[derive(Debug, Serialize)]
    pub struct EPPLogin {
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}clID")]
        pub client_id: String,
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}pw")]
        pub password: String,
        #[serde(rename = "$attr:{http://www.w3.org/2001/XMLSchema-instance}newPW", skip_serializing_if = "Option::is_none")]
        pub new_password: Option<String>,
        pub options: EPPLoginOptions,
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}svcs")]
        pub services: EPPLoginServices,
    }

    #[derive(Debug, Serialize)]
    pub struct EPPLoginOptions {
        pub version: String,
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}lang")]
        pub language: String,
    }

    #[derive(Debug, Serialize)]
    pub struct EPPLoginServices {
        #[serde(rename = "{urn:ietf:params:xml:ns:epp-1.0}objURI")]
        pub objects: Vec<String>,
    }


    #[test]
    fn encode() {
        pretty_env_logger::init();
        println!("{:?}", super::ser::to_string(&EPPMessage {
            message: EPPMessageType::Command(EPPCommand {
                command: "&".to_string(),
                client_transaction_id: Some("&".to_string()),
            })
        }).unwrap());
    }
}
