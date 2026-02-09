#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct OuterSignatre {
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:Signature")]
    pub signature: Signature,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Signature {
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:SignedInfo")]
    pub signed_info: SignedInfo,
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:SignatureValue")]
    pub signature_value: SignatureValue,
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:KeyInfo")]
    pub key_info: Option<KeyInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignatureValue {
    #[serde(rename = "$value")]
    pub value: String,
    #[serde(rename = "$attr:Id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignedInfo {
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:CanonicalizationMethod")]
    pub canonicalization_method: CanonicalizationMethod,
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:SignatureMethod")]
    pub signature_method: SignatureMethod,
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:Reference")]
    pub reference: Vec<Reference>,
    #[serde(rename = "$attr:Id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CanonicalizationMethod {
    #[serde(rename = "$attr:Algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignatureMethod {
    #[serde(rename = "$attr:Algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyInfo {
    #[serde(rename = "$value")]
    pub keys_info: Vec<KeyInfoType>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Reference {
    #[serde(
        rename = "{http://www.w3.org/2000/09/xmldsig#}ds:Transforms",
        default, skip_serializing_if = "Option::is_none"
    )]
    pub transforms: Option<Transforms>,
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:DigestMethod")]
    pub digest_method: DigestMethod,
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:DigestValue")]
    pub digest_value: String,
    #[serde(rename = "$attr:Id", default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "$attr:URI", default, skip_serializing_if = "Option::is_none")]
    pub uri: Option<String>,
    #[serde(rename = "$attr:Type", default, skip_serializing_if = "Option::is_none")]
    pub ref_type: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transforms {
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:Transform")]
    pub transforms: Vec<Transform>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Transform {
    #[serde(rename = "$attr:Algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DigestMethod {
    #[serde(rename = "$attr:Algorithm")]
    pub algorithm: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KeyInfoType {
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:KeyName")]
    KeyName(String),
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:KeyValue")]
    KeyValue(KeyValue),
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:X509Data")]
    X509Data(X509Data),
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:PGPData")]
    PGPData(PGPData),
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:SPKIData")]
    SPKIData(SPKIData),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum KeyValue {
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:DSAKeyValue")]
    DSA(DSAKeyValue),
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:RSAKeyValue")]
    RSA(RSAKeyValue),
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:ECKeyValue")]
    EC(ECKeyValue),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DSAKeyValue {
    #[serde(
    rename = "{http://www.w3.org/2000/09/xmldsig#}ds:P",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub p: Option<String>,
    #[serde(
    rename = "{http://www.w3.org/2000/09/xmldsig#}ds:Q",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub q: Option<String>,
    #[serde(
    rename = "{http://www.w3.org/2000/09/xmldsig#}ds:G",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub g: Option<String>,
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:Y")]
    pub y: String,
    #[serde(
    rename = "{http://www.w3.org/2000/09/xmldsig#}ds:J",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub j: Option<String>,
    #[serde(
    rename = "{http://www.w3.org/2000/09/xmldsig#}ds:Seed",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub seed: Option<String>,
    #[serde(
    rename = "{http://www.w3.org/2000/09/xmldsig#}ds:PgenCounter",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub pgen_counter: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RSAKeyValue {
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:Modulus")]
    pub modulus: String,
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:Exponent")]
    pub exponent: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ECKeyValue {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:PublicKey")]
    pub pub_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ECKeyCurve {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:NamedCurve")]
    NamedCurve(String),
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:ECParameters")]
    Params(ECParams),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ECParams {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:FieldID")]
    pub field_id: ECFieldID,
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:Curve")]
    pub curve: ECCurve,
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:Base")]
    pub base: String,
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:Order")]
    pub order: String,
    #[serde(
    rename = "{http://www.w3.org/2009/xmldsig11#}ds11:CoFactor",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub cofactor: Option<i64>,
    #[serde(
    rename = "{http://www.w3.org/2009/xmldsig11#}ds11:ValidationData",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub validation_data: Option<ECValidationData>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ECCurve {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:A")]
    pub a: String,
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:B")]
    pub b: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ECValidationData {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:seed")]
    pub seed: String,
    #[serde(rename = "$attr:hashAlgorithm")]
    pub hash_algorithm: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ECFieldID {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:Prime")]
    Prime(PrimeFieldParams),
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:TnB")]
    TnB(TnBFieldParams),
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:PnB")]
    PnB(PnBFieldParams),
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:GnB")]
    GnB(GnBFieldParams),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrimeFieldParams {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:P")]
    pub prime: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TnBFieldParams {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:M")]
    pub m: u64,
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:K")]
    pub k: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PnBFieldParams {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:M")]
    pub m: u64,
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:K1")]
    pub k1: u64,
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:K2")]
    pub k2: u64,
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:K3")]
    pub k3: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GnBFieldParams {
    #[serde(rename = "{http://www.w3.org/2009/xmldsig11#}ds11:M")]
    pub m: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct X509Data {
    #[serde(rename = "$value")]
    pub x509_data: Vec<X509Datum>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum X509Datum {
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:X509IssuerSerial")]
    IssuerSerial(X509IssuerSerial),
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:X509SKI")]
    SKI(String),
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:X509SubjectName")]
    SubjectName(String),
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:X509Certificate")]
    Certificate(String),
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:X509CRL")]
    CRL(String),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct X509IssuerSerial {
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:X509IssuerName")]
    pub issuer_name: String,
    #[serde(rename = "{http://www.w3.org/2000/09/xmldsig#}ds:X509SerialNumber")]
    pub serial_number: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PGPData {
    #[serde(
    rename = "{http://www.w3.org/2000/09/xmldsig#}ds:PGPKeyID",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub key_id: Option<String>,
    #[serde(
    rename = "{http://www.w3.org/2000/09/xmldsig#}ds:PGPKeyPacket",
    default, skip_serializing_if = "Option::is_none"
    )]
    pub key_packet: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SPKIData {
    #[serde(
    rename = "{http://www.w3.org/2000/09/xmldsig#}ds:SPKISexp",
    default, skip_serializing_if = "Vec::is_empty"
    )]
    pub sexp: Vec<String>,
}