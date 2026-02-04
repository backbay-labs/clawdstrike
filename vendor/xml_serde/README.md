# Namespace aware XML (de)serializer for Rust utilizing Serde

```rust
// XML elements can be specified with structs
#[derive(Debug, Serialize, Deserialize)]
pub struct BulkObservable {
    // Required attributes can easily be defined, with the format of {namespace}ns-prefix:element
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}iodef:BulkObservableList")]
    pub list: String,

    // Repeated and optional elements can be defined with Vec and Option
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}iodef:AdditionalData", default, skip_serializing_if="Vec::is_empty")]
    pub additional_data: Vec<ExtensionType>,
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}iodef:BulkObservableFormat", default, skip_serializing_if="Option::is_none")]
    pub format: Option<BulkObservableFormat>,

    // Element attributes can be specified with the $attr: prefix
    #[serde(rename = "$attr:type")]
    pub bulk_type: BulkObservableType,
    #[serde(rename = "$attr:ext-type", default, skip_serializing_if="Option::is_none")]
    pub bulk_ext_type: Option<String>,

    // Textual element content can be set with the special name $value
    #[serde(rename = "$value")]
    pub value: f64,
}

// Enumerated values can also be defined
#[derive(Debug, Serialize, Deserialize)]
pub enum ConfidenceRating {
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "numeric")]
    Numeric,
    #[serde(rename = "unknown")]
    Unknown
}

// As can enumerated objects
#[derive(Debug, Serialize, Deserialize)]
pub enum IndicatorExpressionInner {
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IndicatorExpression")]
    IndicatorExpression(IndicatorExpression),
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}Observable")]
    Observable(Observable),
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}ObservableReference")]
    ObservableReference(ObservableReference),
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}IndicatorReference")]
    IndicatorReference(IndicatorReference),
    #[serde(rename = "{urn:ietf:params:xml:ns:iodef-2.0}AdditionalData")]
    AdditionalData(ExtensionType),
}
```
