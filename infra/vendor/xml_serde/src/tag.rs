use std::borrow::Cow;

static NAME_RE: once_cell::sync::Lazy<regex::Regex> = once_cell::sync::Lazy::new(|| {
    regex::Regex::new(r"^(?:\{(?P<n>[^;]+)(?:;(?P<l>.*))?\})?(?:(?P<p>.+):)?(?P<e>.+)$").unwrap()
});

#[derive(Debug,Copy,Clone,Eq,PartialEq)]
pub(crate) struct Tag<'a> {
    pub n: Option<&'a str>,
    pub l: Option<&'a str>,
    pub p: Option<&'a str>,
    pub e: &'a str,
}

impl<'a> Tag<'a> {
    pub fn new(str: &'a str) -> Self {
        let captures = NAME_RE.captures(str).unwrap();
        Self {
            n: captures.name("n").map(|m| m.as_str()),
            l: captures.name("l").map(|m| m.as_str()),
            p: captures.name("p").map(|m| m.as_str()),
            e: captures.name("e").map(|m| m.as_str()).unwrap(),
        }
    }

    pub fn from_cow(str: &'a Cow<'static, str>) -> Tag<'a> {
        match str {
            Cow::Borrowed(str) => Tag::from_static(str),
            Cow::Owned(str) => Self::new(str.as_ref()),
        }
    }
}

impl Tag<'static> {
    pub fn from_static(str: &'static str) -> Tag<'static> {
        use once_cell::sync::OnceCell;
        use std::sync::Mutex;
        use std::collections::btree_map::{BTreeMap,Entry};

        // Make a single global BTreeMap to act as a cache
        static CACHE: OnceCell<Mutex<BTreeMap<usize, Tag<'static>>>> = OnceCell::new();
        let mut cache = CACHE.get_or_init(|| {
            Mutex::new(BTreeMap::new())
        }).lock().unwrap();

        // Look up the pointer address of our &'static [&'static str] in the cache
        match cache.entry(str.as_ptr() as usize) {
            Entry::Vacant(e) => {
                // Miss
                *e.insert(Self::new(str))
            }
            Entry::Occupied(e) => {
                // Hit
                *e.get()
            }
        }
    }
}

impl<'a> From<Tag<'a>> for xml::name::Name<'a> {
    fn from(tag: Tag<'a>) -> Self {
        xml::name::Name {
            local_name: tag.e,
            namespace: tag.n,
            prefix: tag.p,
        }
    }
}