// Copyright 2019 Pierre Krieger
// Copyright (c) 2019 Tokio Contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::ops::{Add, AddAssign, Sub, SubAssign};
use std::time::Duration;

use crate::js::performance_now;

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Hash, Debug)]
pub struct Instant(Duration);

impl Instant {
    #[cfg(not(all(feature = "tokio-test-util", feature = "tokio")))]
    pub fn now() -> Instant {
        Self::now_js()
    }

    #[cfg(all(feature = "tokio-test-util", feature = "tokio"))]
    pub fn now() -> Instant {
        crate::timer::clock::now()
    }

    pub(crate) fn now_js() -> Instant {
        let val = (performance_now() * 1000.0) as u64;
        Instant(Duration::from_micros(val))
    }

    pub fn duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    pub fn elapsed(&self) -> Duration {
        Instant::now() - *self
    }

    pub fn checked_duration_since(&self, earlier: Instant) -> Option<Duration> {
        self.0.checked_sub(earlier.0)
    }

    pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
        self.checked_duration_since(earlier).unwrap_or_default()
    }

    pub fn checked_add(&self, duration: Duration) -> Option<Instant> {
        self.0.checked_add(duration).map(Instant)
    }

    pub fn checked_sub(&self, duration: Duration) -> Option<Instant> {
        self.0.checked_sub(duration).map(Instant)
    }
}

impl Add<Duration> for Instant {
    type Output = Instant;

    /// # Panics
    ///
    /// This function may panic if the resulting point in time cannot be represented by the
    /// underlying data structure. See [`Instant::checked_add`] for a version without panic.
    fn add(self, other: Duration) -> Instant {
        self.checked_add(other)
            .expect("overflow when adding duration to instant")
    }
}

impl AddAssign<Duration> for Instant {
    fn add_assign(&mut self, other: Duration) {
        *self = *self + other;
    }
}

impl Sub<Duration> for Instant {
    type Output = Instant;

    fn sub(self, other: Duration) -> Instant {
        self.checked_sub(other)
            .expect("overflow when subtracting duration from instant")
    }
}

impl SubAssign<Duration> for Instant {
    fn sub_assign(&mut self, other: Duration) {
        *self = *self - other;
    }
}

impl Sub<Instant> for Instant {
    type Output = Duration;

    /// Returns the amount of time elapsed from another instant to this one,
    /// or zero duration if that instant is later than this one.
    ///
    /// # Panics
    ///
    /// Previous Rust versions panicked when `other` was later than `self`. Currently this
    /// method saturates. Future versions may reintroduce the panic in some circumstances.
    /// See [Monotonicity].
    ///
    /// [Monotonicity]: Instant#monotonicity
    fn sub(self, other: Instant) -> Duration {
        self.duration_since(other)
    }
}

pub const UNIX_EPOCH: SystemTime = SystemTime { inner: 0.0 };

#[derive(Debug, Copy, Clone)]
pub struct SystemTime {
    /// Unit is milliseconds.
    inner: f64,
}

#[derive(Debug, Copy, Clone)]
pub struct SystemTimeError(Duration);

impl SystemTimeError {
    pub fn duration(&self) -> Duration {
        self.0
    }
}

impl std::fmt::Display for SystemTimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "second time provided was later than self")
    }
}

impl PartialEq for SystemTime {
    fn eq(&self, other: &SystemTime) -> bool {
        // Note that this will most likely only compare equal if we clone an `SystemTime`,
        // but that's ok.
        self.inner == other.inner
    }
}

impl Eq for SystemTime {}

impl PartialOrd for SystemTime {
    fn partial_cmp(&self, other: &SystemTime) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SystemTime {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.partial_cmp(&other.inner).unwrap()
    }
}

impl SystemTime {
    pub const UNIX_EPOCH: SystemTime = SystemTime { inner: 0.0 };

    pub fn now() -> SystemTime {
        let val = js_sys::Date::now();
        SystemTime { inner: val }
    }

    pub fn duration_since(&self, earlier: SystemTime) -> Result<Duration, SystemTimeError> {
        let dur_ms = self.inner - earlier.inner;
        if dur_ms < 0.0 {
            return Err(SystemTimeError(Duration::from_millis(dur_ms.abs() as u64)));
        }
        Ok(Duration::from_millis(dur_ms as u64))
    }

    pub fn elapsed(&self) -> Result<Duration, SystemTimeError> {
        SystemTime::now().duration_since(*self)
    }

    pub fn checked_add(&self, duration: Duration) -> Option<SystemTime> {
        Some(*self + duration)
    }

    pub fn checked_sub(&self, duration: Duration) -> Option<SystemTime> {
        Some(*self - duration)
    }
}

impl Add<Duration> for SystemTime {
    type Output = SystemTime;

    fn add(self, other: Duration) -> SystemTime {
        let new_val = self.inner + other.as_millis() as f64;
        SystemTime { inner: new_val }
    }
}

impl Sub<Duration> for SystemTime {
    type Output = SystemTime;

    fn sub(self, other: Duration) -> SystemTime {
        let new_val = self.inner - other.as_millis() as f64;
        SystemTime { inner: new_val }
    }
}

impl AddAssign<Duration> for SystemTime {
    fn add_assign(&mut self, rhs: Duration) {
        *self = *self + rhs;
    }
}

impl SubAssign<Duration> for SystemTime {
    fn sub_assign(&mut self, rhs: Duration) {
        *self = *self - rhs;
    }
}

#[cfg(feature = "serde")]
impl serde_crate::ser::Serialize for SystemTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde_crate::ser::Serializer,
    {
        use serde_crate::ser::{Error, SerializeStruct};
        let duration_since_epoch = match self.duration_since(UNIX_EPOCH) {
            Ok(duration_since_epoch) => duration_since_epoch,
            Err(_) => return Err(S::Error::custom("SystemTime must be later than UNIX_EPOCH")),
        };
        let mut state = serializer.serialize_struct("SystemTime", 2)?;
        state.serialize_field("secs_since_epoch", &duration_since_epoch.as_secs())?;
        state.serialize_field("nanos_since_epoch", &duration_since_epoch.subsec_nanos())?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde_crate::de::Deserialize<'de> for SystemTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde_crate::de::Deserializer<'de>,
    {
        use serde_crate::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
        use std::fmt;
        // Reuse duration
        enum Field {
            Secs,
            Nanos,
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str("`secs_since_epoch` or `nanos_since_epoch`")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match value {
                            "secs_since_epoch" => Ok(Field::Secs),
                            "nanos_since_epoch" => Ok(Field::Nanos),
                            _ => Err(Error::unknown_field(value, FIELDS)),
                        }
                    }

                    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match value {
                            b"secs_since_epoch" => Ok(Field::Secs),
                            b"nanos_since_epoch" => Ok(Field::Nanos),
                            _ => {
                                let value = String::from_utf8_lossy(value);
                                Err(Error::unknown_field(&value, FIELDS))
                            }
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        fn check_overflow<E>(secs: u64, nanos: u32) -> Result<(), E>
        where
            E: Error,
        {
            static NANOS_PER_SEC: u32 = 1_000_000_000;
            match secs.checked_add((nanos / NANOS_PER_SEC) as u64) {
                Some(_) => Ok(()),
                None => Err(E::custom("overflow deserializing SystemTime epoch offset")),
            }
        }

        struct DurationVisitor;

        impl<'de> Visitor<'de> for DurationVisitor {
            type Value = Duration;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct SystemTime")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let secs: u64 = match seq.next_element()? {
                    Some(value) => value,
                    None => {
                        return Err(Error::invalid_length(0, &self));
                    }
                };
                let nanos: u32 = match seq.next_element()? {
                    Some(value) => value,
                    None => {
                        return Err(Error::invalid_length(1, &self));
                    }
                };
                check_overflow(secs, nanos)?;
                Ok(Duration::new(secs, nanos))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut secs: Option<u64> = None;
                let mut nanos: Option<u32> = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Secs => {
                            if secs.is_some() {
                                return Err(<A::Error as Error>::duplicate_field(
                                    "secs_since_epoch",
                                ));
                            }
                            secs = Some(map.next_value()?);
                        }
                        Field::Nanos => {
                            if nanos.is_some() {
                                return Err(<A::Error as Error>::duplicate_field(
                                    "nanos_since_epoch",
                                ));
                            }
                            nanos = Some(map.next_value()?);
                        }
                    }
                }
                let secs = match secs {
                    Some(secs) => secs,
                    None => return Err(<A::Error as Error>::missing_field("secs_since_epoch")),
                };
                let nanos = match nanos {
                    Some(nanos) => nanos,
                    None => return Err(<A::Error as Error>::missing_field("nanos_since_epoch")),
                };
                check_overflow(secs, nanos)?;
                Ok(Duration::new(secs, nanos))
            }
        }

        const FIELDS: &[&str] = &["secs_since_epoch", "nanos_since_epoch"];
        let duration = deserializer.deserialize_struct("SystemTime", FIELDS, DurationVisitor)?;
        UNIX_EPOCH
            .checked_add(duration)
            .ok_or_else(|| D::Error::custom("overflow deserializing SystemTime"))
    }
}
