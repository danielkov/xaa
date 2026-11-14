//! `application/x-www-form-urlencoded` token-endpoint requests, shared by the
//! server components.

#[cfg(any(test, feature = "resource-as", feature = "idp"))]
/// A parsed form body. Parameter order and repeats are preserved so that a
/// repeated parameter can be rejected (RFC 6749 §3.2).
#[derive(Debug, Clone, Default)]
pub(crate) struct Form {
    pairs: Vec<(String, String)>,
}

#[cfg(any(test, feature = "resource-as", feature = "idp"))]
/// A parameter that may appear at most once appeared more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Repeated(pub &'static str);

#[cfg(any(test, feature = "resource-as", feature = "idp"))]
impl Form {
    pub(crate) fn parse(body: &[u8]) -> Self {
        Self {
            pairs: url::form_urlencoded::parse(body)
                .map(|(name, value)| (name.into_owned(), value.into_owned()))
                .collect(),
        }
    }

    /// The single value of `name`. An empty value counts as absent
    /// (RFC 6749 §3.2: parameters sent without a value are omitted).
    pub(crate) fn one(&self, name: &'static str) -> Result<Option<&str>, Repeated> {
        let mut values = self
            .pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str());
        let first = values.next();
        if values.next().is_some() {
            return Err(Repeated(name));
        }
        Ok(first.filter(|value| !value.is_empty()))
    }

    #[cfg(any(test, feature = "idp"))]
    /// Every value of a parameter that may repeat, such as `resource`
    /// (RFC 8707 §2), in order.
    pub(crate) fn all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }
}

#[cfg(any(test, feature = "client"))]
/// Serialize pairs as a form body.
pub(crate) fn encode(pairs: &[(String, String)]) -> Vec<u8> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish().into_bytes()
}

/// Every value of header `name`, compared case-insensitively.
pub(crate) fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_repeated_and_empty_values() {
        let form = Form::parse(b"a=1&b=&c=x&c=y&d=%2Fp%20q+r");
        assert_eq!(form.one("a"), Ok(Some("1")));
        assert_eq!(form.one("b"), Ok(None));
        assert_eq!(form.one("c"), Err(Repeated("c")));
        assert_eq!(form.one("d"), Ok(Some("/p q r")));
        assert_eq!(form.one("missing"), Ok(None));
        assert_eq!(form.all("c"), ["x", "y"]);
    }

    #[test]
    fn encode_round_trips() {
        let pairs = vec![
            (
                "resource".to_owned(),
                "https://api.example/?a=b&c".to_owned(),
            ),
            ("scope".to_owned(), "a b".to_owned()),
        ];
        let form = Form::parse(&encode(&pairs));
        assert_eq!(form.one("resource"), Ok(Some("https://api.example/?a=b&c")));
        assert_eq!(form.one("scope"), Ok(Some("a b")));
    }

    #[test]
    fn headers_are_case_insensitive() {
        let headers = vec![
            ("DPoP".to_owned(), "a".to_owned()),
            ("dpop".to_owned(), "b".to_owned()),
            ("Accept".to_owned(), "x".to_owned()),
        ];
        assert_eq!(header_values(&headers, "DPOP"), ["a", "b"]);
    }
}
