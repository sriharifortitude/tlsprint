//! A list of fingerprints to look out for. JA4's three sections mean different things, and the
//! point of them is hunting on one at a time, so a pattern can leave any of them open.

struct Pattern {
    sections: [String; 3],
    label: String,
}

pub struct WatchList {
    patterns: Vec<Pattern>,
}

fn section_matches(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}

impl WatchList {
    /// One `fingerprint[,label]` per line; blank lines and lines starting with # are ignored.
    pub fn parse(text: &str) -> Result<WatchList, String> {
        let mut patterns = Vec::new();
        for (i, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (fingerprint, label) = line.split_once(',').unwrap_or((line, ""));
            let parts: Vec<&str> = fingerprint.trim().split('_').collect();
            let [a, b, c] = parts.as_slice() else {
                return Err(format!(
                    "line {}: {fingerprint:?} does not have the three sections of a JA4",
                    i + 1
                ));
            };
            if [a, b, c].iter().any(|s| s.is_empty()) {
                return Err(format!(
                    "line {}: {fingerprint:?} has an empty section; use * to leave one open",
                    i + 1
                ));
            }
            let label = if label.trim().is_empty() {
                fingerprint.trim()
            } else {
                label.trim()
            };
            patterns.push(Pattern {
                sections: [a.to_string(), b.to_string(), c.to_string()],
                label: label.to_string(),
            });
        }
        Ok(WatchList { patterns })
    }

    /// The labels of every pattern this fingerprint matches.
    pub fn matches(&self, ja4: &str) -> Vec<String> {
        let parts: Vec<&str> = ja4.split('_').collect();
        self.patterns
            .iter()
            .filter(|p| {
                parts.len() == 3
                    && p.sections
                        .iter()
                        .zip(&parts)
                        .all(|(s, v)| section_matches(s, v))
            })
            .map(|p| p.label.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";

    #[test]
    fn whole_and_partial_patterns() {
        let list = WatchList::parse(
            "# a comment\n\n t13d1516h2_8daaf6152771_e5627efa2ab1 , exact \n*_8daaf6152771_*,ciphers\nt13d*_*_e5627efa2ab1,prefix\nq13d1516h2_*_*,other\nt13d1516h2_*_000000000000\n",
        )
        .unwrap();
        assert_eq!(list.matches(JA4), ["exact", "ciphers", "prefix"]);
        assert_eq!(list.matches("q13d1516h2_x_y"), ["other"]);
        assert_eq!(
            list.matches("t13d1516h2_x_000000000000"),
            ["t13d1516h2_*_000000000000"],
            "the label defaults to the pattern"
        );
        assert!(list.matches("not-a-fingerprint").is_empty());
        assert!(list.matches("a_b_c_d").is_empty());
    }

    #[test]
    fn bad_lines_name_their_line() {
        for (text, want) in [
            ("x_y", "line 1"),
            ("# c\nt13_x", "line 2"),
            ("a__c", "empty section"),
            ("a_b_c_d,x", "three sections"),
        ] {
            let err = WatchList::parse(text).err().unwrap();
            assert!(err.contains(want), "{text}: {err}");
        }
    }

    #[test]
    fn an_empty_list_matches_nothing() {
        assert!(WatchList::parse("# nothing\n")
            .unwrap()
            .matches(JA4)
            .is_empty());
    }
}
