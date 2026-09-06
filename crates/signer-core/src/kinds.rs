//! Names for the event kinds a user is likely to be asked to sign.

use nostr::event::Kind;

/// A short name for a kind, or `None` when the number is all there is.
///
/// The list is deliberately short and skewed towards the kinds that hand
/// something over: a direct message, an auth token, a deletion. "Sign a kind
/// 27235 event" tells the user nothing, and that is the request that gives a
/// website your identity.
pub fn name(kind: Kind) -> Option<&'static str> {
    Some(match kind.as_u16() {
        0 => "profile",
        1 => "note",
        3 => "contact list",
        4 => "legacy direct message",
        5 => "deletion request",
        6 => "repost",
        7 => "reaction",
        13 => "sealed message",
        14 => "direct message",
        1059 => "gift wrap",
        1063 => "file metadata",
        1111 => "comment",
        1984 => "report",
        9734 => "zap request",
        10000 => "mute list",
        10002 => "relay list",
        22242 => "relay authentication",
        27235 => "HTTP authentication",
        30023 => "article",
        30078 => "application data",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_the_kinds_that_matter() {
        assert_eq!(name(Kind::from_u16(1)), Some("note"));
        assert_eq!(name(Kind::from_u16(9734)), Some("zap request"));
        assert_eq!(name(Kind::from_u16(27235)), Some("HTTP authentication"));
    }

    #[test]
    fn leaves_an_unknown_kind_as_a_number() {
        assert_eq!(name(Kind::from_u16(31337)), None);
    }
}
