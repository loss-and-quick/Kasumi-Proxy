//! Which GUI the privileged data-path serves. A machine has one tun and one set of
//! routes, and the Windows service runs with the paths of the GUI that started it,
//! so it serves only that GUI's Windows session, and one connection at a time. A
//! GUI in another session (a second RDP or fast-user-switch login) is refused with
//! a reply that names the owner, instead of driving the other user's data-path.

/// What the service does with a client that has just connected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Serve,
    /// Answer with [`PrivReply::OtherSession`](super::proto::PrivReply::OtherSession)
    /// naming the session the data-path belongs to, then hang up.
    Refuse {
        owner: Option<u32>,
    },
}

/// `owner` is the session of the GUI that started the service (`None` from a GUI
/// that predates the argument: any session is let in, as before), `client` the
/// connecting GUI's session (`None` when it can't be read), `serving` the session
/// of the connection already being served, if any.
pub fn admit(owner: Option<u32>, client: Option<u32>, serving: Option<Option<u32>>) -> Admission {
    if let Some(active) = serving {
        return Admission::Refuse {
            owner: owner.or(active),
        };
    }
    match owner {
        Some(o) if client != Some(o) => Admission::Refuse { owner: Some(o) },
        _ => Admission::Serve,
    }
}

/// Why a GUI was refused, for the startup error. `mine` is the GUI's own session.
pub fn refusal_message(owner: Option<u32>, mine: Option<u32>) -> String {
    match owner {
        Some(o) if Some(o) == mine => "another Kasumi Proxy window in this Windows session \
             still holds the data-path; quit it, then start Kasumi Proxy again"
            .to_owned(),
        Some(o) => format!(
            "Kasumi Proxy is already running in another Windows session (session {o}); \
             quit it there or sign that user out, then start it here"
        ),
        None => "Kasumi Proxy is already running in another Windows session; quit it \
                 there or sign that user out, then start it here"
            .to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_the_owner_session_when_idle() {
        assert_eq!(admit(Some(2), Some(2), None), Admission::Serve);
    }

    #[test]
    fn refuses_another_session() {
        assert_eq!(
            admit(Some(2), Some(3), None),
            Admission::Refuse { owner: Some(2) }
        );
    }

    // Without the caller's session there is no telling whose it is.
    #[test]
    fn refuses_a_client_whose_session_is_unknown() {
        assert_eq!(
            admit(Some(2), None, None),
            Admission::Refuse { owner: Some(2) }
        );
    }

    #[test]
    fn refuses_a_second_connection_even_from_the_owner() {
        assert_eq!(
            admit(Some(2), Some(2), Some(Some(2))),
            Admission::Refuse { owner: Some(2) }
        );
    }

    // A service started by a GUI without `--session` keeps the old behaviour: it
    // serves whoever connects, one at a time.
    #[test]
    fn a_service_without_an_owner_serves_any_session_one_at_a_time() {
        assert_eq!(admit(None, Some(3), None), Admission::Serve);
        assert_eq!(admit(None, None, None), Admission::Serve);
        assert_eq!(
            admit(None, Some(3), Some(Some(2))),
            Admission::Refuse { owner: Some(2) }
        );
    }

    #[test]
    fn messages_name_the_owner() {
        assert!(refusal_message(Some(2), Some(3)).contains("session 2"));
        assert!(refusal_message(Some(2), Some(2)).contains("this Windows session"));
        assert!(refusal_message(None, Some(3)).contains("another Windows session"));
    }
}
