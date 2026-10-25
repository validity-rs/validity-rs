//! What the module says, in English or French: never both.
//!
//! pam_fprintd translates with gettext, which follows the locale the
//! application set with `setlocale`; LightDM's PAM process never sets one,
//! so its messages came out in English next to a French greeter. This
//! module reads the language from the environment instead, as
//! `setlocale(LC_MESSAGES, "")` would: `LC_ALL`, then `LC_MESSAGES`, then
//! `LANG`, the first one set and not empty. Each variable is looked up in
//! the PAM environment first (`pam_getenv`), then in the process's.

/// The languages the messages exist in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    /// English: any locale other than French, `C` and `POSIX` included.
    En,
    /// French: `fr`, `fr_FR.UTF-8`, `fr_BE@euro`...
    Fr,
}

/// The locale variables, in the order that decides.
pub const LOCALE_VARS: [&str; 3] = ["LC_ALL", "LC_MESSAGES", "LANG"];

impl Lang {
    /// The language of a locale name (`language[_territory][.codeset][@modifier]`).
    pub fn of_locale(locale: &str) -> Self {
        match locale.split(['_', '.', '@']).next() {
            Some("fr") => Lang::Fr,
            _ => Lang::En,
        }
    }

    /// The language of the environment: `pam_env` (the PAM environment)
    /// before `process_env`, variable by variable.
    pub fn of_env(
        pam_env: impl Fn(&str) -> Option<String>,
        process_env: impl Fn(&str) -> Option<String>,
    ) -> Self {
        let set = |v: Option<String>| v.filter(|v| !v.is_empty());
        LOCALE_VARS
            .iter()
            .find_map(|var| set(pam_env(var)).or_else(|| set(process_env(var))))
            .map_or(Lang::En, |locale| Lang::of_locale(&locale))
    }
}

/// The finger's name in a sentence, or `None` for a name fprintd does not define.
fn finger(lang: Lang, name: &str) -> Option<&'static str> {
    let (side, digit) = name.split_once('-')?;
    let i = [
        "thumb",
        "index-finger",
        "middle-finger",
        "ring-finger",
        "little-finger",
    ]
    .iter()
    .position(|d| *d == digit)?;
    let left = match side {
        "left" => true,
        "right" => false,
        _ => return None,
    };
    let names: [[&str; 5]; 2] = match lang {
        Lang::En => [
            [
                "left thumb",
                "left index finger",
                "left middle finger",
                "left ring finger",
                "left little finger",
            ],
            [
                "right thumb",
                "right index finger",
                "right middle finger",
                "right ring finger",
                "right little finger",
            ],
        ],
        Lang::Fr => [
            [
                "pouce gauche",
                "index gauche",
                "majeur gauche",
                "annulaire gauche",
                "auriculaire gauche",
            ],
            [
                "pouce droit",
                "index droit",
                "majeur droit",
                "annulaire droit",
                "auriculaire droit",
            ],
        ],
    };
    Some(names[usize::from(!left)][i])
}

/// The prompt, one line: the finger by name when exactly one is enrolled,
/// any finger otherwise.
pub fn prompt(lang: Lang, enrolled: &[String]) -> String {
    let one = match enrolled {
        [only] => finger(lang, only),
        _ => None,
    };
    match (lang, one) {
        (Lang::En, Some(f)) => format!("Place your {f} on the fingerprint reader."),
        (Lang::En, None) => "Place your finger on the fingerprint reader.".to_string(),
        (Lang::Fr, Some(f)) => format!("Posez votre {f} sur le lecteur d'empreintes."),
        (Lang::Fr, None) => "Posez le doigt sur le lecteur d'empreintes.".to_string(),
    }
}

/// The line after a match, with the `confirm` option.
pub fn confirm(lang: Lang, user: &str) -> String {
    match lang {
        Lang::En => format!("{user} recognized, press Enter."),
        Lang::Fr => format!("{user} reconnu, appuyez sur Entrée."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| m.get(k).cloned()
    }
    fn none(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn locale_names() {
        for l in [
            "fr",
            "fr_FR",
            "fr_FR.UTF-8",
            "fr_BE.UTF-8",
            "fr_CA",
            "fr_BE@euro",
            "fr.UTF-8",
        ] {
            assert_eq!(Lang::of_locale(l), Lang::Fr, "{l}");
        }
        for l in [
            "",
            "C",
            "POSIX",
            "C.UTF-8",
            "en_US.UTF-8",
            "en_GB",
            "nl_BE.UTF-8",
            "de_DE",
            "fra",
            "frFR",
            "FR_fr",
        ] {
            assert_eq!(Lang::of_locale(l), Lang::En, "{l}");
        }
    }

    #[test]
    fn posix_order() {
        let all = [
            ("LC_ALL", "fr_FR.UTF-8"),
            ("LC_MESSAGES", "en_US.UTF-8"),
            ("LANG", "en_US.UTF-8"),
        ];
        assert_eq!(Lang::of_env(env(&all), none), Lang::Fr);
        let msgs = [("LC_MESSAGES", "fr_FR.UTF-8"), ("LANG", "en_US.UTF-8")];
        assert_eq!(Lang::of_env(env(&msgs), none), Lang::Fr);
        let msgs = [("LC_MESSAGES", "en_US.UTF-8"), ("LANG", "fr_FR.UTF-8")];
        assert_eq!(Lang::of_env(env(&msgs), none), Lang::En);
        assert_eq!(
            Lang::of_env(env(&[("LANG", "fr_BE.UTF-8")]), none),
            Lang::Fr
        );
        assert_eq!(
            Lang::of_env(env(&[("LANG", "en_US.UTF-8")]), none),
            Lang::En
        );
        // Set but empty means not set.
        let empty = [("LC_ALL", ""), ("LC_MESSAGES", ""), ("LANG", "fr_FR.UTF-8")];
        assert_eq!(Lang::of_env(env(&empty), none), Lang::Fr);
        assert_eq!(Lang::of_env(none, none), Lang::En);
        // Other variables do not count.
        assert_eq!(
            Lang::of_env(env(&[("LANGUAGE", "fr"), ("LC_CTYPE", "fr_FR")]), none),
            Lang::En
        );
    }

    #[test]
    fn pam_environment_first() {
        // The same variable: PAM's wins.
        let pam = env(&[("LANG", "fr_FR.UTF-8")]);
        assert_eq!(Lang::of_env(pam, env(&[("LANG", "en_US.UTF-8")])), Lang::Fr);
        let pam = env(&[("LANG", "en_US.UTF-8")]);
        assert_eq!(Lang::of_env(pam, env(&[("LANG", "fr_FR.UTF-8")])), Lang::En);
        // The process's when PAM's is unset or empty.
        assert_eq!(
            Lang::of_env(none, env(&[("LANG", "fr_FR.UTF-8")])),
            Lang::Fr
        );
        assert_eq!(
            Lang::of_env(env(&[("LANG", "")]), env(&[("LANG", "fr_FR.UTF-8")])),
            Lang::Fr
        );
        // Variable order first: the process's LC_ALL beats PAM's LANG.
        let pam = env(&[("LANG", "en_US.UTF-8")]);
        assert_eq!(
            Lang::of_env(pam, env(&[("LC_ALL", "fr_FR.UTF-8")])),
            Lang::Fr
        );
        let pam = env(&[("LANG", "fr_FR.UTF-8")]);
        assert_eq!(Lang::of_env(pam, env(&[("LC_MESSAGES", "C")])), Lang::En);
    }

    fn fingers(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn one_finger_by_name() {
        let cases = [
            ("left-thumb", "left thumb", "pouce gauche"),
            ("left-index-finger", "left index finger", "index gauche"),
            ("left-middle-finger", "left middle finger", "majeur gauche"),
            ("left-ring-finger", "left ring finger", "annulaire gauche"),
            (
                "left-little-finger",
                "left little finger",
                "auriculaire gauche",
            ),
            ("right-thumb", "right thumb", "pouce droit"),
            ("right-index-finger", "right index finger", "index droit"),
            ("right-middle-finger", "right middle finger", "majeur droit"),
            ("right-ring-finger", "right ring finger", "annulaire droit"),
            (
                "right-little-finger",
                "right little finger",
                "auriculaire droit",
            ),
        ];
        for (name, en, fr) in cases {
            assert_eq!(
                prompt(Lang::En, &fingers(&[name])),
                format!("Place your {en} on the fingerprint reader.")
            );
            assert_eq!(
                prompt(Lang::Fr, &fingers(&[name])),
                format!("Posez votre {fr} sur le lecteur d'empreintes.")
            );
        }
        assert_eq!(
            prompt(Lang::Fr, &fingers(&["right-index-finger"])),
            "Posez votre index droit sur le lecteur d'empreintes."
        );
        assert_eq!(
            prompt(Lang::En, &fingers(&["right-index-finger"])),
            "Place your right index finger on the fingerprint reader."
        );
    }

    #[test]
    fn any_finger_otherwise() {
        let en = "Place your finger on the fingerprint reader.";
        let fr = "Posez le doigt sur le lecteur d'empreintes.";
        for names in [
            &[][..],
            &["left-thumb", "right-index-finger"][..],
            &["left-thumb", "left-thumb"][..],
            &["any"][..],
            &["right-pinky"][..],
            &["middle-finger"][..],
            &["up-thumb"][..],
            &["left"][..],
            &[""][..],
        ] {
            assert_eq!(prompt(Lang::En, &fingers(names)), en, "{names:?}");
            assert_eq!(prompt(Lang::Fr, &fingers(names)), fr, "{names:?}");
        }
    }

    #[test]
    fn confirmation() {
        assert_eq!(
            confirm(Lang::Fr, "papa"),
            "papa reconnu, appuyez sur Entrée."
        );
        assert_eq!(confirm(Lang::En, "papa"), "papa recognized, press Enter.");
    }
}
