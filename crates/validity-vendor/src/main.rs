//! validity-vendor: see `--help` and the library documentation.

use std::path::PathBuf;
use std::process::ExitCode;

use validity_vendor::{DEFAULT_DIR, Error, LENOVO, Outcome, Source, Status, check, install};

const USAGE: &str = "\
Usage: validity-vendor install [--archive FILE | --url URL] [--dir DIR]
       validity-vendor check [--dir DIR]

Installs the Synaptics files validity-daemon needs (the driver DLL and the
firmware extension). They come from Lenovo's driver package nz3gf07w.exe,
which may not be redistributed: it is downloaded on this machine, checked
against its SHA-256, and the two files are extracted, checked and switched
into DIR/vendor in one atomic step. Run as root.

Commands:
  install          install, or repair, the files (does nothing if they are
                   already in place and intact)
  check            report whether the files are in place and intact

Options:
  --archive FILE   use a copy of nz3gf07w.exe already on disk (no network)
  --url URL        download from URL (a mirror) instead of Lenovo; the
                   SHA-256 check is the same. Default: $VALIDITY_VENDOR_URL,
                   else https://download.lenovo.com/pccbbs/mobiles/nz3gf07w.exe
  --dir DIR        installation directory (default /var/lib/validity)
  -h, --help       this text
  -V, --version    version

Exit status: 0 done (or already in place), 1 error, 2 usage, 3 download
failed, 4 (check) files missing or damaged.
";

enum Cmd {
    Install,
    Check,
}

struct Args {
    cmd: Cmd,
    archive: Option<PathBuf>,
    url: Option<String>,
    dir: PathBuf,
}

enum Parsed {
    Help,
    Version,
    Run(Args),
}

fn parse(args: &[String]) -> Result<Parsed, String> {
    let mut it = args.iter();
    let cmd = match it.next().map(String::as_str) {
        Some("-h" | "--help") => return Ok(Parsed::Help),
        Some("-V" | "--version") => return Ok(Parsed::Version),
        Some("install") => Cmd::Install,
        Some("check") => Cmd::Check,
        Some(other) => return Err(format!("unknown command {other:?}")),
        None => return Err("a command is needed".into()),
    };
    let mut a = Args {
        cmd,
        archive: None,
        url: None,
        dir: PathBuf::from(DEFAULT_DIR),
    };
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "-h" | "--help" => return Ok(Parsed::Help),
            "--archive" => a.archive = Some(PathBuf::from(value("--archive")?)),
            "--url" => a.url = Some(value("--url")?),
            "--dir" => a.dir = PathBuf::from(value("--dir")?),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    if matches!(a.cmd, Cmd::Check) && (a.archive.is_some() || a.url.is_some()) {
        return Err("check takes only --dir".into());
    }
    if a.archive.is_some() && a.url.is_some() {
        return Err("--archive and --url exclude each other".into());
    }
    Ok(Parsed::Run(a))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a = match parse(&args) {
        Ok(Parsed::Run(a)) => a,
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Parsed::Version) => {
            println!("validity-vendor {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("validity-vendor: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    match a.cmd {
        Cmd::Check => match check(&LENOVO, &a.dir) {
            Ok(Status::Installed(p)) => {
                println!(
                    "validity-vendor: the vendor files are in place in {}",
                    p.display()
                );
                ExitCode::SUCCESS
            }
            Ok(Status::Missing) => {
                eprintln!(
                    "validity-vendor: the vendor files are not installed in {}; run: validity-vendor install",
                    a.dir.display()
                );
                ExitCode::from(4)
            }
            Ok(Status::Damaged(name)) => {
                eprintln!(
                    "validity-vendor: {name} in {} is missing or altered; run: validity-vendor install",
                    a.dir.display()
                );
                ExitCode::from(4)
            }
            Err(e) => {
                eprintln!("validity-vendor: {e}");
                ExitCode::FAILURE
            }
        },
        Cmd::Install => {
            let env_url = std::env::var("VALIDITY_VENDOR_URL")
                .ok()
                .filter(|u| !u.is_empty());
            let url = a.url.or(env_url).unwrap_or_else(|| LENOVO.url.to_string());
            let source = match &a.archive {
                Some(p) => Source::Archive(p),
                None => Source::Url(&url),
            };
            // Said only when something will be fetched.
            if let (Source::Url(u), Ok(Status::Missing | Status::Damaged(_))) =
                (source, check(&LENOVO, &a.dir))
            {
                eprintln!("validity-vendor: downloading {u}");
            }
            match install(&LENOVO, &a.dir, source) {
                Ok(Outcome::AlreadyInstalled(p)) => {
                    println!(
                        "validity-vendor: the vendor files are already in place in {}",
                        p.display()
                    );
                    ExitCode::SUCCESS
                }
                Ok(Outcome::Installed(p)) => {
                    println!("validity-vendor: vendor files installed in {}", p.display());
                    ExitCode::SUCCESS
                }
                Err(e @ (Error::Download { .. } | Error::NoCurl)) => {
                    eprintln!(
                        "validity-vendor: {e}\n\
                         The fingerprint sensor needs Lenovo's driver package; password login is\n\
                         not affected. Once online, run as root:  validity-vendor install\n\
                         Or download {} on another machine and run:\n\
                         \x20 validity-vendor install --archive nz3gf07w.exe",
                        LENOVO.url
                    );
                    ExitCode::from(3)
                }
                Err(e) => {
                    eprintln!("validity-vendor: {e}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
