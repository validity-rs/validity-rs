//! A local HTTP mirror for the tests: serves fixed bodies by path on 127.0.0.1,
//! counts the requests, answers 404 for anything else. Enough HTTP/1.1 for curl.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone)]
pub struct Mirror {
    port: u16,
    files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    hits: Arc<AtomicUsize>,
}

impl Mirror {
    pub fn start() -> Mirror {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("address").port();
        let m = Mirror {
            port,
            files: Arc::default(),
            hits: Arc::default(),
        };
        let served = m.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let s = served.clone();
                std::thread::spawn(move || s.answer(stream));
            }
        });
        m
    }

    /// Serves `body` at `path` (replacing what was there).
    pub fn put(&self, path: &str, body: Vec<u8>) {
        self.files.lock().unwrap().insert(path.to_string(), body);
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{path}", self.port)
    }

    /// Requests received so far, whatever the path.
    pub fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn answer(&self, stream: TcpStream) {
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        // Skip the headers.
        loop {
            let mut h = String::new();
            if reader.read_line(&mut h).is_err() || h == "\r\n" || h.is_empty() {
                break;
            }
        }
        self.hits.fetch_add(1, Ordering::SeqCst);
        let path = line.split_whitespace().nth(1).unwrap_or("").to_string();
        let body = self.files.lock().unwrap().get(&path).cloned();
        let mut out = stream;
        let _ = match body {
            Some(b) => out
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        b.len()
                    )
                    .as_bytes(),
                )
                .and_then(|()| out.write_all(&b)),
            None => out.write_all(
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ),
        };
    }
}

/// A local URL nothing listens on: the connection is refused, as offline.
pub fn unreachable_url() -> String {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().expect("address").port();
    drop(l);
    format!("http://127.0.0.1:{port}/nz3gf07w.exe")
}
