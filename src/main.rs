use std::{
    collections::HashMap,
    env,
    fmt::Write as _,
    fs,
    io::{BufRead, BufReader, Write as _},
    net::TcpStream,
    sync::Arc,
};

use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, Stream};

pub enum Url {
    Http {
        view_source: bool,
        host: String,
        port: u16,
        path: String,
    },
    Https {
        view_source: bool,
        host: String,
        port: u16,
        path: String,
    },
    File {
        view_source: bool,
        path: String,
    },
    Data {
        view_source: bool,
        content: String,
    },
}

impl Url {
    pub fn new(url: &str) -> Self {
        let view_source = url.starts_with("view-source:");
        let url = url.strip_prefix("view-source:").unwrap_or(url);

        if url.starts_with("data:") {
            let (mediatype, content) = url.strip_prefix("data:").unwrap().split_once(',').unwrap();
            assert!(
                mediatype == "text/html",
                "Unsupported media type: {mediatype}"
            );

            return Self::Data {
                view_source,
                content: content.to_string(),
            };
        }

        let (scheme, url) = url.split_once("://").unwrap();
        if scheme == "file" {
            return Self::File {
                view_source,
                path: url.to_string(),
            };
        }

        let mut remainder = url.to_string();
        if !remainder.contains('/') {
            remainder.push('/');
        }

        let (host, url) = remainder.split_once('/').unwrap();
        let mut host = host.to_string();
        let mut port = match scheme {
            "http" => 80,
            "https" => 443,
            _ => panic!("Unsupported scheme: {scheme}"),
        };
        let path = format!("/{url}");

        if host.contains(':') {
            let (h, p) = host.split_once(':').unwrap();
            port = p.parse().unwrap();
            host = h.to_string();
        }

        match scheme {
            "http" => Self::Http {
                view_source,
                host,
                port,
                path,
            },
            "https" => Self::Https {
                view_source,
                host,
                port,
                path,
            },
            _ => panic!("Unsupported scheme: {scheme}"),
        }
    }

    pub fn request(&self) -> String {
        if let Self::File { path, .. } = self {
            let content = fs::read_to_string(path).unwrap();
            return content;
        }

        if let Self::Data { content, .. } = self {
            return content.to_string();
        }

        let (host, port, path) = match self {
            Self::Http {
                host, port, path, ..
            }
            | Self::Https {
                host, port, path, ..
            } => (host.as_str(), *port, path.as_str()),
            _ => panic!("`host`, `port` and `path` are only available for http/https schemes"),
        };

        let mut s = TcpStream::connect((host, port)).unwrap();

        let mut request = String::new();
        write!(&mut request, "GET {path} HTTP/1.1\r\n").unwrap();
        write!(&mut request, "Host: {host}\r\n").unwrap();
        write!(&mut request, "Connection: close\r\n").unwrap();
        write!(&mut request, "User-Agent: vanadium/0.1.0\r\n").unwrap();
        write!(&mut request, "\r\n").unwrap();

        match self {
            Self::Http { .. } => {
                s.write_all(request.as_bytes()).unwrap();

                let mut response = BufReader::new(s);
                Url::read_response(&mut response)
            }
            Self::Https { host, .. } => {
                let root_store =
                    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let config = ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                let hostname = ServerName::try_from(host.clone()).unwrap();
                let mut client = ClientConnection::new(Arc::new(config), hostname).unwrap();
                let mut s = Stream::new(&mut client, &mut s);

                s.write_all(request.as_bytes()).unwrap();

                let mut response = BufReader::new(s);
                Url::read_response(&mut response)
            }
            _ => unreachable!(),
        }
    }

    fn read_response(reader: &mut impl BufRead) -> String {
        let mut statusline = String::new();
        reader.read_line(&mut statusline).unwrap();
        let mut parts = statusline.splitn(3, ' ');
        let _version = parts.next().unwrap();
        let _status = parts.next().unwrap();
        let _explanation = parts.next().unwrap();

        let mut response_headers = HashMap::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.trim_end().is_empty() {
                break;
            }

            let (header, value) = line.split_once(':').unwrap();
            response_headers.insert(header.to_lowercase(), value.trim().to_string());
        }

        assert!(!response_headers.contains_key("transfer-encoding"));
        assert!(!response_headers.contains_key("content-encoding"));

        let mut content = String::new();
        reader.read_to_string(&mut content).unwrap();
        content
    }
}

enum EntityReadError {
    Eof,
    Unsupported(usize),
}

fn read_entity(body: &str) -> Result<(usize, &'static str), EntityReadError> {
    assert!(body.starts_with('&'));
    match body.find(';') {
        Some(i) => match &body[1..i] {
            "lt" => Ok((i - 1, "<")),
            "gt" => Ok((i - 1, ">")),
            _ => Err(EntityReadError::Unsupported(i)),
        },
        None => Err(EntityReadError::Eof),
    }
}

fn show(body: &str) {
    let mut chars = body.char_indices();
    let mut in_tag = false;

    while let Some((i, c)) = chars.next() {
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if c == '&' {
            match read_entity(&body[i..]) {
                Ok((j, entity)) => {
                    print!("{entity}");
                    chars.nth(j);
                }
                Err(EntityReadError::Eof) => {
                    print!("{}", &body[i..]);
                    chars.nth(body[i..].len());
                }
                Err(EntityReadError::Unsupported(j)) => {
                    print!("{}", &body[i..=(i + j)]);
                    chars.nth(j);
                }
            }
        } else if !in_tag {
            print!("{c}");
        }
    }
}

fn show_source(body: &str) {
    for (number, line) in (1..).zip(body.lines()) {
        println!("{number:>6} {line}");
    }
}

fn load(url: &Url) {
    let body = url.request();
    let view_source = match url {
        Url::Http { view_source, .. }
        | Url::Https { view_source, .. }
        | Url::File { view_source, .. }
        | Url::Data { view_source, .. } => *view_source,
    };

    if view_source {
        show_source(&body);
    } else {
        show(&body);
    }
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let url = args.get(1).map_or(
        "file:///Users/mbrdg/Code/vanadium/README.md",
        String::as_str,
    );

    load(&Url::new(url));
}
