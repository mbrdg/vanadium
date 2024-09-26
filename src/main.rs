use std::{
    collections::HashMap,
    env,
    fmt::Write as _,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::PathBuf,
    sync::Arc,
};

use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};

pub enum RequestStream {
    Tcp(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Read for RequestStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            RequestStream::Tcp(s) => s.read(buf),
            RequestStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for RequestStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            RequestStream::Tcp(s) => s.write(buf),
            RequestStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            RequestStream::Tcp(s) => s.flush(),
            RequestStream::Tls(s) => s.flush(),
        }
    }
}

#[derive(Default)]
pub struct RequestContext {
    inner: HashMap<(String, u16), BufReader<RequestStream>>,
}

impl RequestContext {
    fn build_reader(url: &Url) -> BufReader<RequestStream> {
        match url {
            Url::Http { addr, .. } => {
                let s = TcpStream::connect(addr).unwrap();
                BufReader::new(RequestStream::Tcp(s))
            }
            Url::Https { addr, .. } => {
                let s = TcpStream::connect(addr).unwrap();
                let root_store =
                    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let config = ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                let hostname = ServerName::try_from(addr.0.clone()).unwrap();
                let client = ClientConnection::new(Arc::new(config), hostname).unwrap();
                BufReader::new(RequestStream::Tls(Box::new(StreamOwned::new(client, s))))
            }
            _ => unreachable!(),
        }
    }

    pub fn stream(&mut self, url: &Url) -> &mut RequestStream {
        self.reader(url).get_mut()
    }

    pub fn reader(&mut self, url: &Url) -> &mut BufReader<RequestStream> {
        let (Url::Http { addr, .. } | Url::Https { addr, .. }) = url else {
            panic!("Unsupported variant in this context: {url:?}");
        };

        if !self.inner.contains_key(addr) {
            self.inner
                .insert((addr.0.clone(), addr.1), Self::build_reader(url));
        }

        self.inner.get_mut(addr).unwrap()
    }
}

#[derive(Clone, Debug)]
pub enum Url {
    Http {
        view_source: bool,
        addr: (String, u16),
        path: PathBuf,
    },
    Https {
        view_source: bool,
        addr: (String, u16),
        path: PathBuf,
    },
    File {
        view_source: bool,
        path: PathBuf,
    },
    Data {
        view_source: bool,
        media_type: String,
        content: String,
    },
}

impl Url {
    pub fn new(url: &str) -> Self {
        let view_source = url.starts_with("view-source:");
        let url = url.strip_prefix("view-source:").unwrap_or(url);

        if url.starts_with("data:") {
            let (media_type, content) = url.strip_prefix("data:").unwrap().split_once(',').unwrap();
            return Self::Data {
                view_source,
                media_type: media_type.to_string(),
                content: content.to_string(),
            };
        }

        let (scheme, url) = url.split_once("://").unwrap();
        if scheme == "file" {
            return Self::File {
                view_source,
                path: PathBuf::from(url),
            };
        }

        let mut remainder = url.to_string();
        if !remainder.contains('/') {
            remainder.push('/');
        }

        let (mut host, path) = remainder.split_once('/').unwrap();
        let mut port = match scheme {
            "http" => 80,
            "https" => 443,
            _ => panic!("Unsupported scheme: {scheme}"),
        };

        if host.contains(':') {
            let addr = host.split_once(':').unwrap();
            host = addr.0;
            port = addr.1.parse().unwrap();
        }

        match scheme {
            "http" => Self::Http {
                view_source,
                addr: (host.to_string(), port),
                path: PathBuf::from(format!("/{path}")),
            },
            "https" => Self::Https {
                view_source,
                addr: (host.to_string(), port),
                path: PathBuf::from(format!("/{path}")),
            },
            _ => panic!("Unsupported scheme: {scheme}"),
        }
    }

    fn display_host(&self) -> String {
        match self {
            Url::Http {
                addr: (host, 80), ..
            }
            | Url::Https {
                addr: (host, 443), ..
            } => host.to_string(),
            Url::Http {
                addr: (host, port), ..
            }
            | Url::Https {
                addr: (host, port), ..
            } => format!("{host}:{port}"),
            _ => panic!("`addr` are only available for http/https variants"),
        }
    }

    pub fn request(&self, ctx: &mut RequestContext) -> String {
        if let Self::File { path, .. } = self {
            let content = fs::read_to_string(path).unwrap();
            return content;
        }

        if let Self::Data { content, .. } = self {
            return content.to_string();
        }

        let (Self::Http { path, .. } | Self::Https { path, .. }) = self else {
            panic!("Network path is only available for http/https variants")
        };

        let mut request = String::new();
        write!(&mut request, "GET {} HTTP/1.1\r\n", path.display()).unwrap();
        write!(&mut request, "Host: {}\r\n", self.display_host()).unwrap();
        write!(&mut request, "Connection: keep-alive\r\n").unwrap();
        write!(&mut request, "User-Agent: vanadium/0.1.0\r\n").unwrap();
        write!(&mut request, "\r\n").unwrap();

        let s = ctx.stream(self);
        s.write_all(request.as_bytes()).unwrap();

        let response = ctx.reader(self);
        Url::read_response(response)
    }

    fn read_response(reader: &mut BufReader<RequestStream>) -> String {
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

        let content_length = response_headers
            .get("content-length")
            .expect("Missing content-length header in HTTP response")
            .parse::<usize>()
            .unwrap();
        let mut content = vec![0u8; content_length];
        reader.read_exact(&mut content).unwrap();

        String::from_utf8(content).unwrap()
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

fn load(url: &Url, ctx: &mut RequestContext) {
    let body = url.request(ctx);
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

    let mut ctx = RequestContext::default();
    load(&Url::new(url), &mut ctx);
}
