use std::{
    collections::HashMap,
    env,
    fmt::Write as _,
    io::{BufRead, BufReader, Write as _},
    net::TcpStream,
    sync::Arc,
};

use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, Stream};

pub struct Url {
    scheme: String,
    host: String,
    path: String,
    port: u16,
}

impl Url {
    pub fn new(url: &str) -> Self {
        let mut parts = url.splitn(2, "://");
        let scheme = parts.next().unwrap().to_string();

        let mut port = match scheme.as_str() {
            "http" => 80,
            "https" => 443,
            _ => panic!("Unsupported scheme: {scheme}"),
        };

        let mut remainder = parts.next().unwrap().to_string();
        if !remainder.contains('/') {
            remainder.push('/');
        }

        let mut parts = remainder.splitn(2, '/');
        let mut host = parts.next().unwrap().to_string();
        let mut path = String::from('/');
        path.push_str(parts.next().unwrap());

        if host.contains(':') {
            let mut parts = host.splitn(2, ':');
            let name = parts.next().unwrap().to_string();
            port = parts.next().unwrap().parse().unwrap();
            host = name;
        }

        Url {
            scheme,
            host,
            path,
            port,
        }
    }

    pub fn request(&self) -> String {
        let mut s = TcpStream::connect((self.host.as_str(), self.port)).unwrap();

        let mut request = String::new();
        write!(&mut request, "GET {} HTTP/1.1\r\n", self.path).unwrap();
        write!(&mut request, "Host: {}\r\n", self.host).unwrap();
        write!(&mut request, "Connection: close\r\n").unwrap();
        write!(&mut request, "User-Agent: vanadium/0.1.0\r\n").unwrap();
        write!(&mut request, "\r\n").unwrap();

        match self.scheme.as_str() {
            "http" => {
                s.write_all(request.as_bytes()).unwrap();

                let mut response = BufReader::new(s);
                Url::read_response(&mut response)
            }
            "https" => {
                let root_store =
                    RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let config = ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                let hostname = ServerName::try_from(self.host.clone()).unwrap();
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

            let mut parts = line.splitn(2, ':');
            let header = parts.next().unwrap().to_lowercase();
            let value = parts.next().unwrap().trim().to_string();
            response_headers.insert(header, value);
        }

        assert!(!response_headers.contains_key("transfer-encoding"));
        assert!(!response_headers.contains_key("content-encoding"));

        let mut content = String::new();
        reader.read_to_string(&mut content).unwrap();
        content
    }
}

fn show(body: &str) {
    let mut in_tag = false;
    for c in body.chars() {
        if c == '<' {
            in_tag = true;
        } else if c == '>' {
            in_tag = false;
        } else if !in_tag {
            print!("{c}");
        }
    }
}

fn load(url: &Url) {
    let body = url.request();
    show(&body)
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    load(&Url::new(&args[1]));
}
