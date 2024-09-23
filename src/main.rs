use std::{
    collections::HashMap,
    env,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
};

struct Url {
    // scheme: String,
    host: String,
    path: String,
}

impl Url {
    fn new(url: &str) -> Self {
        let mut parts = url.splitn(2, "://");

        let scheme = parts.next().unwrap().to_string();
        assert!(&scheme == "http", "Unsupported scheme: {scheme}");

        let mut remainder = parts.next().unwrap().to_string();
        if !remainder.contains('/') {
            remainder.push('/');
        }

        let mut parts = remainder.splitn(2, '/');

        let host = parts.next().unwrap().to_string();
        let mut path = String::from('/');
        path.push_str(parts.next().unwrap());

        Url { host, path }
    }

    fn request(&self) -> String {
        let mut s = TcpStream::connect((self.host.as_str(), 80)).unwrap();

        let request = format!("GET {} HTTP/1.0\r\nHOST: {}\r\n\r\n", self.path, self.host);
        s.write_all(request.as_bytes()).unwrap();

        let mut response = BufReader::new(s);

        let mut statusline = String::new();
        response.read_line(&mut statusline).unwrap();
        let mut parts = statusline.splitn(3, ' ');
        let _version = parts.next().unwrap();
        let _status = parts.next().unwrap();
        let _explanation = parts.next().unwrap();

        let mut response_headers = HashMap::new();
        loop {
            let mut line = String::new();
            response.read_line(&mut line).unwrap();
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
        response.read_to_string(&mut content).unwrap();
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
