use core::time;
use std::{error::Error, result::Result, io::Error as IoError, num::ParseIntError, fmt::{Display, Formatter, Result as FmtResult}, vec, env};
use tokio::{net::UdpSocket, main, spawn};

type TokioResult = Result<(), Box<dyn Error>>;

#[main]
async fn main() -> TokioResult {
    let tracing_subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(tracing_subscriber)?;
    
        
    let listen = spawn(listen_dns());
    match listen.await {
        Ok(_) => {
            tracing::info!("Listen exited");
        }
        Err(e) => {
            tracing::error!("Listen exited with error: {}", e);
        }
    }
        
    Ok(())
}

fn get_forward_lookup_zone() -> Option<String> {
    let mut zone: Option<String> = None;
    let mut zones: Vec<String> = Vec::new();
    let forward_lookup_zones = env::var("FORWARD_LOOKUP_ZONES");
    match forward_lookup_zones {
        Ok(z) => {
            let zone_split = z.split(",");
            for zone in zone_split {
                tracing::info!("Adding zone: {}", zone);
                zones.push(String::from(zone));
            }
        }
        Err(e) => {
            zones.push(String::from("8.8.8.8"));
        }
    }
    if zones.len() > 0 {
        zone = Some(zones[0].clone());
    }
    zone
}

type ListenResult = Result<i32, DnsError>;

#[tracing::instrument]
async fn listen_dns() -> ListenResult {
    let socket: UdpSocket;
    let socket_result = UdpSocket::bind("127.0.0.1:5300").await;
    match socket_result {
        Ok(s) => {
            tracing::info!("Listening on {}", s.local_addr()?);
            socket = s;
        }
        Err(e) => {
            tracing::error!("Failed to bind socket: {}", e);
            return Ok(1);
        }        
    }

    loop {
        let mut buf = [0; 512];
        let (size, addr) = socket.recv_from(&mut buf).await?;
        if size == 0 {
            continue;
        }
        tracing::info!("Received {} bytes from {}", size, addr);
        let buf = &mut buf[..size];
        tracing::debug!("Received: {:?}", buf);
        let header: Header;
        let header_result = Header::from_bytes(buf);
        match header_result {
            Ok(h) => {
                tracing::debug!("Header: {:?}", h);
                header = h;
            }
            Err(e) => {
                tracing::error!("Failed to parse header: {}", e);
                continue;
            }
        }
        let question: Question;
        let question_result = Question::from_bytes(buf, header.header_len);
        match question_result {
            Ok(q) => {
                tracing::debug!("Question: {:?}", q);
                question = q;
            }
            Err(e) => {
                tracing::error!("Failed to parse question: {}", e);
                continue;
            }
        }
        let mut response = Response::new(header, question);
        
        response.add_answer(Answer::new(
            question.name.clone(),
            1,
            1,
            3600,
            4,
            vec![127, 0, 0, 1],
        ));
        let mut buf = Vec::with_capacity(512);
        tracing::debug!("Response: {:?}", response);
        response.write(&mut buf)?;
        tracing::debug!("Response Buffer: {:?}", buf);
        socket.send_to(&buf, addr).await?;
    }
}

async fn forward_request(buf: &Vec<u8>, zone: String) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    let mut result: Vec<u8> = Vec::new();
    let forward_socket = UdpSocket::bind("127.0.0.1:5301").await?;
    let mut timeout: u32 = 30;
    // forward the request to the zone
    tracing::info!("Forwarding request to {}", zone);
    forward_socket.send_to(&buf, &zone).await?;
    while timeout > 0 {
        let mut receive_buf = [0; 512];
        let (size, addr) = forward_socket.recv_from(&mut receive_buf).await?;
        if size == 0 {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            timeout -= 1;
            continue;
        }
        tracing::info!("Received {} bytes from {}", size, addr);
        let receive_buf = &mut receive_buf[..size];
        tracing::debug!("Received: {:?}", receive_buf);
        result = receive_buf.to_vec();
        return Ok(Some(result));
    }
    // Timeout
    tracing::error!("Timeout waiting for response from {}", zone);
    Ok(None)
}
    

#[derive(Debug)]
enum DnsError {
    Io(IoError),
    Parse(ParseIntError),
    Other(String),
}

impl From<IoError> for DnsError {
    fn from(err: IoError) -> Self {
        DnsError::Io(err)
    }
}

impl From<ParseIntError> for DnsError {
    fn from(err: ParseIntError) -> Self {
        DnsError::Parse(err)
    }
}
impl From<&str> for DnsError {
    fn from(err: &str) -> Self {
        DnsError::Other(String::from(err))
    }
}
    
impl Display for DnsError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            DnsError::Io(err) => write!(f, "IO error: {}", err),
            DnsError::Parse(err) => write!(f, "Parse error: {}", err),
            DnsError::Other(err) => write!(f, "Dns Error: {}", err),
        }
    }
}

impl Error for DnsError {}

#[derive(Debug)]
struct Header {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
    header_len: usize,
}

type HeaderResult = Result<Header, DnsError>;

impl Header {
    fn from_bytes(buf: &[u8]) -> HeaderResult {
        let id = u16::from_be_bytes([buf[0], buf[1]]);
        let flags = u16::from_be_bytes([buf[2], buf[3]]);
        let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
        let ancount = u16::from_be_bytes([buf[6], buf[7]]);
        let nscount = u16::from_be_bytes([buf[8], buf[9]]);
        let arcount = u16::from_be_bytes([buf[10], buf[11]]);
        Ok(Header {
            id,
            flags,
            qdcount,
            ancount,
            nscount,
            arcount,
            header_len: 12,
        })
    }
}

#[derive(Debug, Copy, Clone)]
struct Question {
    name: & 'static str,
    qtype: u16,
    qclass: u16,
    question_len: usize,
}

type QuestionResult = Result<Question, DnsError>;

impl Question {
    fn new (name: & 'static str, qtype: u16, qclass: u16, question_len: usize) -> Self {
        Question {
            name,
            qtype,
            qclass,
            question_len: question_len,
        }
    }
    fn from_bytes(buf: &[u8], offset: usize) -> QuestionResult {
        let mut question_len = offset;
        let mut name = String::new();
        let mut i = offset;
        loop {
            let len = buf[i] as usize;
            if len == 0 {
                break;
            }
            if i != offset {
                name.push('.');
                question_len += 1;
            }
            for j in 0..len {
                name.push(buf[i + j + 1] as char);
            }
            i += len + 1;
            question_len += len + 1;
        }
        let qtype = u16::from_be_bytes([buf[i + 1], buf[i + 2]]);
        let qclass = u16::from_be_bytes([buf[i + 3], buf[i + 4]]);
        let name = Box::leak(name.into_boxed_str());
        question_len += 4;
        Ok(Question::new(name, qtype, qclass, question_len))
    }
}

impl Question {
    fn write(&self, buf: &mut Vec<u8>) {
        let name = self.name.clone();
        let name = name.split('.');
        for label in name {
            buf.push(label.len() as u8);
            for c in label.chars() {
                buf.push(c as u8);
            }
        }
        buf.push(0);
        buf.push(((self.qtype >> 8) & 0xff) as u8);
        buf.push((self.qtype & 0xff) as u8);
        buf.push(((self.qclass >> 8) & 0xff) as u8);
        buf.push((self.qclass & 0xff) as u8);
    }
}

#[derive(Debug)]
struct Answer {
    name: & 'static str,
    atype: u16,
    aclass: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

impl Answer {
    fn new(
        name: & 'static str,
        atype: u16,
        aclass: u16,
        ttl: u32,
        rdlength: u16,
        rdata: Vec<u8>,
    ) -> Self {
        Answer {
            name,
            atype,
            aclass,
            ttl,
            rdlength,
            rdata,
        }
    }

    fn write(&self, buf: &mut Vec<u8>) {
        let name = self.name.clone();
        let name = name.split('.');
        for label in name {
            buf.push(label.len() as u8);
            for c in label.chars() {
                buf.push(c as u8);
            }
        }
        buf.push(0);
        buf.push(((self.atype >> 8) & 0xff) as u8);
        buf.push((self.atype & 0xff) as u8);
        buf.push(((self.aclass >> 8) & 0xff) as u8);
        buf.push((self.aclass & 0xff) as u8);
        buf.push(((self.ttl >> 24) & 0xff) as u8);
        buf.push(((self.ttl >> 16) & 0xff) as u8);
        buf.push(((self.ttl >> 8) & 0xff) as u8);
        buf.push((self.ttl & 0xff) as u8);
        buf.push(((self.rdlength >> 8) & 0xff) as u8);
        buf.push((self.rdlength & 0xff) as u8);
        buf.append(&mut self.rdata.clone());
    }
}

#[derive(Debug)]
struct Response {
    header: Header,
    question: Question,
    answers: Vec<Answer>,
}

type WriteResult = Result<(), DnsError>;

impl Response {
    fn new(header: Header, question: Question) -> Self {
        Response {
            header,
            question,
            answers: Vec::new(),
        }
    }

    fn add_answer(&mut self, answer: Answer) {
        self.answers.push(answer);
    }

    fn write(&self, buf: &mut Vec<u8>) -> WriteResult {
        buf.push(((self.header.id >> 8) & 0xff) as u8);
        buf.push((self.header.id & 0xff) as u8);
        buf.push(((self.header.flags >> 8) & 0xff) as u8);
        buf.push((self.header.flags & 0xff) as u8);
        buf.push(((self.header.qdcount >> 8) & 0xff) as u8);
        buf.push((self.header.qdcount & 0xff) as u8);
        buf.push(((self.header.ancount >> 8) & 0xff) as u8);
        buf.push((self.header.ancount & 0xff) as u8);
        buf.push(((self.header.nscount >> 8) & 0xff) as u8);
        buf.push((self.header.nscount & 0xff) as u8);
        buf.push(((self.header.arcount >> 8) & 0xff) as u8);
        buf.push((self.header.arcount & 0xff) as u8);
        let mut question_buf = Vec::new();
        self.question.write(&mut question_buf);
        buf.append(&mut question_buf);
        for answer in &self.answers {
            answer.write(buf);
        }
        Ok(())
    }    
}