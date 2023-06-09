use std::{
    env,
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    io::Error as IoError,
    net::{SocketAddr, SocketAddrV6, SocketAddrV4},
    num::ParseIntError,
    result::{Result},
    vec, sync::Arc, f32::consts::E,
};
use futures::{channel::mpsc, StreamExt};
use tokio::net::UdpSocket;
use socket2::{Domain, Protocol, Socket, Type};

type TokioResult = Result<(), Box<dyn Error>>;

#[tokio::main]
async fn main() -> TokioResult {
    let tracing_subscriber = tracing_subscriber::fmt::Subscriber::builder()
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::set_global_default(tracing_subscriber)?;

    tokio::spawn(async move {
        tracing::info!("Starting UDP Listener (IP4)");
        let result = listen_dns_ip4().await;
        match result {
            Ok(_) => {
                tracing::info!("UDP Listener (IP4) running");
            }
            Err(e) => {
                tracing::error!("UDP Listener (IP4) exited with error: {}", e);
            }
        }
    });
    tokio::spawn(async move {
        tracing::info!("Starting UDP Listener (IP6)");
        let result = listen_dns_ip6().await;
        match result {
            Ok(_) => {
                tracing::info!("UDP Listener (IP6) running");
            }
            Err(e) => {
                tracing::error!("UDP Listener (IP6) exited with error: {}", e);
            }
        }
    });
    tracing::info!("Starting main thread");
    tracing::info!("Press Enter to exit");
    tokio::spawn(async move {
        // watch for enter key, confirm stop and continue if not
        loop {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            if input.trim() == "" {
                tracing::info!("Confirm Exit (y?)");
                // read key
                let input = console::Term::stdout().read_key().unwrap();
                if input == console::Key::Char('y') {
                    tracing::info!("Exiting");
                    std::process::exit(0);
                }                
            }
        }
    });
    loop{
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        tracing::debug!("Main thread sleeping");
    }
    Ok(())
}

fn get_forward_lookup_zones() -> Option<Vec<(Domain, String)>> {
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
        Err(_) => {
            // Ports required to parse IP addresses as zones
            // 53 - DNS
            // 67 - DHCP
            zones.push(String::from("8.8.8.8:53"));
        }
    }
    let mut result = zones.iter().map(|z | {
        // Match IPV4, IPV6 or Domain name
        let zone = z.parse::<SocketAddrV4>();
        match zone {
            Ok(_) => {
                tracing::info!("Zone {} is an IP Address", z);
                (Domain::IPV4, z.to_string())
            }
            Err(_) => {
                let zone = z.parse::<SocketAddrV6>();
                match zone {
                    Ok(_) => {
                        tracing::info!("Zone {} is an IP Address", z);
                        (Domain::IPV6, z.to_string())
                    }
                    Err(_) => {
                        tracing::warn!("Zone {} is Invalid", z);
                        (Domain::UNIX, z.to_string())
                    }
                }
            }
        }
    }).collect::<Vec<(Domain, String)>>();
    result.retain(|(d, _)| {
        match d {
            &Domain::UNIX => false,
            _ => true
        }
    });
    if result.len() == 0 {
        None
    } else {
        Some(result)
    }
}

type ListenResult = Result<i32, Box<dyn Error>>;


#[tracing::instrument]
async fn listen_dns_ip4() -> ListenResult {
    tracing::info!("Starting UDP Listener (IP4)");
    let listener = UdpSocket::bind("0.0.0.0:5300".parse::<SocketAddr>()?).await?;
    let r = Arc::new(listener);
    let s = r.clone();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);
    tokio::spawn(async move {
        let mut buf = [0; 512];
        loop {
            let (size, addr) = r.recv_from(&mut buf).await.expect("Failed to receive");
            let buf = buf[..size].to_vec();
            tx.clone().try_send((buf, addr)).expect("Failed to send");
        }
    });
    tokio::spawn(async move {
        while let Some((bytes, addr)) = rx.next().await {
            let socket = s.clone();
            tokio::spawn(async move {
                let result = process_request(&addr, &bytes).await;
                match result {
                    Some(buf) => {
                        match socket.send_to(&buf, &addr).await {
                            Ok(_) => {
                                tracing::info!("Sent response to {}", addr);
                            }
                            _ => {
                                tracing::error!("Failed to send response to {}", addr);
                            }
                        }
                        tracing::info!("Sent response to {}", addr);
                    }
                    _ => {
                        tracing::error!("Failed to send response to {}", addr);
                    }
                }
            });
        }
    });
    
    Ok(0)
}

#[tracing::instrument]
async fn listen_dns_ip6() -> ListenResult{
    // Set listen address
    tracing::info!("Starting UDP Listener (IP6)");
    let listener = get_udp_socket(Domain::IPV6, "[::]:5300")?;
    
    let r = Arc::new(listener);
    let s = r.clone();
    let (tx, mut rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1_000);
    tokio::spawn(async move {
        let mut buf = [0; 512];
        loop {
            let (size, addr) = r.recv_from(&mut buf).await.expect("Failed to receive");
            let buf = buf[..size].to_vec();
            tx.clone().try_send((buf, addr)).expect("Failed to send");
        }
    });
    tokio::spawn(async move {
        while let Some((bytes, addr)) = rx.next().await {
            let socket = s.clone();
            tokio::spawn(async move {
                let result = process_request(&addr, &bytes).await;
                match result {
                    Some(buf) => {
                        match socket.send_to(&buf, &addr).await {
                            Ok(_) => {
                                tracing::info!("Sent response to {}", addr);
                            }
                            _ => {
                                tracing::error!("Failed to send response to {}", addr);
                            }
                        }
                        tracing::info!("Sent response to {}", addr);
                    }
                    _ => {
                        tracing::error!("Failed to send response to {}", addr);
                    }
                }
            });
        }
    });
    
    Ok(0)
}

fn get_udp_socket(domain: Domain, address: &str) -> Result<UdpSocket, Box<dyn Error>> {
    let socket = Socket::new(
        domain,
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    match domain {
        Domain::IPV4 => {
            socket.set_only_v6(false)?;
            socket.bind(&socket2::SockAddr::from(address.parse::<SocketAddr>()?))?;
        }
        Domain::IPV6 => {
            socket.set_only_v6(true)?;
            socket.bind(&socket2::SockAddr::from(SocketAddrV6::from(address.parse().expect("Invalid IPv6 Address"))))?;
        }
        _ => {}
    }
    
    socket.set_nonblocking(true)?;
    socket.set_ttl(64)?;
    let std_listener:std::net::UdpSocket =  socket.into();
    let listener = tokio::net::UdpSocket::from_std(std_listener).expect("Failed to convert to tokio socket");
    Ok(listener)
}

async fn process_request(addr: &SocketAddr, bytes: &Vec<u8>) -> Option<Vec<u8>> {
    let buf = bytes as &[u8];
    tracing::info!("Received from {}", addr);
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
            return None;
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
            return None;
        }
    }
    let mut response = &Response::new(header, question);

    response = match get_answer(response).await {
        Ok(r) => {
            r
        }
        Err(e) => {
            tracing::error!("Failed to get answer: {}", e);
            return None;
        }
    };
    let mut buf = Vec::with_capacity(512);
    tracing::debug!("Response: {:?}", response);
    response.write(&mut buf).expect("msg too big");
    tracing::debug!("Response Buffer: {:?}", buf);
    Some(buf.clone())
}

async fn get_answer(response: &Response) -> Result<&Response, Box<dyn Error>> {
    // TODO - get answer from cache
    // Get answer from forward lookup
    Ok(check_forward_zones(response).await?)
    
    // TODO - get answer from reverse lookup
}

async fn check_forward_zones(response: &Response) -> Result<&Response, Box<dyn Error>>  {
    let zones = get_forward_lookup_zones();
    match zones {
        Some(z) => {
            for (domain, zone) in z {
                let mut buf = Vec::new();
                response.question.write(&mut buf);
                let result = forward_lookup(&zone, &buf, domain).await;
                match result {
                    Ok(r) => {
                        tracing::debug!("Forward Lookup Result: {:?}", r);
                        return Ok(Box::leak(Box::new(r)));
                    }
                    Err(e) => {
                        tracing::error!("Forward Lookup Error: {}", e);
                        return Err(e);
                    }
                }
            }
        }
        _ => {}
    }
    Err("No Forward Lookup Zones".into())
}

async fn forward_lookup(zone: &str, buf: &Vec<u8>, domain:Domain) -> Result<Response, Box<dyn Error>> {
    let socket = get_udp_socket(domain, zone)?;
    socket.send(buf).await?;
    let mut buf = [0; 512];
    let (size, _) = socket.recv_from(&mut buf).await?;
    let buf = buf[..size].to_vec();
    let header: Header;
    let header_result = Header::from_bytes(&buf);
    match header_result {
        Ok(h) => {
            tracing::debug!("Header: {:?}", h);
            header = h;
        }
        Err(e) => {
            tracing::error!("Failed to parse header: {}", e);
            return Err(e.into());
        }
    }
    let question: Question;
    let question_result = Question::from_bytes(&buf, header.header_len);
    match question_result {
        Ok(q) => {
            tracing::debug!("Question: {:?}", q);
            question = q;
        }
        Err(e) => {
            tracing::error!("Failed to parse question: {}", e);
            return Err(e.into());
        }
    }
    let mut response = Response::new(header, question);
    let mut answers: Vec<Answer> = Vec::new();
    let mut i = response.header.header_len + response.question.question_len;
    for _ in 0..response.header.ancount {
        let mut answer: Answer = Answer::new("", 0, 0, 0, 0, Vec::new());
        let answer_result = answer.from_bytes(&buf, i);
        match answer_result {
            Ok(a) => {
                tracing::debug!("Answer: {:?}", a);
                answer = a;
            }
            Err(e) => {
                tracing::error!("Failed to parse answer: {}", e);
                return Err(e.into());
            }
        }
        i += *(&answer.rdlength) as usize;
        answers.push(answer);
        
    }
    response.answers = answers;
    Ok(response)
}

#[derive(Debug)]
struct DnsError {
    error_type: DnsErrorType,
}

#[derive(Debug)]
enum DnsErrorType {
    Io(IoError),
    Parse(ParseIntError),
    Other(String),
}

impl DnsError {
    fn new(error_type: DnsErrorType) -> Self {
        DnsError { error_type }
    }
}

impl From<DnsErrorType> for DnsError {
    fn from(error_type: DnsErrorType) -> Self {
        DnsError::new(error_type)
    }
}

impl From<&str> for DnsError {
    fn from(err: &str) -> Self {
        DnsError::new(DnsErrorType::Other(String::from(err)))
    }
}

impl From<IoError> for DnsErrorType {
    fn from(err: IoError) -> Self {
        DnsErrorType::Io(err)
    }
}

impl From<ParseIntError> for DnsErrorType {
    fn from(err: ParseIntError) -> Self {
        DnsErrorType::Parse(err)
    }
}
impl From<&str> for DnsErrorType {
    fn from(err: &str) -> Self {
        DnsErrorType::Other(String::from(err))
    }
}

impl Display for DnsErrorType {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        match self {
            DnsErrorType::Io(err) => write!(f, "IO error: {}", err),
            DnsErrorType::Parse(err) => write!(f, "Parse error: {}", err),
            DnsErrorType::Other(err) => write!(f, "Dns Error: {}", err),
        }
    }
}
impl Display for DnsError {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "Dns Error: {}", self.error_type)
    }
}

impl Error for DnsError {}

impl Error for DnsErrorType {}

#[derive(Debug, Clone)]
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
    name: &'static str,
    qtype: u16,
    qclass: u16,
    question_len: usize,
}

type QuestionResult = Result<Question, DnsError>;

impl Question {
    fn new(name: &'static str, qtype: u16, qclass: u16, question_len: usize) -> Self {
        Question {
            name,
            qtype,
            qclass,
            question_len: question_len,
        }
    }
    #[tracing::instrument]
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
        let question = Question::new(name, qtype, qclass, question_len);
        tracing::debug!("Question {:?}", &question);
        Ok(question)
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

#[derive(Debug, Clone)]
struct Answer {
    name: &'static str,
    atype: u16,
    aclass: u16,
    ttl: u32,
    rdlength: u16,
    rdata: Vec<u8>,
}

impl Answer {
    fn new(
        name: &'static str,
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

    fn from_bytes(&self, buf: &Vec<u8>, index: usize) -> Result<Self, Box<dyn Error>>{
        let mut i = index;
        let mut name = String::new();
        loop {
            let len = buf[i];
            if len == 0 {
                break;
            }
            if i != index {
                name.push('.');
            }
            for j in 0..len {
                name.push(buf[i + j as usize + 1] as char);
            }
            i += len as usize + 1;
        }
        let atype = u16::from_be_bytes([buf[i + 1], buf[i + 2]]);
        let aclass = u16::from_be_bytes([buf[i + 3], buf[i + 4]]);
        let ttl = u32::from_be_bytes([
            buf[i + 5],
            buf[i + 6],
            buf[i + 7],
            buf[i + 8],
        ]);
        let rdlength = u16::from_be_bytes([buf[i + 9], buf[i + 10]]);
        let mut rdata = Vec::new();
        for j in 0..rdlength {
            rdata.push(buf[i + 11 + j as usize]);
        }
        Ok(Answer {
            name: Box::leak(name.into_boxed_str()),
            atype,
            aclass,
            ttl,
            rdlength,
            rdata,
        })
    }
}

#[derive(Debug, Clone)]
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

    fn add_answers(&mut self, answers: &mut Vec<Answer>) {
        self.answers.append(answers);
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
