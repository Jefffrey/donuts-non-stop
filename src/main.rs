use rand::Rng;
use std::{
    io::{Cursor, Error, ErrorKind, Read, Result},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    thread::sleep,
    time::Duration,
};

fn read_u8_from_cursor(cursor: &mut Cursor<impl AsRef<[u8]>>) -> Result<u8> {
    let mut b = [0; 1];
    cursor.read_exact(&mut b)?;
    Ok(u8::from_be_bytes(b))
}

fn read_u16_from_cursor(cursor: &mut Cursor<impl AsRef<[u8]>>) -> Result<u16> {
    let mut b = [0; 2];
    cursor.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

fn read_i16_from_cursor(cursor: &mut Cursor<impl AsRef<[u8]>>) -> Result<i16> {
    let mut b = [0; 2];
    cursor.read_exact(&mut b)?;
    Ok(i16::from_be_bytes(b))
}

fn read_u32_from_cursor(cursor: &mut Cursor<impl AsRef<[u8]>>) -> Result<u32> {
    let mut b = [0; 4];
    cursor.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn read_i32_from_cursor(cursor: &mut Cursor<impl AsRef<[u8]>>) -> Result<i32> {
    let mut b = [0; 4];
    cursor.read_exact(&mut b)?;
    Ok(i32::from_be_bytes(b))
}

fn read_character_string(cursor: &mut Cursor<impl AsRef<[u8]>>) -> Result<String> {
    let length = read_u8_from_cursor(cursor)?;

    // string
    let mut b = vec![0; length.into()];
    cursor.read_exact(&mut b)?;

    Ok(String::from_utf8_lossy(&b).into_owned())
}

fn read_domain_name(
    cursor: &mut Cursor<impl AsRef<[u8]>>,
    original_bytes: &[u8],
) -> Result<String> {
    let mut labels = vec![];
    loop {
        let length = read_u8_from_cursor(cursor)?;

        if length == 0 {
            // found null root, end
            break;
        } else if length & 0b_1100_0000 == 0b_1100_0000 {
            // pointer (message compression)
            // offset is 2 bytes (we already have 1), ensure clear the 2 flag bits at start
            let first_b = length & 0b_0011_1111;
            let second_b = read_u8_from_cursor(cursor)?;
            let offset = u16::from_be_bytes([first_b, second_b]);

            let mut r_cursor = Cursor::new(original_bytes);
            r_cursor.set_position(offset as u64);
            let pointed_string = read_domain_name(&mut r_cursor, original_bytes)?;

            if labels.is_empty() {
                return Ok(pointed_string);
            } else {
                let mut ret_str = labels.join(".");
                ret_str.push('.');
                ret_str.push_str(&pointed_string);
                return Ok(ret_str);
            }
        }

        // label
        let mut b = vec![0; length.into()];
        cursor.read_exact(&mut b)?;
        labels.push(String::from_utf8_lossy(&b).into_owned());
    }
    Ok(labels.join("."))
}

#[derive(Clone, Copy, Debug)]
enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

impl From<u8> for ResponseCode {
    fn from(b: u8) -> Self {
        match b {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            v => panic!("Unknown response code value: {v}"),
        }
    }
}

impl ResponseCode {
    fn value(&self) -> u8 {
        match *self {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
        }
    }
}

// TODO: AAAA, etc.
#[derive(Debug)]
enum RData {
    A(Ipv4Addr),
    NS(String),
    CNAME(String),
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
    MB(String),
    MG(String),
    MR(String),
    NULL(Vec<u8>),
    WKS {
        address: Ipv4Addr,
        protocol: u8,
        bit_map: Vec<u8>,
    },
    PTR(String),
    HINFO {
        cpu: String,
        os: String,
    },
    MINFO {
        rmailbx: String,
        emailbx: String,
    },
    MX {
        preference: i16,
        exchange: String,
    },
    TXT(Vec<String>),
}

impl RData {
    fn new(rrtype: u16, rdata: Vec<u8>, original_bytes: &[u8]) -> Result<Self> {
        match rrtype {
            1 => Ok(Self::A(Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            ))),
            2 => Ok(Self::NS(read_domain_name(
                &mut Cursor::new(&rdata),
                original_bytes,
            )?)),
            3 => Ok(Self::MX {
                preference: 0,
                exchange: read_domain_name(&mut Cursor::new(&rdata), original_bytes)?,
            }),
            4 => Ok(Self::MX {
                preference: 10,
                exchange: read_domain_name(&mut Cursor::new(&rdata), original_bytes)?,
            }),
            5 => Ok(Self::CNAME(read_domain_name(
                &mut Cursor::new(&rdata),
                original_bytes,
            )?)),
            6 => {
                let mut cursor = Cursor::new(&rdata);
                let mname = read_domain_name(&mut cursor, original_bytes)?;
                let rname = read_domain_name(&mut cursor, original_bytes)?;

                let serial = read_u32_from_cursor(&mut cursor)?;
                let refresh = read_i32_from_cursor(&mut cursor)?;
                let retry = read_i32_from_cursor(&mut cursor)?;
                let expire = read_i32_from_cursor(&mut cursor)?;
                let minimum = read_u32_from_cursor(&mut cursor)?;

                Ok(Self::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            7 => Ok(Self::MB(read_domain_name(
                &mut Cursor::new(&rdata),
                original_bytes,
            )?)),
            8 => Ok(Self::MG(read_domain_name(
                &mut Cursor::new(&rdata),
                original_bytes,
            )?)),
            9 => Ok(Self::MR(read_domain_name(
                &mut Cursor::new(&rdata),
                original_bytes,
            )?)),
            10 => Ok(Self::NULL(rdata)),
            11 => {
                let address = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);
                let protocol = rdata[4];
                let bit_map = rdata[5..].to_vec();
                Ok(Self::WKS {
                    address,
                    protocol,
                    bit_map,
                })
            } // WKS
            12 => Ok(Self::PTR(read_domain_name(
                &mut Cursor::new(&rdata),
                original_bytes,
            )?)),
            13 => {
                let mut cursor = Cursor::new(&rdata);
                let cpu = read_character_string(&mut cursor)?;
                let os = read_character_string(&mut cursor)?;
                Ok(Self::HINFO { cpu, os })
            }
            14 => {
                let mut cursor = Cursor::new(&rdata);
                let rmailbx = read_domain_name(&mut cursor, original_bytes)?;
                let emailbx = read_domain_name(&mut cursor, original_bytes)?;
                Ok(Self::MINFO { rmailbx, emailbx })
            }
            15 => {
                let mut cursor = Cursor::new(&rdata);
                Ok(Self::MX {
                    preference: read_i16_from_cursor(&mut cursor)?,
                    exchange: read_domain_name(&mut cursor, original_bytes)?,
                })
            }
            16 => {
                let mut cursor = Cursor::new(&rdata);
                let mut txt_data = vec![];
                while (cursor.position() as usize) < rdata.len() {
                    txt_data.push(read_character_string(&mut cursor)?);
                }
                Ok(Self::TXT(txt_data))
            }
            v => Err(Error::new(ErrorKind::Other, format!("Unknown rrtype: {v}"))),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Class {
    IN,
    CS,
    CH,
    HS,
}

impl Class {
    fn value(self) -> u16 {
        match self {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
        }
    }
}

impl From<u16> for Class {
    fn from(b: u16) -> Self {
        match b {
            1 => Class::IN,
            2 => Class::CS,
            3 => Class::CH,
            4 => Class::HS,
            v => panic!("Unknown class value: {v}"),
        }
    }
}

#[derive(Clone, Debug)]
struct Question {
    qname: String, // ensure no trailing .
    qtype: u16,    // A = 1 for ipv4
    qclass: Class, // IN = 1 for internet
}

#[derive(Debug)]
struct ResourceRecord {
    name: String,
    class: Class,
    ttl: i32,
    rdata: RData,
}

#[derive(Debug)]
struct Message {
    // header fields
    id: u16,             // 16 bits; usually random bits
    qr: u8,              // 1 bit; 0 if query, 1 if response
    opcode: u8,          // 4 bits; 0 if query, 1 if iquery, 2 if status
    aa: u8,              // 1 bit; 1 if response is authority of domain name
    tc: u8,              // 1 bit; 1 if truncated
    rd: u8,              // 1 bit; 1 if desire recursive query
    ra: u8,              // 1 bit; 1 if recursive query available
    z: u8,               // 3 bits; reserved for future, always 0
    rcode: ResponseCode, // 4 bits;
    // body fields
    questions: Vec<Question>,
    answers: Vec<ResourceRecord>,
    authority: Vec<ResourceRecord>,
    additional: Vec<ResourceRecord>,
}

impl Message {
    fn query(id: u16, questions: &[Question], recursive: bool) -> Self {
        Self {
            id,
            qr: 0,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: if recursive { 1 } else { 0 },
            ra: 0,
            z: 0,
            rcode: ResponseCode::NoError,
            questions: questions.to_vec(),
            answers: vec![],
            authority: vec![],
            additional: vec![],
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];

        /*
        header structure:
                                       1  1  1  1  1  1
         0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                      ID                       |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    QDCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ANCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    NSCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        |                    ARCOUNT                    |
        +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        */

        buf.extend(self.id.to_be_bytes());
        buf.push(self.qr << 7 | self.opcode << 3 | self.aa << 2 | self.tc << 1 | self.rd);
        buf.push(self.ra << 7 | self.z << 4 | self.rcode.value());
        buf.extend((self.questions.len() as u16).to_be_bytes()); // QDCOUNT
        buf.extend((self.answers.len() as u16).to_be_bytes()); // ANCOUNT
        buf.extend((self.authority.len() as u16).to_be_bytes()); // NSCOUNT
        buf.extend((self.additional.len() as u16).to_be_bytes()); // ARCOUNT

        // questions
        self.questions.iter().for_each(|q| {
            // QNAME
            q.qname.split('.').for_each(|label| {
                // prefix with length byte
                buf.push(label.as_bytes().len() as u8);
                // then add the name bytes
                buf.extend(label.as_bytes());
            });
            buf.push(0); // zero length null label for root

            buf.extend(q.qtype.to_be_bytes());
            buf.extend(q.qclass.value().to_be_bytes());
        });

        // TODO: A,A,A (but not necessary since we are client only?)

        buf
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);

        // header
        let id = read_u16_from_cursor(&mut cursor)?;

        let flg = read_u8_from_cursor(&mut cursor)?;
        let qr = flg >> 7; // don't need mask since will shift the other bits out anyway
        let opcode = (flg & 0b_0111_1000) >> 3;
        let aa = (flg & 0b_0000_0100) >> 2;
        let tc = (flg & 0b_0000_0010) >> 1;
        if tc != 0 {
            return Err(Error::new(ErrorKind::Other, "Message is truncated"));
        }
        let rd = flg & 0b_0000_0001;

        let flg = read_u8_from_cursor(&mut cursor)?;
        let ra = flg >> 7;
        let z = (flg & 0b_0111_0000) >> 4;
        let rcode = (flg & 0b_0000_1111).into();

        let qdcount = read_u16_from_cursor(&mut cursor)?;
        let ancount = read_u16_from_cursor(&mut cursor)?;
        let nscount = read_u16_from_cursor(&mut cursor)?;
        let arcount = read_u16_from_cursor(&mut cursor)?;

        // questions
        let questions = (0..qdcount)
            .map(|_| {
                let qname = read_domain_name(&mut cursor, bytes)?;
                let qtype = read_u16_from_cursor(&mut cursor)?;
                let qclass = read_u16_from_cursor(&mut cursor)?.into();

                Ok(Question {
                    qname,
                    qtype,
                    qclass,
                })
            })
            .collect::<Result<Vec<Question>>>()?;

        // answer
        let answers = (0..ancount)
            .map(|_| Self::parse_resource_record(&mut cursor, bytes))
            .collect::<Result<Vec<ResourceRecord>>>()?;

        // authority
        let authority = (0..nscount)
            .map(|_| Self::parse_resource_record(&mut cursor, bytes))
            .collect::<Result<Vec<ResourceRecord>>>()?;

        // additional
        let additional = (0..arcount)
            .map(|_| Self::parse_resource_record(&mut cursor, bytes))
            .collect::<Result<Vec<ResourceRecord>>>()?;

        Ok(Message {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            questions,
            answers,
            authority,
            additional,
        })
    }

    fn parse_resource_record(
        cursor: &mut Cursor<impl AsRef<[u8]>>,
        original_bytes: &[u8],
    ) -> Result<ResourceRecord> {
        let name = read_domain_name(cursor, original_bytes)?;

        let rrtype = read_u16_from_cursor(cursor)?;
        let class = read_u16_from_cursor(cursor)?.into();
        let ttl = read_i32_from_cursor(cursor)?;
        let rdlength = read_u16_from_cursor(cursor)?;

        let mut rdata = vec![0; rdlength.into()];
        cursor.read_exact(&mut rdata)?;
        let rdata = RData::new(rrtype, rdata, original_bytes)?;

        Ok(ResourceRecord {
            name,
            class,
            ttl,
            rdata,
        })
    }
}

fn main() -> Result<()> {
    let mut args = std::env::args();
    args.next(); // program name

    let resolve_name = args
        .next()
        .map(|s| {
            // ensure no trailing dot as this is hardcoded later on
            if s.ends_with('.') {
                s[..s.len() - 1].to_string()
            } else {
                s
            }
        })
        .expect("No name to resolve");

    let dns_server = args
        .next()
        .and_then(|s| s.parse::<SocketAddrV4>().ok())
        // Cloudflare default
        .unwrap_or_else(|| SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53));

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;

    let mut rng = rand::thread_rng();
    let id = rng.gen();
    let send_buffer = Message::query(
        id,
        &[Question {
            qname: resolve_name,
            qtype: 1,
            qclass: 1.into(),
        }],
        true,
    )
    .to_bytes();

    // send
    println!("Sending!");
    for _ in 0..1 {
        socket.send_to(&send_buffer, dns_server)?;
        sleep(Duration::from_millis(100));
    }

    let mut recv_buffer = vec![0; 512];
    let (len, addr) = socket.recv_from(&mut recv_buffer)?;
    println!("Received {len} bytes from {addr}");
    let recv_message = Message::from_bytes(&recv_buffer)?;
    println!("Response: {:?}", recv_message);

    Ok(())
}
