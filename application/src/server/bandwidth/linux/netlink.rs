use crate::io::SafeSliceExt;
use anyhow::{Context, ensure};
use netlink_packet_core::{
    DefaultNla, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_EXCL, NLM_F_REPLACE,
    NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_route::{
    RouteNetlinkMessage,
    link::{InfoKind, LinkAttribute, LinkFlags, LinkInfo, LinkMessage},
    tc::{
        TcAction, TcActionAttribute, TcActionMirrorOption, TcActionOption, TcActionType,
        TcAttribute, TcFilterMatchAllOption, TcHandle, TcMessage, TcMirror, TcMirrorActionType,
        TcOption, TcQdiscFqCodelOption,
    },
};
use rustix::{
    io::Errno,
    net::{
        self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType,
        netlink::SocketAddrNetlink,
    },
};
use std::{
    os::fd::OwnedFd,
    time::{Duration, Instant},
};

const TCA_TBF_PARMS: u16 = 1;
const TCA_TBF_RATE64: u16 = 4;
const TCA_TBF_BURST: u16 = 6;
const TC_LINKLAYER_ETHERNET: u8 = 1;
const ETH_P_ALL: u16 = 0x0003;
const FILTER_INFO: u32 = (1 << 16) | ETH_P_ALL.to_be() as u32;

const INGRESS_HANDLE: TcHandle = TcHandle {
    major: 0xffff,
    minor: 0,
};
const FILTER_HANDLE: TcHandle = TcHandle { major: 0, minor: 1 };
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    pub mtu: u32,
    pub flags: LinkFlags,
}

impl Link {
    pub fn is_up(&self) -> bool {
        self.flags.contains(LinkFlags::Up)
    }

    pub fn is_loopback(&self) -> bool {
        self.flags.contains(LinkFlags::Loopback)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shaping {
    pub rate: u64,
    pub burst: u32,
    pub memory: u32,
    pub packets: u32,
    pub quantum: u32,
    pub flows: u32,
    pub target: u32,
    pub interval: u32,
}

pub struct Route {
    socket: OwnedFd,
    sequence: u32,
}

impl Route {
    pub fn open() -> Result<Self, anyhow::Error> {
        let socket = net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            None,
        )
        .context("failed to open netlink socket")?;
        net::connect(&socket, &SocketAddrNetlink::new(0, 0))?;

        Ok(Self {
            socket,
            sequence: 0,
        })
    }

    pub fn links(&mut self) -> Result<Vec<Link>, anyhow::Error> {
        self.request(
            RouteNetlinkMessage::GetLink(LinkMessage::default()),
            NLM_F_DUMP,
        )?
        .into_iter()
        .filter_map(|reply| match reply {
            RouteNetlinkMessage::NewLink(message) => Some(parse_link(message)),
            _ => None,
        })
        .collect()
    }

    pub fn shape(
        &mut self,
        index: u32,
        handle: u16,
        shaping: Shaping,
    ) -> Result<(), anyhow::Error> {
        let root = TcHandle {
            major: handle,
            minor: 0,
        };
        let child = TcHandle {
            major: handle + 1,
            minor: 0,
        };
        let parent = TcHandle {
            major: handle,
            minor: 1,
        };

        self.set_qdisc(
            index,
            root,
            TcHandle::ROOT,
            "tbf",
            tbf_options(shaping)?,
            NLM_F_REPLACE,
        )?;

        match self.set_qdisc(
            index,
            child,
            parent,
            "fq_codel",
            fq_codel_options(shaping, true),
            NLM_F_REPLACE | NLM_F_EXCL,
        ) {
            Err(err) if errno(&err) == Some(Errno::EXIST) => self.set_qdisc(
                index,
                child,
                parent,
                "fq_codel",
                fq_codel_options(shaping, false),
                NLM_F_REPLACE,
            ),
            result => result,
        }
    }

    pub fn unshape(&mut self, index: u32, handle: u16) -> Result<(), anyhow::Error> {
        let message = tc_message(
            index,
            TcHandle {
                major: handle,
                minor: 0,
            },
            TcHandle::ROOT,
        )?;

        match self.request(RouteNetlinkMessage::DelQueueDiscipline(message), NLM_F_ACK) {
            Err(err) if matches!(errno(&err), Some(Errno::NOENT | Errno::INVAL)) => Ok(()),
            result => result.map(drop),
        }
    }

    pub fn add_ifb(&mut self, name: &str) -> Result<(), anyhow::Error> {
        let mut message = link_message(0, LinkFlags::Up);
        message.attributes = vec![
            LinkAttribute::IfName(name.into()),
            LinkAttribute::LinkInfo(vec![LinkInfo::Kind(InfoKind::Ifb)]),
        ];

        match self.request(
            RouteNetlinkMessage::NewLink(message),
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        ) {
            Err(err) if errno(&err) == Some(Errno::EXIST) => Ok(()),
            result => result.map(drop),
        }
        .context("failed to create ifb device")
    }

    pub fn set_up(&mut self, index: u32) -> Result<(), anyhow::Error> {
        self.request(
            RouteNetlinkMessage::NewLink(link_message(index, LinkFlags::Up)),
            NLM_F_ACK,
        )
        .map(drop)
    }

    pub fn delete_link(&mut self, index: u32) -> Result<(), anyhow::Error> {
        match self.request(
            RouteNetlinkMessage::DelLink(link_message(index, LinkFlags::empty())),
            NLM_F_ACK,
        ) {
            Err(err) if errno(&err) == Some(Errno::NODEV) => Ok(()),
            result => result.map(drop),
        }
    }

    pub fn add_ingress(&mut self, index: u32) -> Result<(), anyhow::Error> {
        let mut message = tc_message(index, INGRESS_HANDLE, TcHandle::INGRESS)?;
        message.attributes = vec![TcAttribute::Kind("ingress".into())];

        match self.request(
            RouteNetlinkMessage::NewQueueDiscipline(message),
            NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        ) {
            Err(err) if errno(&err) == Some(Errno::EXIST) => Ok(()),
            result => result.map(drop),
        }
        .context("failed to install ingress qdisc")
    }

    pub fn delete_ingress(&mut self, index: u32) -> Result<(), anyhow::Error> {
        let message = tc_message(index, INGRESS_HANDLE, TcHandle::INGRESS)?;

        match self.request(RouteNetlinkMessage::DelQueueDiscipline(message), NLM_F_ACK) {
            Err(err) if matches!(errno(&err), Some(Errno::NOENT | Errno::INVAL)) => Ok(()),
            result => result.map(drop),
        }
    }

    pub fn redirect(&mut self, index: u32, target: u32) -> Result<(), anyhow::Error> {
        let mut mirror = TcMirror::default();
        mirror.generic.action = TcActionType::Stolen;
        mirror.eaction = TcMirrorActionType::EgressRedir;
        mirror.ifindex = target;

        let mut action = TcAction::default();
        action.tab = 1;
        action.attributes = vec![
            TcActionAttribute::Kind("mirred".into()),
            TcActionAttribute::Options(vec![TcActionOption::Mirror(TcActionMirrorOption::Parms(
                mirror,
            ))]),
        ];

        let mut message = filter_message(index)?;
        message.attributes = vec![
            TcAttribute::Kind("matchall".into()),
            TcAttribute::Options(vec![TcOption::MatchAll(TcFilterMatchAllOption::Action(
                vec![action],
            ))]),
        ];

        let flags = NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
        match self.request(
            RouteNetlinkMessage::NewTrafficFilter(message.clone()),
            flags,
        ) {
            Err(err) if errno(&err) == Some(Errno::EXIST) => {
                self.request(
                    RouteNetlinkMessage::DelTrafficFilter(filter_message(index)?),
                    NLM_F_ACK,
                )?;
                self.request(RouteNetlinkMessage::NewTrafficFilter(message), flags)
            }
            result => result,
        }
        .context("failed to install ingress redirect")
        .map(drop)
    }

    fn set_qdisc(
        &mut self,
        index: u32,
        handle: TcHandle,
        parent: TcHandle,
        kind: &str,
        options: Vec<TcOption>,
        flags: u16,
    ) -> Result<(), anyhow::Error> {
        let mut message = tc_message(index, handle, parent)?;
        message.attributes = vec![
            TcAttribute::Kind(kind.into()),
            TcAttribute::Options(options),
        ];

        self.request(
            RouteNetlinkMessage::NewQueueDiscipline(message),
            NLM_F_ACK | NLM_F_CREATE | flags,
        )
        .with_context(|| format!("failed to install {kind} qdisc"))
        .map(drop)
    }

    fn request(
        &mut self,
        message: RouteNetlinkMessage,
        flags: u16,
    ) -> Result<Vec<RouteNetlinkMessage>, anyhow::Error> {
        self.sequence = self.sequence.wrapping_add(1);

        let mut header = NetlinkHeader::default();
        header.flags = flags | NLM_F_REQUEST;
        header.sequence_number = self.sequence;
        let mut request = NetlinkMessage::new(header, NetlinkPayload::from(message));
        request.finalize();
        let mut bytes = vec![0u8; request.buffer_len()];
        request.serialize(&mut bytes);

        ensure!(
            net::send(&self.socket, &bytes, SendFlags::empty())? == bytes.len(),
            "incomplete netlink request"
        );

        let deadline = Instant::now() + REQUEST_TIMEOUT;
        let mut buffer = vec![0u8; 65536];
        let mut replies = Vec::new();

        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .context("netlink request timed out")?;
            net::sockopt::set_socket_timeout(
                &self.socket,
                net::sockopt::Timeout::Recv,
                Some(remaining),
            )?;

            let (_, length, source) =
                match net::recvfrom(&self.socket, &mut buffer, RecvFlags::TRUNC) {
                    Err(Errno::INTR) => continue,
                    result => result.context("failed to receive netlink reply")?,
                };
            let source = SocketAddrNetlink::try_from(source.context("missing netlink sender")?)?;
            ensure!(
                source.pid() == 0,
                "netlink reply did not come from the kernel"
            );

            let mut messages = buffer
                .get_slice(..length)
                .context("truncated netlink datagram")?;
            while !messages.is_empty() {
                let reply = NetlinkMessage::<RouteNetlinkMessage>::deserialize(messages)
                    .context("invalid netlink reply")?;
                let length = reply.header.length as usize;
                messages = messages.get_slice(length.next_multiple_of(4).min(messages.len())..)?;

                if reply.header.sequence_number != self.sequence {
                    continue;
                }
                ensure!(
                    reply.header.flags & NLM_F_DUMP_INTR == 0,
                    "interrupted netlink dump"
                );

                match reply.payload {
                    NetlinkPayload::Error(error) if error.code.is_some() => {
                        return Err(error.to_io())
                            .context("netlink request rejected by the kernel");
                    }
                    NetlinkPayload::Error(_) | NetlinkPayload::Done(_) => return Ok(replies),
                    NetlinkPayload::InnerMessage(message) => replies.push(message),
                    _ => {}
                }
            }
        }
    }
}

fn errno(err: &anyhow::Error) -> Option<Errno> {
    err.chain().find_map(|cause| {
        Some(Errno::from_raw_os_error(
            cause.downcast_ref::<std::io::Error>()?.raw_os_error()?,
        ))
    })
}

fn link_message(index: u32, flags: LinkFlags) -> LinkMessage {
    let mut message = LinkMessage::default();
    message.header.index = index;
    message.header.flags = flags;
    message.header.change_mask = flags;

    message
}

fn parse_link(message: LinkMessage) -> Result<Link, anyhow::Error> {
    let mut name = None;
    let mut mtu = None;

    for attribute in message.attributes {
        match attribute {
            LinkAttribute::IfName(value) => name = Some(value),
            LinkAttribute::Mtu(value) => mtu = Some(value),
            _ => {}
        }
    }

    Ok(Link {
        index: message.header.index,
        name: name.context("kernel omitted interface name")?,
        mtu: mtu.context("kernel omitted interface mtu")?,
        flags: message.header.flags,
    })
}

fn tc_message(index: u32, handle: TcHandle, parent: TcHandle) -> Result<TcMessage, anyhow::Error> {
    let mut message = TcMessage::with_index(i32::try_from(index)?);
    message.header.handle = handle;
    message.header.parent = parent;

    Ok(message)
}

fn filter_message(index: u32) -> Result<TcMessage, anyhow::Error> {
    let mut message = tc_message(index, FILTER_HANDLE, INGRESS_HANDLE)?;
    message.header.info = FILTER_INFO;

    Ok(message)
}

fn tbf_parameters(shaping: Shaping) -> Result<Vec<u8>, anyhow::Error> {
    let mut parameters = Vec::with_capacity(36);
    parameters.extend([0, TC_LINKLAYER_ETHERNET]);
    parameters.extend(0u16.to_ne_bytes());
    parameters.extend((-1i16).to_ne_bytes());
    parameters.extend(0u16.to_ne_bytes());
    parameters.extend(u32::try_from(shaping.rate.min(u64::from(u32::MAX)))?.to_ne_bytes());
    parameters.extend([0u8; 12]);
    parameters.extend(shaping.memory.to_ne_bytes());
    parameters.extend([0u8; 8]);

    Ok(parameters)
}

fn tbf_options(shaping: Shaping) -> Result<Vec<TcOption>, anyhow::Error> {
    Ok(vec![
        TcOption::Other(DefaultNla::new(TCA_TBF_PARMS, tbf_parameters(shaping)?)),
        TcOption::Other(DefaultNla::new(
            TCA_TBF_RATE64,
            shaping.rate.to_ne_bytes().to_vec(),
        )),
        TcOption::Other(DefaultNla::new(
            TCA_TBF_BURST,
            shaping.burst.to_ne_bytes().to_vec(),
        )),
    ])
}

fn fq_codel_options(shaping: Shaping, create: bool) -> Vec<TcOption> {
    create
        .then_some(TcQdiscFqCodelOption::Flows(shaping.flows))
        .into_iter()
        .chain([
            TcQdiscFqCodelOption::Target(shaping.target),
            TcQdiscFqCodelOption::Limit(shaping.packets),
            TcQdiscFqCodelOption::Interval(shaping.interval),
            TcQdiscFqCodelOption::Ecn(1),
            TcQdiscFqCodelOption::Quantum(shaping.quantum),
            TcQdiscFqCodelOption::MemoryLimit(shaping.memory),
        ])
        .map(TcOption::FqCodel)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // tbf_parameters

    #[test]
    fn tbf_parameters_match_kernel_layout() {
        let shaping = Shaping {
            rate: 1_000_000,
            burst: 5000,
            memory: 65536,
            packets: 64,
            quantum: 1514,
            flows: 4096,
            target: 5000,
            interval: 100_000,
        };
        let parameters = tbf_parameters(shaping).unwrap();

        assert_eq!(parameters.len(), 36);
        assert_eq!(parameters.get(1), Some(&TC_LINKLAYER_ETHERNET));
        assert_eq!(parameters.get(8..12), Some(&1_000_000u32.to_ne_bytes()[..]));
        assert_eq!(parameters.get(24..28), Some(&65536u32.to_ne_bytes()[..]));

        let fast = tbf_parameters(Shaping {
            rate: 10_000_000_000,
            ..shaping
        })
        .unwrap();
        assert_eq!(fast.get(8..12), Some(&u32::MAX.to_ne_bytes()[..]));
    }
}
