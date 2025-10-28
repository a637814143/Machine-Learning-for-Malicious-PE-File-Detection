"""Utility helpers for PCAP feature extraction and flow aggregation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

import socket
import statistics

import dpkt

__all__ = [
    "PacketInfo",
    "FlowAccumulator",
    "iterate_packets",
    "build_flows",
    "flow_to_feature_dict",
    "extract_flow_features",
]


_ACTIVITY_TIMEOUT = 1.0  # seconds separating active/idle periods
_MICROSECONDS = 1_000_000.0


@dataclass
class PacketInfo:
    """Normalized packet representation used for aggregation."""

    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    total_length: int
    header_length: int
    payload_length: int
    tcp_flags: int = 0
    tcp_window: int = 0
    is_forward: bool = True
    has_payload: bool = False


@dataclass
class FlowAccumulator:
    """Stateful accumulator that tracks bidirectional flow statistics."""

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    start_time: float

    total_packets: int = 0
    total_bytes: int = 0
    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0
    forward_header_bytes: int = 0
    backward_header_bytes: int = 0
    forward_payload_bytes: int = 0
    backward_payload_bytes: int = 0

    packet_lengths: List[int] = field(default_factory=list)
    forward_packet_lengths: List[int] = field(default_factory=list)
    backward_packet_lengths: List[int] = field(default_factory=list)
    flow_iats: List[float] = field(default_factory=list)
    forward_iats: List[float] = field(default_factory=list)
    backward_iats: List[float] = field(default_factory=list)

    fwd_psh_flags: int = 0
    bwd_psh_flags: int = 0
    fwd_urg_flags: int = 0
    bwd_urg_flags: int = 0

    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwr_count: int = 0
    ece_count: int = 0

    down_up_ratio: float = 0.0
    avg_packet_size: float = 0.0
    avg_fwd_segment_size: float = 0.0
    avg_bwd_segment_size: float = 0.0

    init_win_bytes_forward: int = 0
    init_win_bytes_backward: int = 0
    act_data_pkt_fwd: int = 0
    min_seg_size_forward: int = 0

    active_durations: List[float] = field(default_factory=list)
    idle_durations: List[float] = field(default_factory=list)

    subflow_forward_packets: List[int] = field(default_factory=list)
    subflow_forward_bytes: List[int] = field(default_factory=list)
    subflow_backward_packets: List[int] = field(default_factory=list)
    subflow_backward_bytes: List[int] = field(default_factory=list)

    last_timestamp: Optional[float] = None
    last_forward_timestamp: Optional[float] = None
    last_backward_timestamp: Optional[float] = None
    current_active_start: Optional[float] = None

    current_subflow_start: Optional[float] = None
    current_subflow_forward_packets: int = 0
    current_subflow_forward_bytes: int = 0
    current_subflow_backward_packets: int = 0
    current_subflow_backward_bytes: int = 0

    end_time: Optional[float] = None

    def add_packet(self, packet: PacketInfo) -> None:
        """Update statistics with a new packet."""

        if self.total_packets == 0:
            self.current_active_start = packet.timestamp
            self.current_subflow_start = packet.timestamp

        if self.last_timestamp is not None:
            delta = packet.timestamp - self.last_timestamp
            if delta > 0:
                self.flow_iats.append(delta)
            if delta > _ACTIVITY_TIMEOUT:
                self._finalize_active_period(packet.timestamp)
                self._finalize_subflow()
                self.current_active_start = packet.timestamp
                self.current_subflow_start = packet.timestamp
                self.idle_durations.append(delta)
        else:
            self.current_active_start = packet.timestamp
            self.current_subflow_start = packet.timestamp

        self.total_packets += 1
        self.total_bytes += packet.total_length
        self.packet_lengths.append(packet.total_length)
        self.end_time = packet.timestamp

        if packet.is_forward:
            self.forward_packets += 1
            self.forward_bytes += packet.total_length
            self.forward_header_bytes += packet.header_length
            self.forward_payload_bytes += packet.payload_length
            self.forward_packet_lengths.append(packet.total_length)
            if self.last_forward_timestamp is not None:
                delta = packet.timestamp - self.last_forward_timestamp
                if delta > 0:
                    self.forward_iats.append(delta)
            self.last_forward_timestamp = packet.timestamp
            if packet.tcp_flags:
                self._count_directional_flags(packet.tcp_flags, forward=True)
                if self.forward_packets == 1 and packet.tcp_window:
                    self.init_win_bytes_forward = packet.tcp_window
            if packet.has_payload:
                self.act_data_pkt_fwd += 1
                if self.min_seg_size_forward == 0:
                    self.min_seg_size_forward = packet.payload_length
                else:
                    self.min_seg_size_forward = min(
                        self.min_seg_size_forward, packet.payload_length or packet.total_length
                    )
            self.current_subflow_forward_packets += 1
            self.current_subflow_forward_bytes += packet.total_length
        else:
            self.backward_packets += 1
            self.backward_bytes += packet.total_length
            self.backward_header_bytes += packet.header_length
            self.backward_payload_bytes += packet.payload_length
            self.backward_packet_lengths.append(packet.total_length)
            if self.last_backward_timestamp is not None:
                delta = packet.timestamp - self.last_backward_timestamp
                if delta > 0:
                    self.backward_iats.append(delta)
            self.last_backward_timestamp = packet.timestamp
            if packet.tcp_flags:
                self._count_directional_flags(packet.tcp_flags, forward=False)
                if self.backward_packets == 1 and packet.tcp_window:
                    self.init_win_bytes_backward = packet.tcp_window
            self.current_subflow_backward_packets += 1
            self.current_subflow_backward_bytes += packet.total_length

        if packet.tcp_flags:
            self._count_flow_flags(packet.tcp_flags)

        self.last_timestamp = packet.timestamp

    def finalize(self) -> None:
        """Finalize active periods and subflows after processing."""

        self._finalize_active_period(self.end_time)
        self._finalize_subflow()
        self._compute_ratios()

    def _finalize_active_period(self, reference_time: Optional[float]) -> None:
        if self.current_active_start is not None and self.last_timestamp is not None:
            active_duration = self.last_timestamp - self.current_active_start
            if active_duration > 0:
                self.active_durations.append(active_duration)
        self.current_active_start = reference_time

    def _finalize_subflow(self) -> None:
        if self.current_subflow_start is None:
            return
        if self.current_subflow_forward_packets or self.current_subflow_backward_packets:
            self.subflow_forward_packets.append(self.current_subflow_forward_packets)
            self.subflow_forward_bytes.append(self.current_subflow_forward_bytes)
            self.subflow_backward_packets.append(self.current_subflow_backward_packets)
            self.subflow_backward_bytes.append(self.current_subflow_backward_bytes)
        self.current_subflow_forward_packets = 0
        self.current_subflow_forward_bytes = 0
        self.current_subflow_backward_packets = 0
        self.current_subflow_backward_bytes = 0
        self.current_subflow_start = None

    def _count_directional_flags(self, flags: int, *, forward: bool) -> None:
        if flags & dpkt.tcp.TH_PUSH:
            if forward:
                self.fwd_psh_flags += 1
            else:
                self.bwd_psh_flags += 1
        if flags & dpkt.tcp.TH_URG:
            if forward:
                self.fwd_urg_flags += 1
            else:
                self.bwd_urg_flags += 1

    def _count_flow_flags(self, flags: int) -> None:
        if flags & dpkt.tcp.TH_FIN:
            self.fin_count += 1
        if flags & dpkt.tcp.TH_SYN:
            self.syn_count += 1
        if flags & dpkt.tcp.TH_RST:
            self.rst_count += 1
        if flags & dpkt.tcp.TH_PUSH:
            self.psh_count += 1
        if flags & dpkt.tcp.TH_ACK:
            self.ack_count += 1
        if flags & dpkt.tcp.TH_URG:
            self.urg_count += 1
        if flags & dpkt.tcp.TH_CWR:
            self.cwr_count += 1
        if flags & dpkt.tcp.TH_ECE:
            self.ece_count += 1

    def _compute_ratios(self) -> None:
        if self.forward_packets:
            self.down_up_ratio = self.backward_packets / self.forward_packets
        else:
            self.down_up_ratio = 0.0

        if self.total_packets:
            self.avg_packet_size = self.total_bytes / self.total_packets
        else:
            self.avg_packet_size = 0.0

        if self.forward_packets:
            self.avg_fwd_segment_size = self.forward_bytes / self.forward_packets
        else:
            self.avg_fwd_segment_size = 0.0

        if self.backward_packets:
            self.avg_bwd_segment_size = self.backward_bytes / self.backward_packets
        else:
            self.avg_bwd_segment_size = 0.0


def _inet_to_str(address: bytes) -> str:
    """Convert raw IP bytes to a human readable string."""

    try:
        if len(address) == 4:
            return socket.inet_ntop(socket.AF_INET, address)
        if len(address) == 16:
            return socket.inet_ntop(socket.AF_INET6, address)
    except (ValueError, OSError):
        pass
    return "0.0.0.0"


def _stats(values: List[float]) -> Tuple[float, float, float, float]:
    """Return (mean, std, maximum, minimum) for a list of floats."""

    if not values:
        return (0.0, 0.0, 0.0, 0.0)
    if len(values) == 1:
        v = values[0]
        return (v, 0.0, v, v)
    mean_val = statistics.fmean(values)
    std_val = statistics.pstdev(values)
    return (mean_val, std_val, max(values), min(values))


def _variance(values: List[float]) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return 0.0
    return statistics.pvariance(values)


PCAP_HEADER_MAGIC = {
    b"\xd4\xc3\xb2\xa1",  # little endian, microsecond resolution
    b"\xa1\xb2\xc3\xd4",  # big endian, microsecond resolution
    b"\x4d\x3c\xb2\xa1",  # little endian, nanosecond resolution
    b"\xa1\xb2\x3c\x4d",  # big endian, nanosecond resolution
}
PCAPNG_HEADER_MAGIC = b"\x0a\x0d\x0d\x0a"


def _try_read_pcap(path: Path) -> Iterator[Tuple[float, bytes]]:
    with path.open("rb") as fh:
        header = fh.read(4)
        fh.seek(0)

        if header in PCAP_HEADER_MAGIC:
            reader: Iterator[Tuple[float, bytes]] = dpkt.pcap.Reader(fh)
        elif header == PCAPNG_HEADER_MAGIC:
            reader = dpkt.pcapng.Reader(fh)
        else:  # pragma: no cover - defensive branch for unknown formats
            raise ValueError("Unsupported PCAP header signature; expected PCAP or PCAPNG data")

        for timestamp, buf in reader:
            yield timestamp, buf


def _packet_from_buf(timestamp: float, buf: bytes) -> Optional[PacketInfo]:
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except (dpkt.UnpackError, ValueError):
        return None

    ip = eth.data
    if isinstance(ip, dpkt.ip.IP):
        src_ip = _inet_to_str(ip.src)
        dst_ip = _inet_to_str(ip.dst)
        protocol = ip.p
        ip_header_length = ip.hl * 4
        total_length = int(ip.len)
    elif isinstance(ip, dpkt.ip6.IP6):
        src_ip = _inet_to_str(ip.src)
        dst_ip = _inet_to_str(ip.dst)
        protocol = ip.nxt
        ip_header_length = 40
        total_length = ip.plen + ip_header_length
    else:
        return None

    transport = ip.data
    src_port = 0
    dst_port = 0
    tcp_flags = 0
    tcp_window = 0
    header_length = ip_header_length
    payload_length = 0
    has_payload = False

    if isinstance(transport, dpkt.tcp.TCP):
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        tcp_flags = transport.flags
        tcp_window = int(transport.win)
        header_length += transport.off * 4
        payload_length = len(transport.data)
        has_payload = payload_length > 0
    elif isinstance(transport, dpkt.udp.UDP):
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
        header_length += 8
        payload_length = len(transport.data)
        has_payload = payload_length > 0
    elif isinstance(transport, dpkt.icmp.ICMP) or isinstance(transport, dpkt.icmp6.ICMP6):
        header_length += 8
        payload_length = len(transport.data)
    else:
        payload_length = len(bytes(transport)) if hasattr(transport, "__bytes__") else 0

    if total_length == 0:
        total_length = ip_header_length + payload_length

    return PacketInfo(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        total_length=total_length,
        header_length=header_length,
        payload_length=payload_length,
        tcp_flags=tcp_flags,
        tcp_window=tcp_window,
        has_payload=has_payload,
    )


def iterate_packets(path: Path) -> Iterator[PacketInfo]:
    """Iterate packets from a pcap file as :class:`PacketInfo` objects."""

    for timestamp, buf in _try_read_pcap(path):
        packet = _packet_from_buf(timestamp, buf)
        if packet is not None:
            yield packet


def build_flows(packets: Iterable[PacketInfo]) -> Dict[str, FlowAccumulator]:
    """Group packets by five-tuple and accumulate bidirectional statistics."""

    flows: Dict[str, FlowAccumulator] = {}

    for packet in packets:
        flow_id = "-".join([packet.src_ip, str(packet.src_port), packet.dst_ip, str(packet.dst_port), str(packet.protocol)])

        accumulator: Optional[FlowAccumulator] = None
        is_forward = True

        if flow_id in flows:
            accumulator = flows[flow_id]
            is_forward = True
        else:
            reverse_flow_id = "-".join([packet.dst_ip, str(packet.dst_port), packet.src_ip, str(packet.src_port), str(packet.protocol)])
            if reverse_flow_id in flows:
                accumulator = flows[reverse_flow_id]
                flow_id = reverse_flow_id
                is_forward = False
            else:
                accumulator = FlowAccumulator(
                    flow_id=flow_id,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    src_port=packet.src_port,
                    dst_port=packet.dst_port,
                    protocol=packet.protocol,
                    start_time=packet.timestamp,
                )
                flows[flow_id] = accumulator

        packet.is_forward = is_forward
        accumulator.add_packet(packet)

    for accumulator in flows.values():
        accumulator.finalize()

    return flows


def flow_to_feature_dict(flow: FlowAccumulator) -> Dict[str, object]:
    """Convert an accumulator into the requested feature dictionary."""

    duration = (flow.end_time - flow.start_time) if flow.end_time is not None else 0.0
    duration_seconds = max(duration, 0.0)
    duration_microseconds = duration_seconds * _MICROSECONDS

    flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _stats(flow.flow_iats)
    fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _stats(flow.forward_iats)
    bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _stats(flow.backward_iats)

    flow_iat_mean *= _MICROSECONDS
    flow_iat_std *= _MICROSECONDS
    flow_iat_max *= _MICROSECONDS
    flow_iat_min *= _MICROSECONDS

    fwd_iat_total = sum(flow.forward_iats) * _MICROSECONDS
    bwd_iat_total = sum(flow.backward_iats) * _MICROSECONDS

    fwd_iat_mean *= _MICROSECONDS
    fwd_iat_std *= _MICROSECONDS
    fwd_iat_max *= _MICROSECONDS
    fwd_iat_min *= _MICROSECONDS

    bwd_iat_mean *= _MICROSECONDS
    bwd_iat_std *= _MICROSECONDS
    bwd_iat_max *= _MICROSECONDS
    bwd_iat_min *= _MICROSECONDS

    flow_packets_per_s = flow.total_packets / duration_seconds if duration_seconds > 0 else 0.0
    flow_bytes_per_s = flow.total_bytes / duration_seconds if duration_seconds > 0 else 0.0
    fwd_packets_per_s = flow.forward_packets / duration_seconds if duration_seconds > 0 else 0.0
    bwd_packets_per_s = flow.backward_packets / duration_seconds if duration_seconds > 0 else 0.0

    min_packet_length = min(flow.packet_lengths) if flow.packet_lengths else 0
    max_packet_length = max(flow.packet_lengths) if flow.packet_lengths else 0
    packet_length_mean = statistics.fmean(flow.packet_lengths) if flow.packet_lengths else 0.0
    packet_length_std = statistics.pstdev(flow.packet_lengths) if len(flow.packet_lengths) > 1 else 0.0
    packet_length_variance = _variance(flow.packet_lengths)

    fwd_packet_length_max = max(flow.forward_packet_lengths) if flow.forward_packet_lengths else 0
    fwd_packet_length_min = min(flow.forward_packet_lengths) if flow.forward_packet_lengths else 0
    fwd_packet_length_mean = (
        statistics.fmean(flow.forward_packet_lengths) if flow.forward_packet_lengths else 0.0
    )
    fwd_packet_length_std = (
        statistics.pstdev(flow.forward_packet_lengths) if len(flow.forward_packet_lengths) > 1 else 0.0
    )

    bwd_packet_length_max = max(flow.backward_packet_lengths) if flow.backward_packet_lengths else 0
    bwd_packet_length_min = min(flow.backward_packet_lengths) if flow.backward_packet_lengths else 0
    bwd_packet_length_mean = (
        statistics.fmean(flow.backward_packet_lengths) if flow.backward_packet_lengths else 0.0
    )
    bwd_packet_length_std = (
        statistics.pstdev(flow.backward_packet_lengths) if len(flow.backward_packet_lengths) > 1 else 0.0
    )

    active_mean, active_std, active_max, active_min = _stats(flow.active_durations)
    idle_mean, idle_std, idle_max, idle_min = _stats(flow.idle_durations)

    active_mean *= _MICROSECONDS
    active_std *= _MICROSECONDS
    active_max *= _MICROSECONDS
    active_min *= _MICROSECONDS

    idle_mean *= _MICROSECONDS
    idle_std *= _MICROSECONDS
    idle_max *= _MICROSECONDS
    idle_min *= _MICROSECONDS

    subflow_fwd_packets = max(flow.subflow_forward_packets) if flow.subflow_forward_packets else flow.forward_packets
    subflow_fwd_bytes = max(flow.subflow_forward_bytes) if flow.subflow_forward_bytes else flow.forward_bytes
    subflow_bwd_packets = max(flow.subflow_backward_packets) if flow.subflow_backward_packets else flow.backward_packets
    subflow_bwd_bytes = max(flow.subflow_backward_bytes) if flow.subflow_backward_bytes else flow.backward_bytes

    timestamp_str = datetime.utcfromtimestamp(flow.start_time).isoformat() + "Z"

    return {
        "Flow ID": flow.flow_id,
        "Source IP": flow.src_ip,
        "Source Port": flow.src_port,
        "Destination IP": flow.dst_ip,
        "Destination Port": flow.dst_port,
        "Protocol": flow.protocol,
        "Timestamp": timestamp_str,
        "Flow Duration": duration_microseconds,
        "Total Fwd Packets": flow.forward_packets,
        "Total Backward Packets": flow.backward_packets,
        "Total Length of Fwd Packets": flow.forward_bytes,
        "Total Length of Bwd Packets": flow.backward_bytes,
        "Fwd Packet Length Max": fwd_packet_length_max,
        "Fwd Packet Length Min": fwd_packet_length_min,
        "Fwd Packet Length Mean": fwd_packet_length_mean,
        "Fwd Packet Length Std": fwd_packet_length_std,
        "Bwd Packet Length Max": bwd_packet_length_max,
        "Bwd Packet Length Min": bwd_packet_length_min,
        "Bwd Packet Length Mean": bwd_packet_length_mean,
        "Bwd Packet Length Std": bwd_packet_length_std,
        "Flow Bytes/s": flow_bytes_per_s,
        "Flow Packets/s": flow_packets_per_s,
        "Flow IAT Mean": flow_iat_mean,
        "Flow IAT Std": flow_iat_std,
        "Flow IAT Max": flow_iat_max,
        "Flow IAT Min": flow_iat_min,
        "Fwd IAT Total": fwd_iat_total,
        "Fwd IAT Mean": fwd_iat_mean,
        "Fwd IAT Std": fwd_iat_std,
        "Fwd IAT Max": fwd_iat_max,
        "Fwd IAT Min": fwd_iat_min,
        "Bwd IAT Total": bwd_iat_total,
        "Bwd IAT Mean": bwd_iat_mean,
        "Bwd IAT Std": bwd_iat_std,
        "Bwd IAT Max": bwd_iat_max,
        "Bwd IAT Min": bwd_iat_min,
        "Fwd PSH Flags": flow.fwd_psh_flags,
        "Bwd PSH Flags": flow.bwd_psh_flags,
        "Fwd URG Flags": flow.fwd_urg_flags,
        "Bwd URG Flags": flow.bwd_urg_flags,
        "Fwd Header Length": flow.forward_header_bytes,
        "Bwd Header Length": flow.backward_header_bytes,
        "Fwd Packets/s": fwd_packets_per_s,
        "Bwd Packets/s": bwd_packets_per_s,
        "Min Packet Length": min_packet_length,
        "Max Packet Length": max_packet_length,
        "Packet Length Mean": packet_length_mean,
        "Packet Length Std": packet_length_std,
        "Packet Length Variance": packet_length_variance,
        "FIN Flag Count": flow.fin_count,
        "SYN Flag Count": flow.syn_count,
        "RST Flag Count": flow.rst_count,
        "PSH Flag Count": flow.psh_count,
        "ACK Flag Count": flow.ack_count,
        "URG Flag Count": flow.urg_count,
        "CWE Flag Count": flow.cwr_count,
        "ECE Flag Count": flow.ece_count,
        "Down/Up Ratio": flow.down_up_ratio,
        "Average Packet Size": flow.avg_packet_size,
        "Avg Fwd Segment Size": flow.avg_fwd_segment_size,
        "Avg Bwd Segment Size": flow.avg_bwd_segment_size,
        "Fwd Header Length.1": flow.forward_header_bytes,
        "Fwd Avg Bytes/Bulk": 0.0,
        "Fwd Avg Packets/Bulk": 0.0,
        "Fwd Avg Bulk Rate": 0.0,
        "Bwd Avg Bytes/Bulk": 0.0,
        "Bwd Avg Packets/Bulk": 0.0,
        "Bwd Avg Bulk Rate": 0.0,
        "Subflow Fwd Packets": subflow_fwd_packets,
        "Subflow Fwd Bytes": subflow_fwd_bytes,
        "Subflow Bwd Packets": subflow_bwd_packets,
        "Subflow Bwd Bytes": subflow_bwd_bytes,
        "Init_Win_bytes_forward": flow.init_win_bytes_forward,
        "Init_Win_bytes_backward": flow.init_win_bytes_backward,
        "act_data_pkt_fwd": flow.act_data_pkt_fwd,
        "min_seg_size_forward": flow.min_seg_size_forward,
        "Active Mean": active_mean,
        "Active Std": active_std,
        "Active Max": active_max,
        "Active Min": active_min,
        "Idle Mean": idle_mean,
        "Idle Std": idle_std,
        "Idle Max": idle_max,
        "Idle Min": idle_min,
        "Label": 0,
    }


def extract_flow_features(pcap_path: Path) -> List[Dict[str, object]]:
    """Read a PCAP file and return flow features for each bidirectional stream."""

    flows = build_flows(iterate_packets(pcap_path))
    return [flow_to_feature_dict(flow) for flow in flows.values()]
