"""
flow_tracker.py
----------------
UNSW-NB15 (the dataset train_model.py learns from) describes whole CONNECTIONS
(flows), not single packets: things like total duration, total bytes, and
average load. A live packet sniffer only sees one packet at a time.

This module bridges that gap: it watches packets belonging to the same
(src_ip, dst_ip, protocol) flow, keeps a running tally, and produces a
feature dictionary shaped like one row of the training CSV once a flow has
enough packets (or has been idle long enough to be considered "done").

Honesty about limits: some training features (xServ/service, trans_depth,
response_body_len, ct_ftp_cmd, is_ftp_login, ct_flw_http_mthd, the
ct_*_ltm "last-time-window count" features) need deep packet inspection or
longer-term history that this simple tracker does not implement. Those are
filled with 0, a neutral default. This means live predictions are an
approximation of full offline accuracy, not identical to it - a realistic
and common limitation in applied network ML, not a bug to silently hide.
"""

import time
from collections import defaultdict

FLOW_READY_PACKET_COUNT = 6     # evaluate a flow once it has this many packets...
FLOW_IDLE_TIMEOUT = 3.0          # ...or once it's been idle this many seconds
FLOW_MAX_AGE = 30.0               # hard cap so old flows don't linger forever


class Flow:
    __slots__ = (
        "start_time", "last_time", "spkts", "dpkts", "sbytes", "dbytes",
        "sttl", "dttl", "swin", "dwin", "proto_code", "state_code",
        "evaluated",
    )

    def __init__(self, proto_code):
        now = time.time()
        self.start_time = now
        self.last_time = now
        self.spkts = 0
        self.dpkts = 0
        self.sbytes = 0
        self.dbytes = 0
        self.sttl = 0
        self.dttl = 0
        self.swin = 0
        self.dwin = 0
        self.proto_code = proto_code
        self.state_code = 0
        self.evaluated = False

    def add_packet(self, direction, length, ttl, win):
        self.last_time = time.time()
        if direction == "fwd":
            self.spkts += 1
            self.sbytes += length
            self.sttl = ttl or self.sttl
            self.swin = win or self.swin
        else:
            self.dpkts += 1
            self.dbytes += length
            self.dttl = ttl or self.dttl
            self.dwin = win or self.dwin

    @property
    def packet_count(self):
        return self.spkts + self.dpkts

    def is_ready(self, current_time):
        if self.evaluated:
            return False
        if self.packet_count >= FLOW_READY_PACKET_COUNT:
            return True
        if current_time - self.last_time >= FLOW_IDLE_TIMEOUT and self.packet_count > 0:
            return True
        return False

    def is_expired(self, current_time):
        return current_time - self.last_time >= FLOW_MAX_AGE

    def to_feature_dict(self):
        """Build a row shaped like the UNSW-NB15 training features.
        Fields we genuinely cannot derive from raw packets alone are left
        at 0 (a neutral value) rather than guessed."""
        dur = max(self.last_time - self.start_time, 1e-6)
        total_pkts = max(self.packet_count, 1)
        rate = total_pkts / dur
        sload = (self.sbytes * 8) / dur
        dload = (self.dbytes * 8) / dur
        smean = self.sbytes / max(self.spkts, 1)
        dmean = self.dbytes / max(self.dpkts, 1)

        return {
            "dur": dur,
            "xProt": self.proto_code,
            "xServ": 0,                 # needs app-layer ID - not derived here
            "xState": self.state_code,
            "spkts": self.spkts,
            "dpkts": self.dpkts,
            "sbytes": self.sbytes,
            "dbytes": self.dbytes,
            "rate": rate,
            "sttl": self.sttl,
            "dttl": self.dttl,
            "sload": sload,
            "dload": dload,
            "sloss": 0,
            "dloss": 0,
            "sinpkt": dur / max(self.spkts, 1),
            "dinpkt": dur / max(self.dpkts, 1),
            "sjit": 0,
            "djit": 0,
            "swin": self.swin,
            "stcpb": 0,
            "dtcpb": 0,
            "dwin": self.dwin,
            "tcprtt": 0,
            "synack": 0,
            "ackdat": 0,
            "smean": smean,
            "dmean": dmean,
            "trans_depth": 0,            # HTTP-specific - not derived here
            "response_body_len": 0,      # HTTP-specific - not derived here
            "ct_srv_src": 0,             # needs sliding-window history
            "ct_state_ttl": 0,
            "ct_dst_ltm": 0,
            "ct_src_dport_ltm": 0,
            "ct_dst_sport_ltm": 0,
            "ct_dst_src_ltm": 0,
            "is_ftp_login": 0,
            "ct_ftp_cmd": 0,
            "ct_flw_http_mthd": 0,
            "ct_src_ltm": 0,
            "ct_srv_dst": 0,
            "is_sm_ips_ports": 0,
        }


class FlowTracker:
    """Keeps one Flow per (src_ip, dst_ip, protocol) key."""

    PROTO_CODE = {"TCP": 1, "UDP": 2, "ICMP": 3, "Other": 0}

    def __init__(self):
        self.flows = {}

    def _key(self, src_ip, dst_ip, protocol):
        return (src_ip, dst_ip, protocol)

    def update(self, src_ip, dst_ip, protocol, length, ttl, win, direction="fwd"):
        key = self._key(src_ip, dst_ip, protocol)
        flow = self.flows.get(key)
        if flow is None:
            flow = Flow(self.PROTO_CODE.get(protocol, 0))
            self.flows[key] = flow
        flow.add_packet(direction, length, ttl, win)
        return key, flow

    def pop_ready_flows(self):
        """Return [(key, feature_dict)] for flows ready to be scored, and
        mark them evaluated so we don't re-score the same data twice."""
        current_time = time.time()
        ready = []
        expired_keys = []
        for key, flow in self.flows.items():
            if flow.is_ready(current_time):
                ready.append((key, flow.to_feature_dict()))
                flow.evaluated = True
            if flow.is_expired(current_time):
                expired_keys.append(key)
        for key in expired_keys:
            del self.flows[key]
        return ready
