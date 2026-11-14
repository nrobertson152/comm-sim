"""Networking, part A: TCP, UDP, IPv4 / IPv6, HTTP / HTTPS, WebSocket,
FTP / SFTP, SSH, SNMP, MQTT and CoAP."""
import base64
import hashlib
import math
import struct
import pygame
from ..engine import Scenario, Bld, Frame, Tpl, P, Pdu
from ..bits import inet_cs
from .fam import IpNet, eth_pdu, ipv4_pdu, ipv6_pdu, udp_pdu, tcp_seg, flag_names, ipb, macb, MSS_OPTS
from .webfam import http_req, http_rsp, ws_frame, jdump, tls_hs, tls_record
from .power_a import utc, T0
from ..ui import text


def line_nodes(scn, specs, y=150, style="cat6", conn="rj45"):
    """specs: [(nid, label, kind, x, ip, mac, sub, w)]. Nodes in a row joined by cables; ports at the centres."""
    ns = []
    for nid, label, kind, x, ip, mac, sub, w in specs:
        n = scn.node(nid, label, kind, x, y, ip or "", sub, w=w)
        n.port = (x + w / 2, y + 26)
        if mac:
            scn.lan.host(nid, mac, ip if ip and ":" not in ip else None, ip if ip and ":" in ip else None)
        ns.append(n)
    for a, b in zip(ns, ns[1:]):
        scn.seg([(a.x + a.w, y + 26), (b.x, y + 26)], style, net="TX", c0=conn, c1=conn)
    for n in ns:
        if n is not ns[0]:
            scn.seg([(n.x, y + 26), n.port], style, w=1, col=(40, 40, 44))
        if n is not ns[-1]:
            scn.seg([n.port, (n.x + n.w, y + 26)], style, w=1, col=(40, 40, 44))
    return ns


# ===================================================================== TCP
class TCP(IpNet):
    key, name, cat = "tcp", "TCP", "net"
    blurb = "Reliable connection-oriented data transfer"
    medium = "TCP download across the internet (RTT 40 ms, 20 Mbit/s bottleneck with a 30-packet queue): handshake, slow start, loss recovery, flow control"
    faults = [("loss", "Lossy path (1 % random loss)", "Lost segments produce duplicate ACKs; the third triggers a fast retransmit and halves the congestion window."),
              ("zwin", "Client application stops reading", "The receive buffer fills, the advertised window drops to zero and the server sends window probes."),
              ("closed", "Server port closed", "Connection attempts are answered with RST: 'connection refused'."),
              ("noscale", "Window scaling disabled", "The window field tops out at 65 535 bytes: throughput is capped at 64 KB per round trip.")]
    spec = [("Standard", "RFC 9293 (TCP), RFC 5681 congestion control, RFC 6298 RTO, RFC 7323 window scale / timestamps, RFC 2018 SACK"),
            ("Header", "Ports, sequence and acknowledgment numbers, data offset, flags (SYN FIN RST PSH ACK URG ECE CWR), window, checksum, options"),
            ("Connection", "Three-way handshake (SYN, SYN-ACK, ACK) with MSS / window scale / SACK options; FIN / ACK in each direction to close"),
            ("Reliability", "Cumulative ACKs, retransmission timeout (RTO >= 200 ms), fast retransmit after three duplicate ACKs"),
            ("Congestion", "Slow start doubles cwnd per RTT up to ssthresh, then congestion avoidance (+1 MSS per RTT); loss halves cwnd"),
            ("Flow control", "The receiver advertises its free buffer (rwnd); in flight <= min(cwnd, rwnd); zero window -> persist probes")]
    frame = [["TCP header", ("Src port", 16), ("Dst port", 16), ("Sequence number", 32), ("Ack number", 32), ("Off", 4), ("Rsv", 4), ("Flags", 8), ("Window", 16),
              ("Checksum", 16), ("Urgent", 16), ("Options", "0-40 B")]]
    about = ("TCP turns the unreliable packets of IP into a reliable, ordered byte stream. Every byte has a sequence number and the receiver "
             "acknowledges what it has; lost data is sent again. TCP also decides how fast to send: it starts slowly, doubles its congestion "
             "window every round trip until it sees loss, then backs off - the sawtooth you see in the graph - while never sending more than "
             "the receiver says it can buffer.")
    guide = ["Follow the handshake in FLOW: SYN, SYN-ACK, ACK with MSS and window-scale options.",
             "Watch the congestion window graph: slow start, the loss when the router queue overflows, the halving.",
             "Select a duplicate ACK and the fast retransmission it triggers (same sequence number as the lost segment).",
             "Stop the client application: the window shrinks to zero; the server probes until it reopens."]

    MSS = 1460

    def setup(self):
        line_nodes(self, [("cli", "CLIENT PC", "pc", 30, "192.168.1.20", "3c:52:82:10:00:20", "downloads", 118),
                          ("rtr", "HOME ROUTER", "router", 250, "", "", "20 Mbit/s, queue 30", 130),
                          ("net", "INTERNET", "cloud", 470, "", "", "RTT 40 ms", 118),
                          ("srv", "FILE SERVER", "server", 700, "203.0.113.80", "00:16:3e:50:00:80", "port 443", 118)])
        self.rmac = "00:1a:2b:3c:00:01"
        self.user = "cli"
        self.st = None
        self.hist = []
        self.req_n = 0
        self.by["cli"].vars.update({"State": "CLOSED", "Received": "0 KB", "Throughput": "-", "rwnd advertised": "-"})
        self.by["srv"].vars.update({"cwnd": "-", "ssthresh": "-", "In flight": "-", "Retransmissions": 0, "RTT": "-"})
        self.at(0.1, self.connect)
        self.every(0.05, self.sample, 0.05)

    # ------------------------------------------------------------ frames
    def mkseg(self, frm, flags, seq, ack, win, payload=b"", info=None, kind=None, err=None, opts=b"", n_override=None):
        c2s = frm == "cli"
        sip, dip = ("192.168.1.20", "203.0.113.80") if c2s else ("203.0.113.80", "192.168.1.20")
        sp, dp = (51234, 443) if c2s else (443, 51234)
        smac, dmac = ("3c:52:82:10:00:20", self.rmac) if c2s else (self.rmac, "3c:52:82:10:00:20")
        isn_s, isn_r = (self.st["c_isn"], self.st["s_isn"]) if c2s else (self.st["s_isn"], self.st["c_isn"])
        pl = Pdu(payload, [[0, "TCP payload (%d bytes)" % len(payload), 0, len(payload), "Application data (TLS records here)."]]) if payload else Pdu()
        rs, ra = seq - isn_s, ack - isn_r
        if info is None:
            info = "%d → %d [%s] Seq=%d Ack=%d Win=%d Len=%d" % (sp, dp, flag_names(flags), rs, ra if flags & 0x10 else 0, win, len(payload))

        def mk(f, a=(sip, dip, sp, dp, seq, ack, flags, win, pl, opts, rs, ra, smac, dmac)):
            sip_, dip_, sp_, dp_, seq_, ack_, fl, wn, p_, o_, rs_, ra_, sm, dm = a
            return eth_pdu(dm, sm, 0x0800, ipv4_pdu(sip_, dip_, 6, tcp_seg(sp_, dp_, seq_, ack_, fl, wn, p_, sip_, dip_, o_, rs_, ra_ if fl & 0x10 else 0)))
        n = 14 + 20 + 20 + len(opts) + len(payload) + 4
        fr = self.lan.frame(frm, "srv" if c2s else "cli", mk, info, "TCP", kind or ("ctl" if flags & 0x07 else ("data" if payload else "ack")),
                            key="TCP %s" % flag_names(flags) if not payload else "TCP data", err=err, n=max(64, n))
        fr.meta.update(lat=0.0, seq=seq, ack=ack, win=win, ln=len(payload), flags=flags, dup="Dup ACK" in info)
        return fr

    def c2s(self, fr):
        """Client segment: captured at the client, reaches the server 20 ms later."""
        fr.meta["lat"] = 0.020
        self.tx(fr, bus="up")

    def s2c(self, fr, data_seg=False):
        """Server segment: 10 ms to the router, queued at the 20 Mbit/s bottleneck, 10 ms to the client."""
        def enq():
            dur = (fr.n + 8) * 8 / 20e6
            backlog = max(0.0, self.free.get("wan", 0.0) - self.t)
            if data_seg and backlog > 30 * dur:
                fr.err = "Dropped: router queue full (tail drop)"
                fr.t = self.t + 0.010
                self.at(fr.t, self.emit, fr)
                return
            if data_seg and self.fault["loss"] and self.rng.random() < 0.01:
                fr.err = "Lost in the network (1 % random loss)"
            s = self.slot("wan", self.t, dur)
            fr.t = s + dur + 0.010
            fr.dur = (fr.n + 8) * 8 / 100e6
            self.at(fr.t, self.emit, fr)
        self.at(self.t + 0.010, enq)

    # ------------------------------------------------------------- connection
    def connect(self):
        r = self.rng
        self.st = dict(c_isn=int(r.integers(1, 2 ** 31)), s_isn=int(r.integers(1, 2 ** 31)), state="SYN_SENT", ws=0 if self.fault["noscale"] else 7)
        st = self.st
        st.update(c_nxt=st["c_isn"] + 1, s_una=st["s_isn"] + 1, s_nxt=st["s_isn"] + 1, rcv=0, buf=0, ooo={}, cwnd=10 * self.MSS, ssthresh=10 ** 9,
                  dup=0, todo=0, inflight={}, rto=0.25, srtt=None, last_ack_t=self.t, recover=0, acked_since=0, probe=None, total=0,
                  sacked=set(), lost=set(), retx=set(), retx_q=[], inrec=False)
        self.by["cli"].vars["State"] = "SYN_SENT"
        opts = MSS_OPTS if st["ws"] else bytes([2, 4, 0x05, 0xB4, 4, 2, 1, 1])
        self.c2s(self.mkseg("cli", 0x02, st["c_isn"], 0, 64240, opts=opts))
        self.at(self.t + 0.040, self.srv_syn)

    def srv_syn(self):
        st = self.st
        if self.fault["closed"]:
            self.s2c(self.mkseg("srv", 0x14, 0, st["c_isn"] + 1, 0, info="443 → 51234 [RST,ACK] connection refused"))
            self.by["cli"].vars["State"] = "CLOSED (connection refused)"
            self.at(self.t + 3.0, self.connect)
            return
        opts = MSS_OPTS if st["ws"] else bytes([2, 4, 0x05, 0xB4, 4, 2, 1, 1])
        self.s2c(self.mkseg("srv", 0x12, st["s_isn"], st["c_isn"] + 1, 65160, opts=opts))
        self.at(self.t + 0.040, self.cli_est)

    def cli_est(self):
        st = self.st
        st["state"] = "ESTABLISHED"
        st["rcv"] = st["s_isn"] + 1
        self.by["cli"].vars["State"] = "ESTABLISHED"
        self.c2s(self.mkseg("cli", 0x10, st["c_isn"] + 1, st["rcv"], self.adv_win()))
        self.at(self.t + 0.05, self.request)

    def adv_win(self):
        st = self.st
        free = max(0, 262144 - st["buf"]) if st["ws"] else max(0, 65535 - st["buf"])
        if free < self.MSS:              # receiver silly-window avoidance (RFC 1122): never offer less than one MSS
            return 0
        return min(65535, free >> st["ws"])

    def request(self, nbytes=900_000):
        st = self.st
        if not st or st["state"] != "ESTABLISHED":
            return
        self.req_n += 1
        if self.t - st.get("t_last", 0.0) > st["rto"] and st["cwnd"] > 10 * self.MSS:
            st["cwnd"] = 10 * self.MSS
            self.log("Server: connection was idle longer than the RTO - cwnd restarts at 10 MSS (RFC 5681)")
        req = b"\x17\x03\x03\x00\x40" + bytes(64)
        self.c2s(self.mkseg("cli", 0x18, st["c_nxt"], st["rcv"], self.adv_win(), req, info="Request %d: TLS application data (GET /files/update.bin), 69 bytes" % self.req_n))
        st["c_nxt"] += len(req)
        st["t_req"] = self.t
        st["xfer"] = True
        st["got0"] = st["total"]
        self.at(self.t + 0.020, self.srv_req, nbytes)

    def srv_req(self, nbytes):
        st = self.st
        st["todo"] += nbytes
        self.srv_send()

    # ------------------------------------------------------------ server side
    def flight(self):
        st = self.st
        return sum(l for q, l in st["inflight"].items() if q not in st["sacked"] and q not in st["lost"])

    def srv_send(self):
        st = self.st
        rwnd = st.get("rwnd", 65535 << st["ws"])
        while self.flight() + self.MSS <= min(st["cwnd"], rwnd):
            if st["retx_q"]:
                q = st["retx_q"].pop(0)
                if q in st["inflight"] and q not in st["sacked"]:
                    self.send_seg(q, st["inflight"][q], True)
                continue
            if st["todo"] <= 0:
                break
            ln = min(self.MSS, st["todo"])
            self.send_seg(st["s_nxt"], ln)
            st["s_nxt"] += ln
            st["todo"] -= ln
        if st["todo"] > 0 and rwnd < self.MSS and st["probe"] is None:
            st["probe"] = self.t
            self.at(self.t + 0.5, self.window_probe)
        self.arm_rto()

    def send_seg(self, seq, ln, retx=False):
        st = self.st
        st["inflight"][seq] = ln
        st["lost"].discard(seq)
        if retx:
            st["retx"].add(seq)
        st.setdefault("sent_t", {})[seq] = (self.t, retx)
        info = "443 → 51234 [ACK] Seq=%d Len=%d%s" % (seq - st["s_isn"], ln, "  [RETRANSMISSION]" if retx else "")
        fr = self.mkseg("srv", 0x10, seq, st["c_nxt"], 501, bytes(ln), info=info, kind="err" if retx else "data")
        if retx:
            self.by["srv"].vars["Retransmissions"] += 1
        self.s2c(fr, data_seg=True)

    def arm_rto(self):
        st = self.st
        if st["inflight"]:
            tok = object()
            st["rto_tok"] = tok
            self.at(self.t + st["rto"], self.rto_fire, tok)

    def rto_fire(self, tok):
        st = self.st
        if st.get("rto_tok") is not tok or not st["inflight"]:
            return
        st["ssthresh"] = max(self.flight() // 2, 2 * self.MSS)
        st["cwnd"] = self.MSS
        st["rto"] = min(2.0, st["rto"] * 2)
        st["inrec"] = False
        holes = sorted(q for q in st["inflight"] if q not in st["sacked"])
        st["lost"] = set(holes)
        st["retx"] = set()
        st["retx_q"] = holes
        self.log("Server: retransmission timeout - cwnd = 1 MSS, ssthresh = %d KB, %d segment(s) to resend" % (st["ssthresh"] // 1024, len(holes)))
        self.srv_send()

    def mark_holes(self):
        st = self.st
        if not st["sacked"]:
            return
        hi = max(st["sacked"])
        for q in sorted(st["inflight"]):
            if q < hi and q not in st["sacked"] and q not in st["retx"] and q not in st["lost"]:
                st["lost"].add(q)
                st["retx_q"].append(q)

    def srv_ack(self, ack, win, dupack, sack=()):
        st = self.st
        st["rwnd"] = win << st["ws"]
        if win and st["probe"] is not None:
            st["probe"] = None
        for q in sack:
            if q in st["inflight"]:
                st["sacked"].add(q)
        if ack > st["s_una"]:
            acked = ack - st["s_una"]
            for q in [q for q in st["inflight"] if q < ack]:
                t0, retx = st.get("sent_t", {}).pop(q, (None, True))
                if t0 is not None and not retx:
                    r = self.t - t0
                    st["srtt"] = r if st["srtt"] is None else 0.875 * st["srtt"] + 0.125 * r
                    st["rto"] = max(0.2, 2 * st["srtt"])
                del st["inflight"][q]
                st["sacked"].discard(q)
                st["lost"].discard(q)
                st["retx"].discard(q)
            st["s_una"] = ack
            st["dup"] = 0
            if st["inrec"]:
                if ack >= st["recover"]:
                    st["inrec"] = False
                    st["cwnd"] = st["ssthresh"]
                else:
                    self.mark_holes()
            elif st["cwnd"] < st["ssthresh"]:
                st["cwnd"] += min(acked, 2 * self.MSS)
            else:
                st["cwnd"] += max(1, self.MSS * self.MSS // st["cwnd"])
            self.srv_send()
        elif st["inflight"] and ack == st["s_una"] and dupack:
            st["dup"] += 1
            if st["dup"] == 3 and not st["inrec"]:
                st["ssthresh"] = max(self.flight() // 2, 2 * self.MSS)
                st["cwnd"] = st["ssthresh"]
                st["recover"] = st["s_nxt"]
                st["inrec"] = True
                self.mark_holes()
                if ack in st["inflight"] and ack not in st["retx_q"] and ack not in st["retx"]:
                    st["lost"].add(ack)
                    st["retx_q"].insert(0, ack)
                self.log("Server: 3 duplicate ACKs at Seq=%d - fast retransmit (SACK recovery: %d hole(s)), cwnd halved to %d KB" % (
                    ack - st["s_isn"], len(st["retx_q"]), st["cwnd"] // 1024))
            if st["inrec"]:
                self.mark_holes()
                self.srv_send()

    def window_probe(self):
        st = self.st
        if st["probe"] is None or st["state"] != "ESTABLISHED":
            return
        self.s2c(self.mkseg("srv", 0x10, st["s_una"] - 1, st["c_nxt"], 501, info="443 → 51234 [ACK] Seq=%d Len=0  [TCP ZeroWindowProbe]" % (st["s_una"] - 1 - st["s_isn"]),
                            kind="ctl"))
        self.at(self.t + 0.045, lambda: self.c2s(self.mkseg("cli", 0x10, st["c_nxt"], st["rcv"], self.adv_win(),
                                                            info="51234 → 443 [ACK] Win=%d  [TCP %s]" % (self.adv_win(), "ZeroWindow" if not self.adv_win() else "Window Update"))))
        self.at(self.t + 0.065, self.srv_ack, st["s_una"], self.adv_win(), False)
        self.at(self.t + 0.5, self.window_probe)

    # ------------------------------------------------------------ client side
    def rx(self, fr):
        if fr.err or not self.st:
            return
        st = self.st
        m = fr.meta
        if "seq" not in m:
            return
        if fr.src == "srv" and m["ln"] > 0 and m["flags"] == 0x10:
            self.cli_data(m["seq"], m["ln"])
        elif fr.src == "cli" and m["flags"] & 0x10 and not m["flags"] & 0x07:
            if st["state"] == "ESTABLISHED":
                self.srv_ack(m["ack"], m["win"], m["dup"], m.get("sack", ()))

    def cli_data(self, seq, ln):
        st = self.st
        if seq == st["rcv"]:
            st["rcv"] += ln
            st["buf"] += ln
            st["total"] += ln
            while st["rcv"] in st["ooo"]:
                l2 = st["ooo"].pop(st["rcv"])
                st["rcv"] += l2
                st["buf"] += l2
                st["total"] += l2
            st["acked_since"] += 1
            if st["acked_since"] >= 2 or st["ooo"] == {} and st.get("had_ooo"):
                st["had_ooo"] = False
                self.cli_ack()
            elif st["acked_since"] == 1:
                tok = object()
                st["delack"] = tok
                self.at(self.t + 0.040, lambda: st.get("delack") is tok and st["acked_since"] and self.cli_ack(delayed=True))
        elif seq > st["rcv"]:
            st["ooo"][seq] = ln
            st["had_ooo"] = True
            self.cli_ack(dup=True)
        else:
            self.cli_ack(dup=True)

    def cli_ack(self, dup=False, delayed=False):
        st = self.st
        st["acked_since"] = 0
        st["delack"] = None
        w = self.adv_win()
        tag = "  [TCP Dup ACK]" if dup else ("  [TCP ZeroWindow]" if w == 0 else ("  [delayed ACK]" if delayed else ""))
        sack = b""
        blocks = []
        for q in sorted(st["ooo"]):
            if blocks and blocks[-1][1] == q:
                blocks[-1][1] = q + st["ooo"][q]
            else:
                blocks.append([q, q + st["ooo"][q]])
        if blocks:
            use = blocks[-3:][::-1]
            sack = bytes([1, 1, 5, 2 + 8 * len(use)]) + b"".join(a.to_bytes(4, "big") + b.to_bytes(4, "big") for a, b in use)
            tag += " SACK " + " ".join("%d-%d" % (a - st["s_isn"], b - st["s_isn"]) for a, b in use)
        fr = self.mkseg("cli", 0x10, st["c_nxt"], st["rcv"], w, opts=sack, info="51234 → 443 [ACK] Ack=%d Win=%d%s" % (st["rcv"] - st["s_isn"], w, tag),
                        kind="err" if dup else "ack")
        fr.meta["sack"] = list(st["ooo"])
        self.c2s(fr)

    def sample(self):
        st = self.st
        if not st or st["state"] != "ESTABLISHED":
            return
        rate = 0 if self.fault["zwin"] else 4_000_000 * 0.05
        before = self.adv_win()
        st["buf"] = max(0, st["buf"] - int(rate))
        if before < 8 and self.adv_win() > 64 and not self.fault["zwin"]:
            self.cli_ack()
        self.hist.append((self.t, st["cwnd"] / 1024.0, min(st["ssthresh"], 10 ** 6) / 1024.0))
        self.hist = self.hist[-240:]
        v = self.by["srv"].vars
        v.update({"cwnd": "%d KB" % (st["cwnd"] // 1024), "ssthresh": "-" if st["ssthresh"] > 10 ** 8 else "%d KB" % (st["ssthresh"] // 1024),
                  "In flight": "%d KB" % (self.flight() // 1024), "RTT": "-" if st["srtt"] is None else "%.1f ms" % (st["srtt"] * 1000)})
        c = self.by["cli"].vars
        c["Received"] = "%d KB" % (st["total"] // 1024)
        c["rwnd advertised"] = "%d x %d = %d KB" % (self.adv_win(), 1 << st["ws"], (self.adv_win() << st["ws"]) // 1024)
        if st.get("xfer") and st["todo"] <= 0 and not st["inflight"] and self.t - st["t_req"] > 0.2:
            st["xfer"] = False
            st["t_last"] = self.t
            dt = self.t - st["t_req"]
            if dt > 0:
                c["Throughput"] = "%.1f Mbit/s (last transfer)" % ((st["total"] - st.get("got0", 0)) * 8 / dt / 1e6)
            st["t_req"] = None
            self.at(self.t + 2.0, self.request)

    def close(self, send=True):
        st = self.st
        if not send:
            return Frame(self.t, 0.0001, "cli", "srv", "TCP", "preview", pdu=eth_pdu(self.rmac, "3c:52:82:10:00:20", 0x0800,
                                                                                   ipv4_pdu("192.168.1.20", "203.0.113.80", 6, tcp_seg(51234, 443, 1, 1, 0x11, 501, Pdu(), "192.168.1.20", "203.0.113.80"))))
        if not st or st["state"] != "ESTABLISHED":
            return None
        st["state"] = "FIN_WAIT_1"
        self.by["cli"].vars["State"] = "FIN_WAIT_1"
        self.c2s(self.mkseg("cli", 0x11, st["c_nxt"], st["rcv"], self.adv_win()))
        st["todo"] = 0
        st["inflight"] = {}
        self.at(self.t + 0.040, lambda: self.s2c(self.mkseg("srv", 0x11, st["s_nxt"], st["c_nxt"] + 1, 501)))
        self.at(self.t + 0.080, lambda: self.c2s(self.mkseg("cli", 0x10, st["c_nxt"] + 1, st["s_nxt"] + 1, self.adv_win())))
        self.at(self.t + 0.081, lambda: self.by["cli"].vars.__setitem__("State", "TIME_WAIT (2 MSL), then CLOSED"))
        return None

    def on_fault(self, key, on):
        if key in ("closed", "noscale") and not on and self.st and self.st["state"] != "ESTABLISHED":
            self.at(self.t + 0.2, self.connect)
        if key == "zwin" and not on and self.st:
            self.at(self.t + 0.06, self.cli_ack)

    def tpls(self):
        return [Tpl("Download", [P("kb", "Size (KB)", 2000, 10, 20000)], lambda s, v, send: self._dl(v["kb"], send), "One request; the server streams the file."),
                Tpl("Close connection (FIN)", [], lambda s, v, send: self.close(send), "Client FIN, server FIN-ACK, final ACK."),
                Tpl("Reconnect", [], lambda s, v, send: self._re(send), "New handshake with fresh initial sequence numbers.")]

    def _dl(self, kb, send):
        if not send:
            return Frame(self.t, 0.0001, "cli", "srv", "TCP", "preview", pdu=Pdu(b"GET", [[0, "Request %d KB" % kb, 0, 3, ""]]))
        self.request(kb * 1024)
        return None

    def _re(self, send):
        if not send:
            return self.close(False)
        self.connect()
        return None

    def draw_extra(self, s, rect):
        if len(self.hist) < 2:
            return
        r = pygame.Rect(rect.right - 330, rect.bottom - 130, 320, 120)
        pygame.draw.rect(s, (10, 14, 12), r)
        pygame.draw.rect(s, (70, 90, 80), r, 1)
        t1 = self.hist[-1][0]
        t0 = t1 - 12.0
        top = max(64.0, max(h[1] for h in self.hist) * 1.1)
        pts = [(r.x + 4 + (t - t0) / 12.0 * (r.w - 8), r.bottom - 6 - min(c, top) / top * (r.h - 22)) for t, c, _ in self.hist if t >= t0]
        if len(pts) > 1:
            pygame.draw.lines(s, (90, 230, 120), False, pts, 2)
        th = [(r.x + 4 + (t - t0) / 12.0 * (r.w - 8), r.bottom - 6 - min(x, top) / top * (r.h - 22)) for t, _, x in self.hist if t >= t0 and x < top]
        if len(th) > 1:
            pygame.draw.lines(s, (230, 160, 60), False, th, 1)
        text(s, "cwnd (green) / ssthresh (orange), KB, last 12 s", (r.x + 6, r.y + 3), 9, (170, 190, 170))
        text(s, "%d KB" % int(top), (r.right - 6, r.y + 3), 9, (120, 140, 120), align="r")


# ===================================================================== UDP
def raw_ip4(scn, src, dst, smac, dmac, sip, dip, proto, inner, info, pname, kind="data", ttl=64, frag=0, mf=False, df=True, ident=None, err=None, key=None):
    ident = int(scn.rng.integers(0, 65535)) if ident is None else ident
    pdu = eth_pdu(dmac, smac, 0x0800, ipv4_pdu(sip, dip, proto, inner, ttl=ttl, ident=ident, df=df, frag=frag, mf=mf))
    fr = scn.lan.frame(src, dst, pdu, info, pname, kind, key=key, err=err)
    return scn.lan.send(fr)


def icmp_err(typ, code, orig, extra=b"\x00\x00\x00\x00", title=None):
    body = bytes([typ, code, 0, 0]) + extra + orig
    cs = inet_cs(body)
    names = {(3, 3): "Destination unreachable: port unreachable", (3, 4): "Destination unreachable: fragmentation needed (DF set)", (11, 0): "Time exceeded: TTL expired in transit",
             (3, 1): "Destination unreachable: host unreachable"}
    b = Bld(title or "Internet Control Message Protocol", "RFC 792 error message: type, code, checksum, then the start of the datagram that caused it.")
    b.u8("Type", typ, str(typ), "")
    b.u8("Code", code, "%d (%s)" % (code, names.get((typ, code), "")), "")
    b.u16("Checksum", cs, "0x%04X [correct]" % cs, "")
    b.raw("Unused / next-hop MTU", extra, extra.hex(), "For 'fragmentation needed' the last 2 bytes carry the next-hop MTU.")
    b.raw("Original IP header + first 8 bytes", orig, "%d bytes" % len(orig), "Lets the sender match the error to its own socket.")
    return b.done()


def dns_name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"


def dns_msg(qid, name, resp=False, addr=None, rcode=0):
    b = Bld("Domain Name System (%s)" % ("response" if resp else "query"), "RFC 1035: a header, the question, and (in responses) resource records.")
    fl = (0x8180 if resp else 0x0100) | rcode
    b.u16("Transaction ID", qid, "0x%04X" % qid, "Matches the response to the query.")
    b.u16("Flags", fl, "0x%04X (%s, recursion desired%s%s)" % (fl, "response" if resp else "standard query", ", recursion available" if resp else "",
                                                               {0: "", 3: ", NXDOMAIN"}.get(rcode, "")), "")
    b.u16("Questions", 1, None, "")
    b.u16("Answer RRs", 1 if (resp and addr) else 0, None, "")
    b.u16("Authority RRs", 0, None, "")
    b.u16("Additional RRs", 0, None, "")
    b.raw("Query: name", dns_name(name), name, "Labels, each prefixed by its length, ending with 0.")
    b.u16("Query: type", 1, "A (IPv4 address)", "")
    b.u16("Query: class", 1, "IN", "")
    if resp and addr:
        b.u16("Answer: name", 0xC00C, "pointer to offset 12 (%s)" % name, "Name compression: 2 high bits set = pointer.")
        b.u16("Answer: type", 1, "A", "")
        b.u16("Answer: class", 1, "IN", "")
        b.u32("Answer: TTL", 300, "300 s", "How long resolvers may cache this answer.")
        b.u16("Answer: data length", 4, None, "")
        b.raw("Answer: address", ipb(addr), addr, "")
    return b.done()


def ntp_ts(t):
    s = T0.timestamp() + t + 2208988800
    return struct.pack(">II", int(s), int((s % 1) * 2 ** 32))


def ntp_msg(t, mode, org=None, rx=None):
    b = Bld("Network Time Protocol (NTPv4, %s)" % ("client" if mode == 3 else "server"), "RFC 5905: 48-byte packet with four 64-bit timestamps (seconds since 1900 + fraction).")
    b.u8("LI / VN / Mode", (4 << 3) | mode, "leap 0, version 4, mode %d (%s)" % (mode, "client" if mode == 3 else "server"), "")
    b.u8("Stratum", 0 if mode == 3 else 2, None, "Distance from the reference clock (1 = GPS / atomic).")
    b.u8("Poll", 6, "64 s", "")
    b.u8("Precision", 0xE9, "2^-23 s", "")
    b.u32("Root delay", 0 if mode == 3 else 0x0000_0120, None, "")
    b.u32("Root dispersion", 0 if mode == 3 else 0x0000_0310, None, "")
    b.raw("Reference ID", b"\x00" * 4 if mode == 3 else b"GPS\x00", "" if mode == 3 else "GPS", "")
    b.raw("Reference timestamp", bytes(8) if mode == 3 else ntp_ts(t - 30), "", "")
    b.raw("Origin timestamp", bytes(8) if org is None else ntp_ts(org), "" if org is None else "T1 = client send time", "Copied from the request.")
    b.raw("Receive timestamp", bytes(8) if rx is None else ntp_ts(rx), "" if rx is None else "T2 = server receive time", "")
    b.raw("Transmit timestamp", ntp_ts(t), "T%d" % (1 if mode == 3 else 3), "Offset = ((T2 - T1) + (T3 - T4)) / 2, delay = (T4 - T1) - (T3 - T2).")
    return b.done()


def dhcp_msg(op, xid, mac, yiaddr="0.0.0.0", mtype=1, opts=()):
    names = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK"}
    b = Bld("Dynamic Host Configuration Protocol (%s)" % names[mtype], "RFC 2131: BOOTP message format plus options.")
    b.u8("Op", op, "%d (%s)" % (op, "BOOTREQUEST" if op == 1 else "BOOTREPLY"), "")
    b.u8("Hardware type", 1, "Ethernet", "")
    b.u8("Hardware length", 6, None, "")
    b.u8("Hops", 0, None, "")
    b.u32("Transaction ID", xid, "0x%08X" % xid, "")
    b.u16("Seconds", 0, None, "")
    b.u16("Flags", 0x8000 if op == 1 else 0, "broadcast" if op == 1 else "unicast", "")
    b.raw("Client IP", bytes(4), "0.0.0.0", "")
    b.raw("Your IP", ipb(yiaddr), yiaddr, "The address being offered / assigned.")
    b.raw("Server IP", bytes(4), "0.0.0.0", "")
    b.raw("Relay agent IP", bytes(4), "0.0.0.0", "")
    b.raw("Client MAC", macb(mac) + bytes(10), mac, "")
    b.raw("Server name / boot file", bytes(192), "(empty)", "")
    b.u32("Magic cookie", 0x63825363, "DHCP", "")
    b.raw("Option 53", bytes([53, 1, mtype]), "DHCP message type: %s" % names[mtype], "")
    for code, data, txt in opts:
        b.raw("Option %d" % code, bytes([code, len(data)]) + data, txt, "")
    b.raw("End", b"\xff", "255", "")
    return b.done()


def rtp_pdu(seq, ts, ssrc, n):
    b = Bld("Real-time Transport Protocol", "RFC 3550: sequence number (detects loss / reordering) and media timestamp (90 kHz for video).")
    b.u8("V / P / X / CC", 0x80, "version 2", "")
    b.u8("M / payload type", 96, "dynamic 96 (H.264)", "")
    b.u16("Sequence number", seq & 0xFFFF, None, "Gaps = lost packets: UDP never retransmits.")
    b.u32("Timestamp", ts & 0xFFFFFFFF, None, "")
    b.u32("SSRC", ssrc, "0x%08X" % ssrc, "")
    b.raw("Payload", bytes(n), "%d bytes of video" % n, "")
    return b.done()


class UDP(IpNet):
    key, name, cat = "udp", "UDP", "net"
    blurb = "Fast connectionless transport"
    medium = "UDP on a home LAN: DHCP (broadcast), DNS lookups, NTP time sync and an RTP video stream - no handshakes, no retransmissions"
    faults = [("loss", "Wi-Fi bridge drops 5 % of the video packets", "Gaps in the RTP sequence numbers; UDP does not resend - the decoder conceals or freezes."),
              ("dns", "DNS server not responding", "The resolver retries after 1 s, 2 s ... then the application gives up."),
              ("ntp", "NTP service stopped on the router", "Requests to port 123 come back as ICMP port unreachable."),
              ("frag", "Media server sends 4000-byte datagrams", "IP fragments each datagram into three packets; losing one fragment loses the whole datagram.")]
    spec = [("Standard", "RFC 768 (UDP), RFC 8085 usage guidelines; ports 0-65535, well known < 1024"),
            ("Header", "8 bytes: source port, destination port, length, checksum (optional over IPv4, mandatory over IPv6)"),
            ("Semantics", "Datagrams: no connection, no ordering, no retransmission, no congestion control - the application decides"),
            ("Uses", "DNS 53, DHCP 67/68, NTP 123, SNMP 161/162, syslog 514, RTP / VoIP, QUIC (HTTP/3) 443, CoAP 5683, games"),
            ("Errors", "ICMP port unreachable when nobody listens; fragmentation if larger than the path MTU")]
    frame = [["UDP header", ("Source port", 16), ("Destination port", 16), ("Length", 16), ("Checksum", 16), ("Data", "n x 8")]]
    about = ("UDP is the thinnest possible layer over IP: two port numbers, a length and a checksum. It sends each datagram once and forgets it, "
             "which is exactly right for short request/response exchanges (DNS, DHCP, NTP) and for live media where a late packet is worthless. "
             "Anything else - retries, ordering, pacing - is up to the application.")
    guide = ["Follow DHCP: DISCOVER and OFFER as broadcasts, REQUEST, ACK - the laptop gets its address.",
             "Select a DNS query and its response: transaction ID, question, answer record with TTL.",
             "Watch the RTP sequence numbers; inject loss and see the gaps (no retransmission).",
             "Stop the NTP service: ICMP port unreachable carrying the original header."]

    def setup(self):
        hosts = [("lap", "LAPTOP", "laptop", 40, 40, "192.168.1.50", "3c:52:82:22:00:50", "DHCP client"),
                 ("rtr", "ROUTER (DHCP/DNS/NTP)", "router", 700, 40, "192.168.1.1", "00:1a:2b:3c:00:01", "67, 53, 123"),
                 ("tv", "SMART TV", "display", 40, 290, "192.168.1.60", "a4:77:33:00:00:60", "RTP receiver"),
                 ("ms", "MEDIA SERVER", "server", 700, 290, "192.168.1.10", "00:11:32:00:00:10", "RTP sender")]
        self.star(hosts)
        self.user = "lap"
        self.have_ip = False
        self.rseq = 1000
        self.lost = 0
        self.exp = None
        self.qid = 0x1a2b
        self.by["lap"].vars.update({"IP address": "none (DHCP)", "Last DNS answer": "-", "Clock offset": "-"})
        self.by["tv"].vars.update({"Packets": 0, "Lost": 0, "Loss": "0 %"})
        self.at(0.1, self.dhcp)
        self.every(1.0 / 30, self.rtp, 0.2)
        self.every(5.0, self.dns, 1.5)
        self.every(6.0, self.ntp, 3.0)

    def dhcp(self):
        mac = "3c:52:82:22:00:50"
        xid = 0x5A3C11F0
        opt_off = [(54, ipb("192.168.1.1"), "Server identifier 192.168.1.1"), (51, struct.pack(">I", 86400), "Lease time 24 h"), (1, ipb("255.255.255.0"), "Subnet mask"),
                   (3, ipb("192.168.1.1"), "Router 192.168.1.1"), (6, ipb("192.168.1.1"), "DNS server 192.168.1.1")]
        u = lambda op, mt, yi, opts=(): udp_pdu(68 if op == 1 else 67, 67 if op == 1 else 68, dhcp_msg(op, xid, mac, yi, mt, opts), "0.0.0.0" if op == 1 else "192.168.1.1",
                                                 "255.255.255.255", {67: "bootps", 68: "bootpc"})
        raw_ip4(self, "lap", None, mac, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "255.255.255.255", 17, u(1, 1, "0.0.0.0"), "DHCP DISCOVER xid 0x5A3C11F0 (broadcast from 0.0.0.0)", "DHCP", "bcast")
        self.at(self.t + 0.01, raw_ip4, self, "rtr", None, "00:1a:2b:3c:00:01", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255", 17, u(2, 2, "192.168.1.50", opt_off),
                "DHCP OFFER 192.168.1.50 xid 0x5A3C11F0", "DHCP", "resp")
        self.at(self.t + 0.02, raw_ip4, self, "lap", None, mac, "ff:ff:ff:ff:ff:ff", "0.0.0.0", "255.255.255.255", 17,
                u(1, 3, "0.0.0.0", [(50, ipb("192.168.1.50"), "Requested IP 192.168.1.50"), (54, ipb("192.168.1.1"), "Server identifier")]), "DHCP REQUEST 192.168.1.50", "DHCP", "bcast")
        self.at(self.t + 0.03, raw_ip4, self, "rtr", None, "00:1a:2b:3c:00:01", "ff:ff:ff:ff:ff:ff", "192.168.1.1", "255.255.255.255", 17, u(2, 5, "192.168.1.50", opt_off),
                "DHCP ACK 192.168.1.50, lease 24 h", "DHCP", "resp")
        self.at(self.t + 0.04, self._got_ip)

    def _got_ip(self):
        self.have_ip = True
        self.by["lap"].vars["IP address"] = "192.168.1.50 /24 (lease 24 h)"

    def dns(self, name="updates.example.com", tries=0, send=True):
        if not send:
            return Frame(self.t, 0.0001, "lap", "rtr", "DNS", "preview", pdu=udp_pdu(53001, 53, dns_msg(self.qid + 1, name), "192.168.1.50", "192.168.1.1", {53: "domain"}))
        if not self.have_ip:
            return None
        if tries == 0:
            self.qid = (self.qid + 1) & 0xFFFF
        qid = self.qid
        self.lan.udp("lap", "rtr", 53001, 53, dns_msg(qid, name), "DNS query 0x%04X A %s%s" % (qid, name, " (retry %d)" % tries if tries else ""), "DNS", "cmd", names={53: "domain"})
        if self.fault["dns"]:
            if tries < 2:
                self.at(self.t + 1.0 * (2 ** tries), self.dns, name, tries + 1)
            else:
                self.at(self.t + 4.0, lambda: self.by["lap"].vars.__setitem__("Last DNS answer", "TIMEOUT: name resolution failed"))
            return None
        addr = "203.0.113.%d" % (10 + len(name) % 50) if "nosuch" not in name else None
        self.at(self.t + 0.004, lambda: self.lan.udp("rtr", "lap", 53, 53001, dns_msg(qid, name, True, addr, 0 if addr else 3),
                                                     "DNS response 0x%04X %s %s" % (qid, name, addr or "NXDOMAIN"), "DNS", "resp", names={53: "domain"}))
        self.by["lap"].vars["Last DNS answer"] = "%s -> %s" % (name, addr or "NXDOMAIN")
        return None

    def ntp(self):
        if not self.have_ip:
            return
        t1 = self.t
        self.lan.udp("lap", "rtr", 123, 123, ntp_msg(t1, 3), "NTP client request (T1)", "NTP", "cmd", names={123: "ntp"})
        if self.fault["ntp"]:
            orig = ipv4_pdu("192.168.1.50", "192.168.1.1", 17, udp_pdu(123, 123, ntp_msg(t1, 3), "192.168.1.50", "192.168.1.1")).b[:28]
            self.at(self.t + 0.002, lambda: self.lan.l2("rtr", "lap", 0x0800, ipv4_pdu("192.168.1.1", "192.168.1.50", 1, icmp_err(3, 3, orig)),
                                                        "ICMP destination unreachable (port 123 unreachable)", "ICMP", "err"))
            return
        t2, t3 = t1 + 0.0021, t1 + 0.0022
        self.at(self.t + 0.0022, lambda: self.lan.udp("rtr", "lap", 123, 123, ntp_msg(t3, 4, t1, t2), "NTP server reply (T1 echoed, T2, T3)", "NTP", "resp", names={123: "ntp"}))
        self.by["lap"].vars["Clock offset"] = "%+.1f ms (delay %.1f ms)" % (float(self.rng.normal(3.2, 0.2)), 4.3)

    def rtp(self):
        self.rseq += 1
        tv = self.by["tv"].vars
        tv["Packets"] += 1
        n = 4000 if self.fault["frag"] else 1200
        p = udp_pdu(5004, 5004, rtp_pdu(self.rseq, int(self.t * 90000), 0x1F2E3D4C, n - 12), "192.168.1.10", "192.168.1.60", {5004: "rtp"})
        lost = self.fault["loss"] and self.rng.random() < 0.05
        if self.fault["frag"]:
            ipp = ipv4_pdu("192.168.1.10", "192.168.1.60", 17, p, df=False)
            data = ipp.b[20:]
            ident = int(self.rng.integers(0, 65535))
            chunks = [data[i:i + 1480] for i in range(0, len(data), 1480)]
            for k, ch in enumerate(chunks):
                inner = Pdu(ch, [[0, "IP fragment payload (%d bytes, offset %d)" % (len(ch), k * 1480), 0, len(ch), "Only the first fragment carries the UDP header."]])
                bad = lost and k == 1
                raw_ip4(self, "ms", "tv", "00:11:32:00:00:10", "a4:77:33:00:00:60", "192.168.1.10", "192.168.1.60", 17, inner,
                        "IPv4 fragment %d/%d of RTP seq %d (offset %d, MF %d)" % (k + 1, len(chunks), self.rseq, k * 1480, k < len(chunks) - 1), "IPv4", "data",
                        frag=k * 1480 // 8, mf=k < len(chunks) - 1, df=False, ident=ident, err="Fragment lost: the whole datagram is discarded" if bad else None, key="IP frag")
        else:
            fr = self.lan.udp("ms", "tv", 5004, 5004, rtp_pdu(self.rseq, int(self.t * 90000), 0x1F2E3D4C, n - 12), "RTP seq %d, %d bytes" % (self.rseq, n), "RTP", "data",
                              names={5004: "rtp"}, err="Lost on the Wi-Fi bridge" if lost else None)
        if lost:
            tv["Lost"] += 1
        tv["Loss"] = "%.1f %%" % (100.0 * tv["Lost"] / max(1, tv["Packets"]))

    def tpls(self):
        return [Tpl("DNS query", [P("n", "Name", "www.example.org")], lambda s, v, send: self.dns(v["n"], 0, send), "A-record lookup; try a name containing 'nosuch' for NXDOMAIN."),
                Tpl("Datagram to a closed port", [P("p", "Port", 9999, 1, 65535)], lambda s, v, send: self._closed(v["p"], send), "The receiver answers with ICMP port unreachable.")]

    def _closed(self, port, send):
        inner = Pdu(b"hello", [[0, "Data", 0, 5, ""]])
        if not send:
            return Frame(self.t, 0.0001, "lap", "ms", "UDP", "preview", pdu=udp_pdu(40000, port, inner, "192.168.1.50", "192.168.1.10"))
        self.lan.udp("lap", "ms", 40000, port, inner, "UDP 40000 -> %d, 5 bytes" % port, "UDP", "cmd")
        orig = ipv4_pdu("192.168.1.50", "192.168.1.10", 17, udp_pdu(40000, port, inner, "192.168.1.50", "192.168.1.10")).b[:28]
        self.at(self.t + 0.001, lambda: self.lan.l2("ms", "lap", 0x0800, ipv4_pdu("192.168.1.10", "192.168.1.50", 1, icmp_err(3, 3, orig)),
                                                    "ICMP destination unreachable (port %d unreachable)" % port, "ICMP", "err"))
        return None


# ============================================================ IPv4 / IPv6
def icmp6(src, dst, typ, code, fields, title):
    body = b"".join(f[1] for f in fields)
    msg = bytes([typ, code, 0, 0]) + body
    cs = inet_cs(ipb(src) + ipb(dst) + len(msg).to_bytes(4, "big") + b"\x00\x00\x00\x3a" + msg)
    b = Bld(title, "ICMPv6 (RFC 4443) - also carries Neighbor Discovery (RFC 4861).")
    b.u8("Type", typ, "%d" % typ, "")
    b.u8("Code", code, None, "")
    b.u16("Checksum", cs, "0x%04X [correct]" % cs, "Covers an IPv6 pseudo-header and the message.")
    for lab, data, txt, desc in fields:
        b.raw(lab, data, txt, desc)
    return b.done()


def sn_mcast(a):
    low = ipb(a)[-3:]
    import ipaddress
    return str(ipaddress.IPv6Address(bytes.fromhex("ff0200000000000000000001ff") + low)), "33:33:ff:%02x:%02x:%02x" % tuple(low)


def echo4(typ, ident, seq, n):
    data = bytes((i + 0x10) & 0xFF for i in range(n))
    body = bytes([typ, 0, 0, 0]) + struct.pack(">HH", ident, seq) + data
    cs = inet_cs(body)
    b = Bld("Internet Control Message Protocol (echo %s)" % ("request" if typ == 8 else "reply"), "Ping: the target returns the data unchanged.")
    b.u8("Type", typ, "%d (echo %s)" % (typ, "request" if typ == 8 else "reply"), "")
    b.u8("Code", 0, None, "")
    b.u16("Checksum", cs, "0x%04X [correct]" % cs, "")
    b.u16("Identifier", ident, None, "")
    b.u16("Sequence number", seq, None, "")
    b.raw("Data", data, "%d bytes" % n, "")
    return b.done()


def arp(op, smac, sip, tmac, tip):
    b = Bld("Address Resolution Protocol (%s)" % ("request" if op == 1 else "reply"), "RFC 826: who has this IPv4 address on the local link?")
    b.u16("Hardware type", 1, "Ethernet", "")
    b.u16("Protocol type", 0x0800, "IPv4", "")
    b.u8("Hardware size", 6, None, "")
    b.u8("Protocol size", 4, None, "")
    b.u16("Opcode", op, "request" if op == 1 else "reply", "")
    b.raw("Sender MAC", macb(smac), smac, "")
    b.raw("Sender IP", ipb(sip), sip, "")
    b.raw("Target MAC", macb(tmac), tmac, "")
    b.raw("Target IP", ipb(tip), tip, "")
    return b.done()


class IPNet(IpNet):
    key, name, cat = "ip", "IPv4 / IPv6", "net"
    blurb = "Internet addressing and routing"
    medium = "Dual-stack network: a host, a switch, two routers and a server; ARP and IPv6 neighbour discovery, SLAAC, ping, traceroute and path MTU"
    faults = [("mtu", "Link between the routers has MTU 1400", "Large packets with DF set (and every IPv6 packet) bounce with 'fragmentation needed' / 'packet too big'."),
              ("loop", "Routing loop between router 1 and router 2", "Packets for the server circle until the TTL / hop limit reaches zero: ICMP time exceeded."),
              ("dupip", "Printer configured with the host's IPv4 address", "Its gratuitous ARP claims 192.168.1.20: an address conflict."),
              ("nogw", "Host has no default gateway", "Packets to other networks cannot be sent at all: 'network unreachable' (nothing on the wire).")]
    spec = [("IPv4", "RFC 791: 20-byte header (version, IHL, DSCP / ECN, length, ID, flags DF / MF, fragment offset, TTL, protocol, checksum, addresses)"),
            ("IPv6", "RFC 8200: 40-byte fixed header (version, traffic class, flow label, payload length, next header, hop limit, 128-bit addresses)"),
            ("Address resolution", "IPv4 ARP broadcast; IPv6 Neighbor Solicitation to the solicited-node multicast address"),
            ("Autoconfiguration", "IPv4 DHCP; IPv6 SLAAC: Router Advertisement prefix + interface identifier, duplicate address detection"),
            ("Routing", "Longest-prefix match; each router decrements TTL / hop limit; ICMP time exceeded at zero"),
            ("Fragmentation", "IPv4 routers fragment unless DF is set; IPv6 only the sender fragments - routers send Packet Too Big")]
    frame = [["IPv4 header", ("Ver", 4), ("IHL", 4), ("DSCP/ECN", 8), ("Total length", 16), ("ID", 16), ("Flags", 3), ("Frag offset", 13), ("TTL", 8), ("Protocol", 8),
              ("Checksum", 16), ("Source", 32), ("Destination", 32)],
             ["IPv6 header", ("Ver", 4), ("Traffic class", 8), ("Flow label", 20), ("Payload len", 16), ("Next hdr", 8), ("Hop limit", 8), ("Source", 128), ("Destination", 128)]]
    about = ("IP moves packets between networks. Each router looks only at the destination address, picks the next hop and decrements the TTL "
             "(hop limit in IPv6). On the local link the sender must first find the next hop's MAC address - with ARP for IPv4 and neighbour "
             "discovery for IPv6. IPv6 hosts also configure themselves from router advertisements. Traceroute exploits the TTL to reveal the path.")
    guide = ["Watch IPv6 come up: Router Solicitation, Router Advertisement (prefix), duplicate address detection.",
             "Compare an IPv4 and an IPv6 ping: header sizes, TTL vs hop limit, ARP vs neighbour solicitation.",
             "Run a traceroute (COMPOSE): ICMP time exceeded from each router, then port unreachable from the server.",
             "Set MTU 1400 and ping with 1472 bytes and DF: 'fragmentation needed, next-hop MTU 1400'."]

    H4, R1A, R1B, R2A, R2B, S4 = "192.168.1.20", "192.168.1.1", "10.0.12.1", "10.0.12.2", "203.0.113.1", "203.0.113.80"
    H6, R16, S6 = "2001:db8:10::3e52:82ff:fe10:20", "fe80::21a:2bff:fe3c:1", "2001:db8:99::80"
    HM, R1M = "3c:52:82:10:00:20", "00:1a:2b:3c:00:01"

    def setup(self):
        line_nodes(self, [("h", "HOST", "pc", 20, self.H4, self.HM, "dual stack", 110), ("sw", "SWITCH", "switch", 195, "", "", "", 104),
                          ("r1", "ROUTER 1", "router", 360, self.R1A, self.R1M, "LAN / 10.0.12.0/30", 118), ("r2", "ROUTER 2", "router", 545, self.R2A, "00:1a:2b:3c:00:02", "to 203.0.113.0/24", 118),
                          ("srv", "SERVER", "server", 730, self.S4, "00:16:3e:00:00:80", "203.0.113.80", 118)])
        pr = self.node("pr", "PRINTER", "box", 195, 280, "192.168.1.30", "", w=104, h=40)
        self.lan.host("pr", "00:80:77:00:00:30", "192.168.1.30")
        self.seg([(247, 202), (247, 280)], "cat6", c0="rj45", c1="rj45")
        pr.extra["can"] = False
        self.user = "h"
        self.seq = 0
        self.arp_ok = False
        self.arp_wait = []
        self.slaac = False
        self.by["h"].vars.update({"IPv4": self.H4 + "/24 gw .1", "IPv6": "fe80:: only", "Last ping": "-", "Traceroute": "-"})
        self.at(0.1, self.rs)
        self.every(2.0, self.ping_cycle, 1.0)
        self.every(15.0, self.traceroute, 6.0)

    def send4(self, src, dst, smac, dmac, sip, dip, proto, inner, info, kind, ttl=64, df=True, pname="IPv4", err=None):
        pdu = eth_pdu(dmac, smac, 0x0800, ipv4_pdu(sip, dip, proto, inner, ttl=ttl, ident=int(self.rng.integers(0, 65535)), df=df))
        fr = self.lan.frame(src, dst, pdu, info, pname, kind, err=err, sd=sip, dd=dip)
        return self.lan.send(fr)

    def send6(self, src, dst, smac, dmac, sip, dip, nh, inner, info, kind, hlim=64, pname="ICMPv6"):
        pdu = eth_pdu(dmac, smac, 0x86DD, ipv6_pdu(sip, dip, nh, inner, hlim=hlim))
        fr = self.lan.frame(src, dst, pdu, info, pname, kind, sd=sip, dd=dip)
        return self.lan.send(fr)

    # ---------------------------------------------------------------- IPv6 start-up
    def rs(self):
        ll = "fe80::3e52:82ff:fe10:20"
        self.send6("h", None, self.HM, "33:33:00:00:00:02", ll, "ff02::2", 58, icmp6(ll, "ff02::2", 133, 0, [("Reserved", bytes(4), "", ""),
                   ("Option: source link-layer address", bytes([1, 1]) + macb(self.HM), self.HM, "")], "ICMPv6 Router Solicitation"), "Router Solicitation (to all routers ff02::2)", "ctl", 255)
        pref = ipb("2001:db8:10::")
        ra = icmp6(self.R16, "ff02::1", 134, 0, [("Cur hop limit", b"\x40", "64", ""), ("Flags", b"\x00", "M 0, O 0 (stateless)", "M = use DHCPv6 for addresses, O = for other config."),
                                                  ("Router lifetime", struct.pack(">H", 1800), "1800 s", "Non-zero: use me as default router."),
                                                  ("Reachable / retrans timers", bytes(8), "0 / 0", ""), ("Option: source link-layer address", bytes([1, 1]) + macb(self.R1M), self.R1M, ""),
                                                  ("Option: MTU", bytes([5, 1, 0, 0]) + struct.pack(">I", 1500), "1500", ""),
                                                  ("Option: prefix information", bytes([3, 4, 64, 0xC0]) + struct.pack(">II", 86400, 14400) + bytes(4) + pref, "2001:db8:10::/64, L A, valid 86400 s",
                                                   "A flag: hosts may form addresses from this prefix (SLAAC).")], "ICMPv6 Router Advertisement")
        self.at(self.t + 0.004, self.send6, "r1", None, self.R1M, "33:33:00:00:00:01", self.R16, "ff02::1", 58, ra, "Router Advertisement: prefix 2001:db8:10::/64 (SLAAC), router lifetime 1800 s", "resp", 255)
        sn, smac = sn_mcast(self.H6)
        ns = icmp6("::", sn, 135, 0, [("Reserved", bytes(4), "", ""), ("Target address", ipb(self.H6), self.H6, "The address being checked.")], "ICMPv6 Neighbor Solicitation (DAD)")
        self.at(self.t + 0.05, self.send6, "h", None, self.HM, smac, "::", sn, 58, ns, "Neighbor Solicitation from :: for %s (duplicate address detection)" % self.H6, "ctl", 255)
        self.at(self.t + 1.1, self._slaac)

    def _slaac(self):
        self.slaac = True
        self.by["h"].vars["IPv6"] = self.H6 + "/64 (SLAAC, EUI-64)"

    # ---------------------------------------------------------------- ping
    def ping_cycle(self):
        self.seq += 1
        if self.seq % 2:
            self.ping4(56)
        elif self.slaac:
            self.ping6(56)

    def arp_gw(self, then):
        """Resolve the gateway's MAC first; packets wait in a queue until the ARP reply arrives."""
        if self.arp_ok:
            then()
            return
        self.arp_wait.append(then)
        if len(self.arp_wait) > 1:
            return
        self.lan.l2("h", None, 0x0806, arp(1, self.HM, self.H4, "00:00:00:00:00:00", self.R1A), "ARP who has %s? tell %s" % (self.R1A, self.H4), "ARP", "bcast")
        self.at(self.t + 0.001, self._arp_reply)

    def _arp_reply(self):
        self.lan.l2("r1", "h", 0x0806, arp(2, self.R1M, self.R1A, self.HM, self.H4), "ARP %s is at %s" % (self.R1A, self.R1M), "ARP", "resp")
        self.arp_ok = True
        waiting, self.arp_wait = self.arp_wait, []
        for i, fn in enumerate(waiting):
            self.at(self.t + 0.001 + 0.0002 * i, fn)

    def ping4(self, n, df=True, send=True):
        if not send:
            return Frame(self.t, 0.0001, "h", "srv", "ICMP", "preview", pdu=eth_pdu(self.R1M, self.HM, 0x0800, ipv4_pdu(self.H4, self.S4, 1, echo4(8, 0x4D2, self.seq, n), df=df)))
        if self.fault["nogw"]:
            self.by["h"].vars["Last ping"] = "ping: connect: Network is unreachable (no default route)"
            return None

        seq0 = self.seq

        def go():
            seq = seq0
            self.send4("h", "srv", self.HM, self.R1M, self.H4, self.S4, 1, echo4(8, 0x4D2, seq, n), "Echo (ping) request id 0x04d2 seq %d, %d data bytes, DF %d" % (seq, n, df), "cmd", df=df)
            if self.fault["mtu"] and n + 28 > 1400 and df:
                orig = ipv4_pdu(self.H4, self.S4, 1, echo4(8, 0x4D2, seq, n)).b[:28]
                self.at(self.t + 0.001, self.send4, "r1", "h", self.R1M, self.HM, self.R1A, self.H4, 1, icmp_err(3, 4, orig, struct.pack(">HH", 0, 1400)),
                        "ICMP fragmentation needed and DF set, next-hop MTU 1400 (from router 1)", "err", 64, True, "ICMP")
                self.by["h"].vars["Last ping"] = "Frag needed: MTU 1400 on the path"
                return
            if self.fault["loop"]:
                orig = ipv4_pdu(self.H4, self.S4, 1, echo4(8, 0x4D2, seq, n)).b[:28]
                self.at(self.t + 0.012, self.send4, "r2", "h", self.R1M, self.HM, self.R2A, self.H4, 1, icmp_err(11, 0, orig),
                        "ICMP time exceeded in transit (TTL hit 0 after looping between the routers)", "err", 63, True, "ICMP")
                self.by["h"].vars["Last ping"] = "Time to live exceeded (routing loop)"
                return
            self.at(self.t + 0.0016, self.send4, "srv", "h", self.R1M, self.HM, self.S4, self.H4, 1, echo4(0, 0x4D2, seq, n),
                    "Echo (ping) reply id 0x04d2 seq %d, TTL 62 (64 minus 2 routers)" % seq, "resp", 62)
            self.by["h"].vars["Last ping"] = "%d bytes from %s: seq %d ttl 62 time 1.6 ms" % (n + 8, self.S4, seq)
        self.arp_gw(go)
        return None

    def ping6(self, n, send=True):
        e = icmp6(self.H6, self.S6, 128, 0, [("Identifier", struct.pack(">H", 0x4D2), "0x04d2", ""), ("Sequence", struct.pack(">H", self.seq), str(self.seq), ""),
                                             ("Data", bytes(n), "%d bytes" % n, "")], "ICMPv6 Echo Request")
        if not send:
            return Frame(self.t, 0.0001, "h", "srv", "ICMPv6", "preview", pdu=eth_pdu(self.R1M, self.HM, 0x86DD, ipv6_pdu(self.H6, self.S6, 58, e)))
        if not self.slaac:
            return None
        self.send6("h", "srv", self.HM, self.R1M, self.H6, self.S6, 58, e, "ICMPv6 echo request seq %d, %d bytes (hop limit 64)" % (self.seq, n), "cmd")
        if self.fault["mtu"] and n + 48 > 1400:
            ptb = icmp6(self.R16, self.H6, 2, 0, [("MTU", struct.pack(">I", 1400), "1400", "Routers never fragment IPv6: the sender must."),
                                                  ("Invoking packet", ipv6_pdu(self.H6, self.S6, 58, e).b[:200], "start of the packet", "")], "ICMPv6 Packet Too Big")
            self.at(self.t + 0.001, self.send6, "r1", "h", self.R1M, self.HM, self.R16, self.H6, 58, ptb, "ICMPv6 Packet Too Big, MTU 1400 (from router 1)", "err")
            return None
        r = icmp6(self.S6, self.H6, 129, 0, [("Identifier", struct.pack(">H", 0x4D2), "0x04d2", ""), ("Sequence", struct.pack(">H", self.seq), str(self.seq), ""),
                                             ("Data", bytes(n), "%d bytes" % n, "")], "ICMPv6 Echo Reply")
        self.at(self.t + 0.0016, self.send6, "srv", "h", self.R1M, self.HM, self.S6, self.H6, 58, r, "ICMPv6 echo reply seq %d (hop limit 62)" % self.seq, "resp", 62)
        return None

    def traceroute(self, send=True):
        hops = [("r1", self.R1A), ("r2", self.R2A)]
        if not send:
            return Frame(self.t, 0.0001, "h", "srv", "UDP", "preview", pdu=eth_pdu(self.R1M, self.HM, 0x0800, ipv4_pdu(self.H4, self.S4, 17, udp_pdu(54321, 33434, Pdu(bytes(32)), self.H4, self.S4), ttl=1)))
        if self.fault["nogw"]:
            return None
        out = []

        def probe(ttl):
            port = 33433 + ttl
            u = udp_pdu(54321, port, Pdu(bytes(32), [[0, "Probe data", 0, 32, ""]]), self.H4, self.S4)
            self.send4("h", "srv", self.HM, self.R1M, self.H4, self.S4, 17, u, "Traceroute probe UDP -> %d, TTL %d" % (port, ttl), "cmd", ttl, False, "UDP")
            orig = ipv4_pdu(self.H4, self.S4, 17, u, ttl=1).b[:28]
            if ttl <= 2:
                nid, ip = hops[ttl - 1]
                self.at(self.t + 0.001 * ttl, self.send4, nid, "h", self.R1M, self.HM, ip, self.H4, 1, icmp_err(11, 0, orig), "ICMP time exceeded from %s (hop %d)" % (ip, ttl), "err", 65 - ttl, True, "ICMP")
                out.append(ip)
                self.at(self.t + 0.05, probe, ttl + 1)
            else:
                self.at(self.t + 0.0016, self.send4, "srv", "h", self.R1M, self.HM, self.S4, self.H4, 1, icmp_err(3, 3, orig), "ICMP port unreachable from %s: destination reached" % self.S4,
                        "resp", 62, True, "ICMP")
                out.append(self.S4)
                self.by["h"].vars["Traceroute"] = " > ".join(out)
        self.arp_gw(lambda: probe(1))
        return None

    def on_fault(self, key, on):
        if key == "dupip" and on:
            self.lan.l2("pr", None, 0x0806, arp(1, "00:80:77:00:00:30", self.H4, "00:00:00:00:00:00", self.H4),
                        "Gratuitous ARP: %s is at 00:80:77:00:00:30 (the printer!)" % self.H4, "ARP", "err")
            self.log("Host: IPv4 address conflict - %s is also used by 00:80:77:00:00:30" % self.H4)
            self.by["h"].vars["IPv4"] = self.H4 + " CONFLICT with 00:80:77:00:00:30"
        elif key == "dupip":
            self.by["h"].vars["IPv4"] = self.H4 + "/24 gw .1"

    def _user(self, fn, *a):
        self.seq += 1                    # every ping gets its own sequence number
        return fn(*a)

    def tpls(self):
        return [Tpl("Ping IPv4", [P("n", "Data bytes", 56, 0, 1472), P("df", "Don't fragment", "yes", opts=["yes", "no"])],
                    lambda s, v, send: self.ping4(v["n"], v["df"] == "yes", send) if not send else self._user(self.ping4, v["n"], v["df"] == "yes"),
                    "1472 data bytes + 28 header bytes = 1500 (a full Ethernet MTU)."),
                Tpl("Ping IPv6", [P("n", "Data bytes", 56, 0, 1452)], lambda s, v, send: self.ping6(v["n"], send) if not send else self._user(self.ping6, v["n"]),
                    "ICMPv6 echo; with MTU 1400 a large one gets Packet Too Big."),
                Tpl("Traceroute", [], lambda s, v, send: self.traceroute(send), "UDP probes with TTL 1, 2, 3 ...")]


# ============================================================== HTTP / HTTPS
def decrypted(p, lines):
    p.rows.append([0, "Decrypted TLS payload (session keys logged)", None, 0, "What the endpoints see after decryption; on the wire it is unreadable."])
    for ln in lines:
        p.rows.append([1, ln, None, 0, ""])
    return p


class HTTP(IpNet):
    key, name, cat = "http", "HTTP / HTTPS", "net"
    blurb = "Web communication and REST APIs"
    medium = "A browser loads a web site (HTTP redirect to HTTPS, TLS 1.3 handshake, cached resources) and an app calls a REST API"
    faults = [("cert", "Web server certificate expired", "The browser aborts the handshake with a fatal TLS alert (certificate_expired)."),
              ("404", "Broken link to /index.htm", "The server answers 404 Not Found."),
              ("503", "API server overloaded", "503 Service Unavailable with Retry-After; the app backs off."),
              ("slow", "Slow database behind the web server", "Time to first byte grows to 1.5 s.")]
    spec = [("Standards", "HTTP semantics RFC 9110, HTTP/1.1 RFC 9112, HTTP/2 RFC 9113, HTTP/3 RFC 9114 (QUIC); TLS 1.3 RFC 8446"),
            ("Ports", "80 (http), 443 (https)"),
            ("Request", "Method (GET, POST, PUT, DELETE ...) + target + version, headers, blank line, optional body"),
            ("Response", "Status code (1xx info, 2xx success, 3xx redirect, 4xx client error, 5xx server error) + headers + body"),
            ("Caching", "ETag / If-None-Match and Last-Modified / If-Modified-Since give 304 Not Modified"),
            ("TLS 1.3", "ClientHello (SNI, ALPN, key share) -> ServerHello; certificate and Finished already encrypted; 1 round trip")]
    frame = [["HTTP/1.1 request", ("Method SP target SP version CRLF", "text"), ("Header: value CRLF ...", "text"), ("CRLF", 16), ("Body", "n x 8")]]
    about = ("HTTP is the request/response protocol of the web and of most APIs: a text request line and headers, a status code and a body in "
             "return. Today almost all of it runs inside TLS (HTTPS), which authenticates the server with a certificate and encrypts everything - "
             "so on the wire you only see the TLS records, and the hostname in the ClientHello.")
    guide = ["Follow http://www.example.net: GET, 301 redirect to https.",
             "Watch the TLS 1.3 handshake: ClientHello with SNI, ServerHello, then encrypted records.",
             "Select an encrypted record: the 'decrypted' rows show the HTTP request inside.",
             "COMPOSE a POST to the API and read the 201 Created; then overload the API (503)."]

    def setup(self):
        hosts = [("br", "BROWSER", "laptop", 40, 40, "192.168.1.20", "3c:52:82:10:00:20", "client"),
                 ("web", "WEB SERVER", "server", 700, 40, "198.51.100.10", "00:16:3e:10:00:10", "www.example.net"),
                 ("app", "MOBILE APP", "phone", 40, 290, "192.168.1.30", "a4:77:33:00:00:30", "REST client"),
                 ("api", "API SERVER", "server", 700, 290, "198.51.100.20", "00:16:3e:10:00:20", "api.example.net")]
        self.star(hosts, sw=("sw", "INTERNET", 380, 160))
        self.user = "br"
        self.port = 50100
        self.oid = 1000
        self.by["br"].vars.update({"Page": "-", "TLS": "-", "Status": "-"})
        self.by["app"].vars.update({"Last API call": "-", "Retry-After": "-"})
        self.at(0.1, self.visit)
        self.every(6.0, self.api_poll, 3.0)
        self.every(15.0, self.visit, 15.0)

    def conn(self, a, b, port, then):
        self.port += 1
        c = self.tcp(a, b, self.port, port, "HTTP" if port == 80 else "TLS")
        c.connect(on_open=lambda: self.at(self.t + 0.001, then, c))
        return c

    def visit(self):
        def plain(c):
            c.send("br", http_req("GET", "/", [("Host", "www.example.net"), ("User-Agent", "CommSim/1.0"), ("Accept", "text/html")]), "GET / HTTP/1.1 (Host: www.example.net)", "HTTP", "cmd")
            self.at(self.t + 0.002, lambda: c.send("web", http_rsp(301, [("Location", "https://www.example.net/"), ("Server", "nginx")]),
                                                   "HTTP/1.1 301 Moved Permanently -> https://www.example.net/", "HTTP", "resp"))
            self.at(self.t + 0.004, c.close, "br")
            self.at(self.t + 0.05, self.tls_visit)
        self.conn("br", "web", 80, plain)

    def tls_visit(self):
        def go(c):
            ch = tls_hs(1, [("ClientHello: SNI = www.example.net", "Server Name Indication: which site (sent in clear)."),
                            ("ALPN: h2, http/1.1", "Application protocols the client can speak."), ("key_share: x25519", "Client's ephemeral public key.")])
            c.send("br", ch, "TLS ClientHello (SNI www.example.net, TLS 1.3)", "TLS", "ctl")
            if self.fault["cert"]:
                self.at(self.t + 0.002, lambda: c.send("web", tls_hs(2, [("ServerHello: TLS_AES_128_GCM_SHA256, x25519", "")]), "TLS ServerHello + encrypted certificate", "TLS", "resp"))
                al = tls_record(21, b"\x02\x2d", title="TLS Alert")
                al.rows.append([1, "Level 2 (fatal), description 45 (certificate_expired)", None, 0, "The certificate's notAfter date is in the past."])
                self.at(self.t + 0.004, lambda: c.send("br", al, "TLS Alert (fatal): certificate_expired", "TLS", "err"))
                self.at(self.t + 0.005, c.reset, "br")
                self.by["br"].vars.update({"TLS": "FAILED", "Status": "NET::ERR_CERT_DATE_INVALID"})
                return
            self.at(self.t + 0.002, lambda: c.send("web", tls_hs(2, [("ServerHello: cipher TLS_AES_128_GCM_SHA256, key_share x25519", "From here on everything is encrypted.")]),
                                                   "TLS ServerHello", "TLS", "resp"))
            enc = decrypted(tls_record(23, 3150), ["EncryptedExtensions (ALPN http/1.1)", "Certificate: CN=www.example.net, issuer: Example CA, valid to 2027-03-01",
                                                   "CertificateVerify (signature over the transcript)", "Finished"])
            self.at(self.t + 0.0022, lambda: c.send("web", enc, "TLS encrypted handshake: EncryptedExtensions, Certificate, CertificateVerify, Finished", "TLS", "resp"))
            fin = decrypted(tls_record(23, 53), ["Finished (client)"])
            self.at(self.t + 0.004, lambda: c.send("br", fin, "TLS client Finished (encrypted)", "TLS", "ctl"))
            self.by["br"].vars["TLS"] = "TLS 1.3, TLS_AES_128_GCM_SHA256, x25519"
            self.at(self.t + 0.0045, self.get, c, "/" if not self.fault["404"] else "/index.htm")
            self.at(self.t + 0.05, self.get, c, "/style.css", True)
        self.conn("br", "web", 443, go)

    def get(self, c, path, cond=False):
        if not c.open:
            return
        lines = ["GET %s HTTP/1.1" % path, "Host: www.example.net"] + (['If-None-Match: "5f2a-19c"'] if cond else [])
        c.send("br", decrypted(tls_record(23, 180), lines), "TLS application data: GET %s%s" % (path, " (If-None-Match)" if cond else ""), "TLS", "cmd")
        delay = 1.5 if self.fault["slow"] else 0.003
        if path == "/index.htm":
            r, txt, n = 404, "404 Not Found", 210
        elif cond:
            r, txt, n = 304, "304 Not Modified (use the cached copy)", 120
        else:
            r, txt, n = 200, "200 OK, text/html, 12 KB", 12400
        rows = ["HTTP/1.1 %s" % txt, "Content-Type: text/html; charset=utf-8" if r == 200 else "Server: nginx", 'ETag: "5f2a-19c"' if r != 404 else "Content-Length: 162",
                "Cache-Control: max-age=600"]
        self.at(self.t + delay, lambda: c.send("web", decrypted(tls_record(23, n), rows), "TLS application data: HTTP/1.1 %s" % txt, "TLS", "resp" if r < 400 else "err"))
        if not cond:
            self.by["br"].vars.update({"Page": path, "Status": "%d (TTFB %.0f ms)" % (r, delay * 1000 + 2)})

    def api_poll(self):
        self.api("POST", "/v1/orders", {"item": "sensor-kit", "qty": 2})

    def api(self, method, path, body, send=True):
        data = jdump(body).encode() if body else b""
        hdrs = [("Host", "api.example.net"), ("Authorization", "Bearer eyJhbGciOi..."), ("Content-Type", "application/json"), ("Accept", "application/json")]
        if not send:
            return Frame(self.t, 0.0001, "app", "api", "HTTP", "preview", pdu=http_req(method, path, hdrs, data))

        def go(c):
            c.send("app", tls_hs(1, [("ClientHello: SNI = api.example.net", "")]), "TLS ClientHello (SNI api.example.net)", "TLS", "ctl")
            self.at(self.t + 0.002, lambda: c.send("api", tls_hs(2), "TLS ServerHello + encrypted handshake", "TLS", "resp"))
            req = decrypted(tls_record(23, 200 + len(data)), ["%s %s HTTP/1.1" % (method, path), "Host: api.example.net", "Content-Type: application/json", data.decode()])
            self.at(self.t + 0.004, lambda: c.send("app", req, "TLS application data: %s %s %s" % (method, path, data.decode()[:40]), "TLS", "cmd"))
            if self.fault["503"]:
                rsp = decrypted(tls_record(23, 160), ["HTTP/1.1 503 Service Unavailable", "Retry-After: 30"])
                self.at(self.t + 0.006, lambda: c.send("api", rsp, "TLS application data: HTTP/1.1 503 Service Unavailable, Retry-After: 30", "TLS", "err"))
                self.by["app"].vars.update({"Last API call": "503 - backing off", "Retry-After": "30 s"})
            else:
                self.oid += 1
                out = jdump({"id": self.oid, "status": "created", "item": body.get("item") if body else None})
                rsp = decrypted(tls_record(23, 220), ["HTTP/1.1 201 Created", "Location: /v1/orders/%d" % self.oid, "Content-Type: application/json", out])
                self.at(self.t + 0.006, lambda: c.send("api", rsp, "TLS application data: HTTP/1.1 201 Created, Location /v1/orders/%d" % self.oid, "TLS", "resp"))
                self.by["app"].vars.update({"Last API call": "201 Created order %d" % self.oid, "Retry-After": "-"})
            self.at(self.t + 0.03, c.close, "app")
        self.conn("app", "api", 443, go)
        return None

    def tpls(self):
        return [Tpl("Browse to a path", [P("p", "Path", "/products")], lambda s, v, send: self._browse(v["p"], send), "HTTPS GET on the open connection (or a new one)."),
                Tpl("REST API call", [P("m", "Method", "POST", opts=["POST", "PUT", "DELETE"]), P("p", "Path", "/v1/orders"), P("b", "JSON body", '{"item": "relay", "qty": 1}')],
                    lambda s, v, send: self._api(v, send), "JSON over HTTPS; the server answers with a status code.")]

    def _browse(self, path, send):
        if not send:
            return Frame(self.t, 0.0001, "br", "web", "HTTP", "preview", pdu=http_req("GET", path, [("Host", "www.example.net")]))
        self.conn("br", "web", 443, lambda c: (c.send("br", tls_hs(1), "TLS ClientHello (resumed session)", "TLS", "ctl"), self.at(self.t + 0.004, self.get, c, path)))
        return None

    def _api(self, v, send):
        import json
        try:
            body = json.loads(v["b"])
        except ValueError:
            body = {"raw": v["b"]}
        return self.api(v["m"], v["p"], body, send)


# =============================================================== WebSocket
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_accept(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


class WebSocket(IpNet):
    key, name, cat = "websocket", "WebSocket", "net"
    blurb = "Real-time web communication"
    medium = "A browser dashboard keeps one WebSocket open to a server that pushes live sensor values; pings, fragmented messages and a clean close"
    faults = [("proxy", "Corporate proxy strips the Upgrade header", "The server sees a plain GET and answers 426 Upgrade Required; the page falls back to polling."),
              ("nomask", "Buggy client sends unmasked frames", "The server must fail the connection: close code 1002 (protocol error)."),
              ("nat", "NAT router drops the idle mapping", "Pings get no pong; after the timeout the client reports close code 1006 (abnormal) and reconnects.")]
    spec = [("Standard", "RFC 6455 (WebSocket protocol), RFC 8441 (over HTTP/2); browsers: WebSocket API"),
            ("Handshake", "HTTP/1.1 GET with Upgrade: websocket, Sec-WebSocket-Key; 101 Switching Protocols with Sec-WebSocket-Accept = base64(SHA-1(key + GUID))"),
            ("Frames", "FIN, opcode (1 text, 2 binary, 0 continuation, 8 close, 9 ping, 10 pong), MASK bit + 32-bit key for client frames, 7/16/64-bit length"),
            ("Keep-alive", "Ping / pong control frames (may be sent at any time, even between fragments)"),
            ("Close", "Close frame with a 2-byte code (1000 normal, 1001 going away, 1002 protocol error, 1008 policy, 1011 server error) echoed back")]
    frame = [["Frame header", ("FIN", 1), ("RSV", 3), ("Opcode", 4), ("MASK", 1), ("Length", 7), ("[ext length]", "0/16/64"), ("[masking key]", "0/32"), ("Payload", "n x 8")]]
    about = ("WebSocket turns an HTTP request into a long-lived, full-duplex message channel: after a single upgrade handshake either side "
             "can send messages at any time, with only 2-14 bytes of framing. Browsers use it for chat, dashboards, games and trading screens. "
             "Frames from the client are XOR-masked with a random key, a defence against confused proxies.")
    guide = ["Check the handshake: compute base64(SHA-1(Sec-WebSocket-Key + GUID)) and compare with Sec-WebSocket-Accept.",
             "Server-to-client frames are unmasked; client frames carry a masking key - see both in the dissection.",
             "Find the fragmented message: FIN = 0 text frame, then continuation frames, the last with FIN = 1.",
             "Close with code 1000 (COMPOSE) and watch it echoed back."]

    KEY = "dGhlIHNhbXBsZSBub25jZQ=="

    def setup(self):
        hosts = [("br", "BROWSER DASHBOARD", "laptop", 40, 150, "192.168.1.20", "3c:52:82:10:00:20", "ws client"),
                 ("srv", "WEB / WS SERVER", "server", 700, 150, "198.51.100.30", "00:16:3e:10:00:30", "wss://live.example.net")]
        self.star(hosts, sw=("sw", "PROXY / NAT ROUTER", 370, 150))
        self.user = "br"
        self.c = None
        self.open_ = False
        self.n = 0
        self.port = 51000
        self.by["br"].vars.update({"State": "CLOSED", "Messages": 0, "Last value": "-"})
        self.at(0.1, self.connect)
        self.every(0.5, self.push, 1.0)
        self.every(5.0, self.ping, 3.0)
        self.every(9.0, self.fragmented, 6.5)

    def connect(self):
        self.port += 1
        self.c = self.tcp("br", "srv", self.port, 80, "WebSocket")
        self.c.connect(on_open=self.upgrade)

    def upgrade(self):
        c = self.c
        hdrs = [("Host", "live.example.net"), ("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Key", self.KEY), ("Sec-WebSocket-Version", "13"),
                ("Origin", "https://dash.example.net")]
        if self.fault["proxy"]:
            hdrs = [h for h in hdrs if h[0] not in ("Upgrade", "Connection")] + [("Connection", "keep-alive")]
        c.send("br", http_req("GET", "/ws/sensors", hdrs), "HTTP GET /ws/sensors%s" % (" (Upgrade header stripped by the proxy!)" if self.fault["proxy"] else " Upgrade: websocket"),
               "HTTP", "cmd")
        if self.fault["proxy"]:
            self.at(self.t + 0.002, lambda: c.send("srv", http_rsp(426, [("Upgrade", "websocket"), ("Connection", "Upgrade")], b"WebSocket required"),
                                                   "HTTP/1.1 426 Upgrade Required", "HTTP", "err"))
            self.by["br"].vars["State"] = "FAILED: falling back to long polling"
            return
        acc = ws_accept(self.KEY)
        self.at(self.t + 0.002, lambda: c.send("srv", http_rsp(101, [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Accept", acc)]),
                                               "HTTP/1.1 101 Switching Protocols, Sec-WebSocket-Accept %s" % acc, "HTTP", "resp"))
        self.at(self.t + 0.003, self._opened)

    def _opened(self):
        self.open_ = True
        self.by["br"].vars["State"] = "OPEN"
        self.client_send(jdump({"op": "subscribe", "topics": ["line1/temperature", "line1/pressure"]}))

    def client_send(self, txt, send=True):
        masked = not self.fault["nomask"]
        p = ws_frame(txt, 1, masked, title="WebSocket text frame (client -> server)")
        if not send:
            return Frame(self.t, 0.0001, "br", "srv", "WebSocket", "preview", pdu=p)
        if not (self.open_ and self.c and self.c.open):
            return None
        self.c.send("br", p, "WS text%s: %s" % (" (masked)" if masked else " UNMASKED", txt[:60]), "WebSocket", "cmd")
        if not masked:
            cl = ws_frame(struct.pack(">H", 1002) + b"client frame not masked", 8, title="WebSocket close frame")
            self.at(self.t + 0.002, lambda: self.c.send("srv", cl, "WS close 1002 (protocol error: client frame not masked)", "WebSocket", "err"))
            self.at(self.t + 0.004, self._closed, "closed by server (1002)")
        return None

    def push(self):
        if not (self.open_ and self.c and self.c.open) or self.fault["nat"]:
            return
        self.n += 1
        v = 72.0 + 3 * math.sin(self.t / 4)
        msg = jdump({"topic": "line1/temperature", "ts": utc(self.t).strftime("%H:%M:%S.%f")[:-3], "value": round(v, 2), "unit": "degC"})
        self.c.send("srv", ws_frame(msg, title="WebSocket text frame (server push)"), "WS text (unmasked): %s" % msg, "WebSocket", "data", auto_ack=self.n % 4 == 0)
        self.by["br"].vars["Messages"] += 1
        self.by["br"].vars["Last value"] = "%.2f degC" % v

    def ping(self):
        if not (self.open_ and self.c and self.c.open):
            return
        self.c.send("srv", ws_frame(b"hb-%d" % int(self.t), 9, title="WebSocket ping"), "WS ping (server keep-alive)", "WebSocket", "ctl")
        if self.fault["nat"]:
            self.misses = getattr(self, "misses", 0) + 1
            if self.misses >= 2:
                self.log("No pong and no data for 10 s: connection considered dead (1006 abnormal closure)")
                self._closed("1006 abnormal closure - reconnecting")
                self.c.open = False
                self.at(self.t + 1.0, self.connect)
            return
        self.misses = 0
        self.at(self.t + 0.002, lambda: self.c.send("br", ws_frame(b"hb-%d" % int(self.t), 10, True, title="WebSocket pong"), "WS pong (masked, same payload)", "WebSocket", "ack"))

    def fragmented(self):
        if not (self.open_ and self.c and self.c.open) or self.fault["nat"]:
            return
        big = jdump({"topic": "line1/history", "values": [round(70 + 0.1 * i, 1) for i in range(60)]})
        parts = [big[i:i + 120] for i in range(0, len(big), 120)]
        for k, part in enumerate(parts):
            op = 1 if k == 0 else 0
            p = ws_frame(part, op, title="WebSocket %s frame, FIN %d" % ("first text" if k == 0 else "continuation", k == len(parts) - 1))
            if k < len(parts) - 1:
                p = Pdu(bytes([p.b[0] & 0x7F]) + p.b[1:], p.rows)
                p.rows[1] = [1, "FIN | RSV | opcode: FIN 0, opcode %d (%s)" % (op, "text" if op else "continuation"), 0, 1, "FIN = 0: more fragments follow."]
            self.at(self.t + 0.0005 * k, lambda p=p, k=k: self.c.send("srv", p, "WS fragment %d/%d (%s, FIN %d)" % (k + 1, len(parts), "text" if k == 0 else "continuation",
                                                                                                                      k == len(parts) - 1), "WebSocket", "data", auto_ack=False))

    def _closed(self, why):
        self.open_ = False
        self.by["br"].vars["State"] = "CLOSED (%s)" % why

    def close(self, code, send=True):
        p = ws_frame(struct.pack(">H", code) + b"bye", 8, True, title="WebSocket close frame")
        if not send:
            return Frame(self.t, 0.0001, "br", "srv", "WebSocket", "preview", pdu=p)
        if not self.open_:
            return None
        self.c.send("br", p, "WS close %d (client)" % code, "WebSocket", "ctl")
        self.at(self.t + 0.002, lambda: self.c.send("srv", ws_frame(struct.pack(">H", code), 8, title="WebSocket close frame (echo)"), "WS close %d (server echo)" % code, "WebSocket", "ack"))
        self.at(self.t + 0.004, self.c.close, "srv")
        self._closed("%d normal" % code)
        self.at(self.t + 3.0, self.connect)
        return None

    def on_fault(self, key, on):
        if key == "proxy" and not on and not self.open_:
            self.at(self.t + 0.2, self.connect)

    def tpls(self):
        return [Tpl("Send text message", [P("m", "Message", '{"op": "setpoint", "value": 75}')], lambda s, v, send: self.client_send(v["m"], send), "Client frames are masked."),
                Tpl("Close", [P("c", "Close code", 1000, opts=[1000, 1001, 1008, 1011])], lambda s, v, send: self.close(v["c"], send), "Close handshake: the peer echoes the code.")]


# ============================================================== FTP / SFTP
def ftp_line(txt, title):
    b = Bld(title, "RFC 959: one text line per command or reply, ended by CR LF.")
    b.text("Line", txt + "\r\n", "Commands: 4-letter verbs; replies: 3-digit code (1xx preliminary, 2xx OK, 3xx need more, 4xx transient, 5xx permanent).")
    return b.done()


def ssh_pkt(payload_len, title, lines, seq):
    data = struct.pack(">I", payload_len + 16) + bytes(payload_len + 16 + 16)
    b = Bld(title, "SSH binary packet (RFC 4253): packet length, then encrypted padding length, payload and padding, then the MAC / AEAD tag.")
    b.raw("Packet length", data[:4], str(payload_len + 16), "With chacha20-poly1305 even this length is encrypted (shown in clear here).")
    b.raw("Encrypted payload + padding", data[4:4 + payload_len + 16], "%d bytes" % (payload_len + 16), "")
    b.raw("MAC / auth tag", data[-16:], "16 bytes", "Integrity check over the sequence number (%d) and the packet." % seq)
    p = b.done()
    return decrypted(p, lines)


class FTP(IpNet):
    key, name, cat = "ftp", "FTP / SFTP", "net"
    blurb = "File transfer"
    medium = "FTP to a file server (control connection on port 21, passive data connections) and the same transfer with SFTP over SSH (port 22)"
    faults = [("auth", "Wrong password configured in the client", "530 Login incorrect - and the password crossed the network in clear text."),
              ("active", "Client uses active mode behind NAT", "PORT tells the server to connect back to a private address: 425 Can't open data connection."),
              ("ascii", "Binary file transferred in ASCII mode (TYPE A)", "Line endings are translated: the firmware image arrives corrupted."),
              ("fw", "Firewall blocks the passive port range", "The data connection SYN is never answered: the transfer hangs and times out.")]
    spec = [("FTP", "RFC 959 (+ RFC 2428 EPSV, RFC 4217 FTPS); control TCP 21, data on separate connections; clear-text credentials"),
            ("Modes", "Passive (PASV / EPSV: client connects to a server port) or active (PORT: server connects back to the client)"),
            ("Replies", "1xx preliminary, 2xx done, 3xx more input needed, 4xx transient failure, 5xx permanent failure"),
            ("Types", "TYPE I (image, binary) or TYPE A (ASCII, line endings converted)"),
            ("SFTP", "SSH File Transfer Protocol: a subsystem of SSH (port 22), one encrypted connection, packets such as SSH_FXP_OPEN / READ / DATA / CLOSE")]
    frame = [["FTP session", ("Control: USER/PASS/TYPE/PASV", "text"), ("227 (h1,h2,h3,h4,p1,p2)", "text"), ("Data connection", "bytes"), ("226 Transfer complete", "text")]]
    about = ("FTP is one of the oldest internet protocols and still common on embedded devices and industrial equipment. It uses a text control "
             "connection for commands and a separate TCP connection for every listing or file - which is why it fights with NAT and firewalls - "
             "and it sends the password in clear. SFTP does the same job inside one SSH connection, fully encrypted.")
    guide = ["Read the login in the analyzer: USER and PASS in clear text.",
             "Decode the 227 reply: port = p1 x 256 + p2, then find the data connection to that port.",
             "Compare with the SFTP session: after the key exchange everything is encrypted.",
             "Switch the client to active mode and see why it fails behind NAT."]

    def setup(self):
        hosts = [("cli", "ENGINEERING LAPTOP", "laptop", 40, 40, "192.168.1.20", "3c:52:82:10:00:20", "FTP + SFTP client"),
                 ("srv", "FILE SERVER", "server", 700, 150, "198.51.100.50", "00:16:3e:10:00:50", "ftpd 21, sshd 22")]
        self.star(hosts, sw=("sw", "NAT ROUTER", 380, 150))
        self.user = "cli"
        self.port = 52000
        self.by["cli"].vars.update({"FTP": "-", "Last transfer": "-", "SFTP": "-"})
        self.at(0.1, self.ftp_session)
        self.at(6.0, self.sftp_session)
        self.every(14.0, self.ftp_session, 14.0)

    def ctl(self, c, who, txt, kind, d=0.0):
        self.at(self.t + d, lambda: c.send(who, ftp_line(txt, "File Transfer Protocol (%s)" % ("command" if who == "cli" else "reply")),
                                             ("FTP %s" % txt) if who == "cli" else "FTP %s" % txt, "FTP", kind) if c.open else None)

    def ftp_session(self, fname="firmware-2.4.1.bin", size=48_200):
        self.port += 1
        c = self.tcp("cli", "srv", self.port, 21, "FTP")

        def opened():
            self.ctl(c, "srv", "220 CommSim FTP server ready", "resp")
            self.ctl(c, "cli", "USER engineer", "cmd", 0.01)
            self.ctl(c, "srv", "331 Password required for engineer", "resp", 0.012)
            self.ctl(c, "cli", "PASS %s" % ("Spring2026" if self.fault["auth"] else "Sup3rS3cret"), "cmd", 0.02)
            if self.fault["auth"]:
                self.ctl(c, "srv", "530 Login incorrect.", "err", 0.5)
                self.at(self.t + 0.55, c.close, "cli")
                self.by["cli"].vars["FTP"] = "530 Login incorrect (password was sent in clear!)"
                return
            self.ctl(c, "srv", "230 User engineer logged in", "resp", 0.03)
            self.ctl(c, "cli", "TYPE %s" % ("A" if self.fault["ascii"] else "I"), "cmd", 0.04)
            self.ctl(c, "srv", "200 Type set to %s" % ("A (ASCII)" if self.fault["ascii"] else "I (binary)"), "resp", 0.042)
            if self.fault["active"]:
                self.ctl(c, "cli", "PORT 192,168,1,20,203,32", "cmd", 0.05)
                self.ctl(c, "srv", "200 PORT command successful", "resp", 0.052)
                self.ctl(c, "cli", "RETR %s" % fname, "cmd", 0.06)
                self.ctl(c, "srv", "425 Can't open data connection (192.168.1.20 is not reachable from the internet)", "err", 3.06)
                self.by["cli"].vars["FTP"] = "425: active mode behind NAT"
                return
            dport = 50000 + int(self.rng.integers(0, 900))
            self.ctl(c, "cli", "PASV", "cmd", 0.05)
            self.ctl(c, "srv", "227 Entering Passive Mode (198,51,100,50,%d,%d)" % (dport >> 8, dport & 255), "resp", 0.052)
            self.ctl(c, "cli", "RETR %s" % fname, "cmd", 0.07)
            self.at(self.t + 0.06, self.data_conn, c, dport, fname, size)
        c.connect(on_open=opened)

    def data_conn(self, c, dport, fname, size):
        self.port += 1
        if self.fault["fw"]:
            d = self.tcp("cli", "srv", self.port, dport, "FTP-DATA")
            d.seg("cli", 0x02, info="%d → %d [SYN] (passive data port blocked by the firewall)" % (self.port, dport), err="No answer: dropped by the firewall")
            self.ctl(c, "srv", "425 Can't open data connection", "err", 3.0)
            self.by["cli"].vars["FTP"] = "data connection timed out (firewall)"
            return
        d = self.tcp("cli", "srv", self.port, dport, "FTP-DATA")

        def go():
            self.ctl(c, "srv", "150 Opening %s mode data connection for %s (%d bytes)" % ("ASCII" if self.fault["ascii"] else "BINARY", fname, size), "resp")
            n = 0
            k = 0
            while n < size:
                ln = min(1448, size - n)
                chunk = Pdu(bytes(ln), [[0, "FTP-DATA: %s bytes %d-%d" % (fname, n, n + ln - 1), 0, ln, "Raw file content, no framing: end of file = connection closed."]])
                self.at(self.t + 0.002 + 0.0003 * k, lambda ch=chunk, a=n: d.send("srv", ch, "FTP-DATA %d bytes (offset %d)" % (len(ch.b), a), "FTP-DATA", "data", auto_ack=False) if d.open else None)
                n += ln
                k += 1
            self.at(self.t + 0.003 + 0.0003 * k, d.close, "srv")
            self.ctl(c, "srv", "226 Transfer complete", "resp", 0.01 + 0.0003 * k)
            self.ctl(c, "cli", "QUIT", "cmd", 0.05 + 0.0003 * k)
            self.ctl(c, "srv", "221 Goodbye", "resp", 0.052 + 0.0003 * k)
            self.at(self.t + 0.06 + 0.0003 * k, c.close, "srv")
            self.by["cli"].vars["Last transfer"] = "%s, %d bytes%s" % (fname, size, " - CORRUPTED (ASCII mode changed CR/LF bytes)" if self.fault["ascii"] else "")
            self.by["cli"].vars["FTP"] = "ok (passive, port %d)" % dport
        d.connect(on_open=go)

    def sftp_session(self):
        self.port += 1
        c = self.tcp("cli", "srv", self.port, 22, "SSH")
        seq = [0]

        def enc(who, n, title, lines, info, kind):
            seq[0] += 1
            c.send(who, ssh_pkt(n, title, lines, seq[0]), info, "SSH", kind)

        def opened():
            for i, (who, txt) in enumerate((("srv", "SSH-2.0-CommSim_SSHD_3.1"), ("cli", "SSH-2.0-CommSim_SFTP_1.2"))):
                b = Bld("SSH protocol version exchange", "RFC 4253: one text line in clear.")
                b.text("Version", txt + "\r\n", "")
                self.at(self.t + 0.001 * i, lambda b=b, who=who, txt=txt: c.send(who, b.done(), "SSH version: %s" % txt, "SSH", "ctl"))
            steps = [("cli", 1100, "SSH_MSG_KEXINIT", ["kex: curve25519-sha256, cipher: chacha20-poly1305@openssh.com"], "KEXINIT (algorithm lists, in clear)", "ctl"),
                     ("srv", 1000, "SSH_MSG_KEXINIT", ["server algorithm lists"], "KEXINIT (server)", "ctl"),
                     ("cli", 44, "SSH_MSG_KEX_ECDH_INIT", ["client ephemeral x25519 key"], "KEX_ECDH_INIT", "ctl"),
                     ("srv", 600, "SSH_MSG_KEX_ECDH_REPLY", ["host key ssh-ed25519, server ephemeral key, signature"], "KEX_ECDH_REPLY + NEWKEYS", "ctl"),
                     ("cli", 20, "SSH_MSG_USERAUTH_REQUEST", ["user engineer, method publickey (ssh-ed25519)"], "Encrypted: USERAUTH_REQUEST publickey", "cmd"),
                     ("srv", 12, "SSH_MSG_USERAUTH_SUCCESS", ["authentication succeeded"], "Encrypted: USERAUTH_SUCCESS", "resp"),
                     ("cli", 40, "SSH_MSG_CHANNEL_REQUEST", ['channel 0: subsystem "sftp"'], "Encrypted: CHANNEL_OPEN session + subsystem sftp", "cmd"),
                     ("cli", 40, "SFTP SSH_FXP_OPEN", ['SSH_FXP_OPEN "/firmware/firmware-2.4.1.bin" READ'], "Encrypted: SFTP OPEN", "cmd"),
                     ("srv", 20, "SFTP SSH_FXP_HANDLE", ["handle 0x01"], "Encrypted: SFTP HANDLE", "resp")]
            for i, (who, n, title, lines, info, kind) in enumerate(steps):
                self.at(self.t + 0.01 + 0.012 * i, enc, who, n, "SSH encrypted packet: " + title, lines, "SSH " + info, kind)
            base = self.t + 0.12
            for k in range(8):
                self.at(base + 0.006 * k, enc, "cli", 30, "SFTP SSH_FXP_READ", ["SSH_FXP_READ handle 0x01 offset %d length 32768" % (32768 * k)], "Encrypted: SFTP READ offset %d" % (32768 * k), "cmd")
                self.at(base + 0.006 * k + 0.003, enc, "srv", 1400, "SFTP SSH_FXP_DATA", ["SSH_FXP_DATA 32768 bytes"], "Encrypted: SFTP DATA 32 KB (segment)", "data")
            self.at(base + 0.06, enc, "cli", 20, "SFTP SSH_FXP_CLOSE", ["SSH_FXP_CLOSE handle 0x01"], "Encrypted: SFTP CLOSE", "cmd")
            self.at(base + 0.07, c.close, "cli")
            self.by["cli"].vars["SFTP"] = "firmware-2.4.1.bin over SSH (encrypted)"
        c.connect(on_open=opened)

    def tpls(self):
        return [Tpl("FTP download", [P("f", "File", "logs-2026-11.tar.gz"), P("n", "Size (bytes)", 20000, 100, 500000)],
                    lambda s, v, send: self._dl(v, send), "Login, TYPE, PASV, RETR on a new control connection."),
                Tpl("SFTP download", [], lambda s, v, send: self._sftp(send), "The same file over SSH: one encrypted connection.")]

    def _dl(self, v, send):
        if not send:
            return Frame(self.t, 0.0001, "cli", "srv", "FTP", "preview", pdu=ftp_line("RETR %s" % v["f"], "File Transfer Protocol (command)"))
        self.ftp_session(v["f"], v["n"])
        return None

    def _sftp(self, send):
        if not send:
            return Frame(self.t, 0.0001, "cli", "srv", "SSH", "preview", pdu=ssh_pkt(40, "SFTP SSH_FXP_OPEN", ["SSH_FXP_OPEN"], 1))
        self.sftp_session()
        return None


# ===================================================================== SSH
def ssh_plain(code, title, fields):
    payload = bytes([code]) + b"".join(f[1] for f in fields)
    pad = 8 - ((len(payload) + 5) % 8)
    pad = pad + 8 if pad < 4 else pad
    b = Bld("SSH binary packet (unencrypted): %s" % title, "RFC 4253 section 6: before NEWKEYS packets are sent in clear.")
    b.u32("Packet length", 1 + len(payload) + pad, None, "")
    b.u8("Padding length", pad, None, "")
    b.u8("Message code", code, "%d %s" % (code, title), "")
    for lab, data, txt in fields:
        b.raw(lab, data, txt, "")
    b.raw("Padding", bytes(pad), "%d bytes" % pad, "")
    return b.done()


def ssh_str(s):
    d = s.encode()
    return struct.pack(">I", len(d)) + d


class SSH(IpNet):
    key, name, cat = "ssh", "SSH", "net"
    blurb = "Secure remote access"
    medium = "An engineer opens an SSH session to a switch: version exchange, key exchange, public-key login, an interactive shell and a port forward"
    faults = [("hostkey", "Switch was replaced (new host key)", "The client compares the key with known_hosts and aborts: possible man-in-the-middle."),
              ("algo", "Very old server: only diffie-hellman-group1-sha1", "No common key exchange algorithm: the client disconnects."),
              ("auth", "Public key not installed on the switch", "publickey fails, password fails three times: disconnect, 'too many authentication failures'.")]
    spec = [("Standard", "RFC 4251-4254 (architecture, transport, authentication, connection), RFC 8709 ed25519, RFC 8731 curve25519"),
            ("Transport", "TCP 22; version strings, KEXINIT algorithm negotiation, ECDH key exchange, NEWKEYS, then encrypted packets"),
            ("Authentication", "publickey (signature), password, keyboard-interactive; the host key authenticates the server (known_hosts)"),
            ("Connection", "Multiplexed channels: session (shell, exec, subsystem e.g. sftp), direct-tcpip / forwarded-tcpip port forwarding"),
            ("Ciphers", "chacha20-poly1305, aes128-gcm, aes256-ctr + hmac-sha2-256 ...")]
    frame = [["SSH binary packet", ("Packet length", 32), ("Padding length", 8), ("Payload", "n x 8"), ("Padding", "4-255 B"), ("MAC", "n x 8")]]
    about = ("SSH gives an encrypted, authenticated terminal - and tunnels - to remote machines. The first packets are in clear: version strings "
             "and the lists of algorithms each side supports. A Diffie-Hellman exchange then creates session keys; the server proves its identity "
             "with its host key, the user with a key or password, and everything afterwards, including each keystroke, is encrypted.")
    guide = ["Read the KEXINIT lists in clear: key exchange, host key, ciphers, MACs.",
             "Find NEWKEYS: every later packet is encrypted - only the length is visible.",
             "COMPOSE a command: one small packet per keystroke, echoed back, then the output.",
             "Replace the switch (new host key) and watch the client refuse to log in."]

    def setup(self):
        hosts = [("eng", "ENGINEER LAPTOP", "laptop", 40, 150, "10.10.0.20", "3c:52:82:10:00:20", "ssh client"),
                 ("swc", "CORE SWITCH (SSH)", "switch", 700, 150, "10.10.0.2", "00:1a:2b:00:00:02", "sshd, CLI")]
        self.star(hosts, sw=("sw", "MANAGEMENT VLAN", 380, 150))
        self.user = "eng"
        self.c = None
        self.ok = False
        self.n = 0
        self.port = 53000
        self.by["eng"].vars.update({"Session": "-", "Host key": "-", "Last output": "-"})
        self.at(0.1, self.connect)
        self.every(4.0, lambda: self.command("show interfaces status"), 3.0)

    def enc(self, who, n, title, lines, info, kind="data"):
        self.n += 1
        self.c.send(who, ssh_pkt(n, title, lines, self.n), info, "SSH", kind)

    def connect(self):
        self.port += 1
        self.c = self.tcp("eng", "swc", self.port, 22, "SSH")
        self.ok = False
        self.c.connect(on_open=self.kex)

    def kex(self):
        c = self.c
        for i, (who, txt) in enumerate((("swc", "SSH-2.0-CommSim_SW_7.2" if not self.fault["algo"] else "SSH-1.99-OldSwitch_2.0"), ("eng", "SSH-2.0-CommSim_Client_9.1"))):
            b = Bld("SSH protocol version exchange", "Identification string in clear.")
            b.text("Version", txt + "\r\n", "Protocol version 2.0 + software version.")
            self.at(self.t + 0.001 * i, lambda b=b, who=who, txt=txt: c.send(who, b.done(), "SSH version: %s" % txt, "SSH", "ctl"))
        ck = "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256"
        sk = "diffie-hellman-group1-sha1" if self.fault["algo"] else "curve25519-sha256,diffie-hellman-group14-sha256"
        fields = lambda kex: [("Cookie", bytes(range(16)), "16 random bytes"), ("kex_algorithms", ssh_str(kex), kex), ("server_host_key_algorithms", ssh_str("ssh-ed25519,rsa-sha2-256"), "ssh-ed25519,rsa-sha2-256"),
                              ("encryption (c->s, s->c)", ssh_str("chacha20-poly1305@openssh.com,aes128-gcm@openssh.com") * 2, "chacha20-poly1305, aes128-gcm"),
                              ("mac (c->s, s->c)", ssh_str("hmac-sha2-256") * 2, "hmac-sha2-256 (unused with AEAD)"), ("compression", ssh_str("none") * 2, "none")]
        self.at(self.t + 0.01, lambda: c.send("eng", ssh_plain(20, "SSH_MSG_KEXINIT", fields(ck)), "SSH KEXINIT (client algorithm lists)", "SSH", "ctl"))
        self.at(self.t + 0.011, lambda: c.send("swc", ssh_plain(20, "SSH_MSG_KEXINIT", fields(sk)), "SSH KEXINIT (server algorithm lists)", "SSH", "ctl"))
        if self.fault["algo"]:
            self.at(self.t + 0.013, lambda: c.send("eng", ssh_plain(1, "SSH_MSG_DISCONNECT", [("Reason", struct.pack(">I", 3), "3 key exchange failed"),
                                                                                            ("Description", ssh_str("no matching key exchange method found"), "")]),
                                                   "SSH DISCONNECT: no matching key exchange method found", "SSH", "err"))
            self.at(self.t + 0.014, c.close, "eng")
            self.by["eng"].vars["Session"] = "FAILED: no matching kex (server offers only diffie-hellman-group1-sha1)"
            return
        self.at(self.t + 0.02, lambda: c.send("eng", ssh_plain(30, "SSH_MSG_KEX_ECDH_INIT", [("Q_C (client ephemeral public key)", ssh_str("x" * 32), "32-byte x25519 key")]),
                                              "SSH KEX_ECDH_INIT (curve25519)", "SSH", "ctl"))
        hk = "SHA256:Zx8f3Q2nR+1aV0w7cT9kS4mLp6yB5uJd2hG1eN0oKqA" if not self.fault["hostkey"] else "SHA256:7Lr0Qm4bWn9cX2vY5tP1sK8dF3gH6jA0zE2uI9oN4wB"
        self.at(self.t + 0.022, lambda: c.send("swc", ssh_plain(31, "SSH_MSG_KEX_ECDH_REPLY", [("K_S (host key)", ssh_str("ssh-ed25519 AAAAC3Nza..."), "ssh-ed25519 " + hk),
                                                                                              ("Q_S (server ephemeral key)", ssh_str("y" * 32), "32 bytes"),
                                                                                              ("Signature of the exchange hash", ssh_str("s" * 64), "ed25519 signature")]),
                                                "SSH KEX_ECDH_REPLY: host key %s..." % hk[:20], "SSH", "resp"))
        self.by["eng"].vars["Host key"] = hk[:30] + "..."
        if self.fault["hostkey"]:
            self.at(self.t + 0.024, c.close, "eng")
            self.by["eng"].vars["Session"] = "ABORTED: REMOTE HOST IDENTIFICATION HAS CHANGED (known_hosts mismatch)"
            self.log("Client: host key does not match known_hosts - refusing to continue (possible man-in-the-middle)")
            return
        self.at(self.t + 0.024, lambda: c.send("eng", ssh_plain(21, "SSH_MSG_NEWKEYS", []), "SSH NEWKEYS (from here on: encrypted)", "SSH", "ctl"))
        self.at(self.t + 0.025, lambda: c.send("swc", ssh_plain(21, "SSH_MSG_NEWKEYS", []), "SSH NEWKEYS", "SSH", "ctl"))
        self.at(self.t + 0.03, self.enc, "eng", 20, "SERVICE_REQUEST", ['SSH_MSG_SERVICE_REQUEST "ssh-userauth"'], "SSH encrypted: SERVICE_REQUEST ssh-userauth", "cmd")
        self.at(self.t + 0.032, self.enc, "swc", 20, "SERVICE_ACCEPT", ["SSH_MSG_SERVICE_ACCEPT"], "SSH encrypted: SERVICE_ACCEPT", "resp")
        self.at(self.t + 0.035, self.login)

    def login(self, tries=0):
        if not self.fault["auth"]:
            self.enc("eng", 300, "USERAUTH_REQUEST", ["user engineer, service ssh-connection, method publickey ssh-ed25519, with signature"], "SSH encrypted: USERAUTH_REQUEST publickey", "cmd")
            self.at(self.t + 0.004, self.enc, "swc", 12, "USERAUTH_SUCCESS", ["SSH_MSG_USERAUTH_SUCCESS"], "SSH encrypted: USERAUTH_SUCCESS", "resp")
            self.at(self.t + 0.01, self.shell)
            return
        if tries == 0:
            self.enc("eng", 300, "USERAUTH_REQUEST", ["publickey ssh-ed25519"], "SSH encrypted: USERAUTH_REQUEST publickey", "cmd")
            self.at(self.t + 0.004, self.enc, "swc", 40, "USERAUTH_FAILURE", ["SSH_MSG_USERAUTH_FAILURE: can continue: publickey,password"], "SSH encrypted: USERAUTH_FAILURE", "err")
            self.at(self.t + 1.0, self.login, 1)
        elif tries <= 3:
            self.enc("eng", 60, "USERAUTH_REQUEST", ["method password (typed by the user, encrypted on the wire)"], "SSH encrypted: USERAUTH_REQUEST password (try %d)" % tries, "cmd")
            self.at(self.t + 0.8, self.enc, "swc", 40, "USERAUTH_FAILURE", ["SSH_MSG_USERAUTH_FAILURE"], "SSH encrypted: USERAUTH_FAILURE (delayed 0.8 s against guessing)", "err")
            self.at(self.t + 1.6, self.login, tries + 1)
        else:
            self.enc("swc", 60, "DISCONNECT", ["SSH_MSG_DISCONNECT: too many authentication failures"], "SSH encrypted: DISCONNECT too many authentication failures", "err")
            self.at(self.t + 0.002, self.c.close, "swc")
            self.by["eng"].vars["Session"] = "Permission denied (publickey,password)"

    def shell(self):
        self.enc("eng", 40, "CHANNEL_OPEN", ['SSH_MSG_CHANNEL_OPEN "session" channel 0, window 2 MB'], "SSH encrypted: CHANNEL_OPEN session", "cmd")
        self.at(self.t + 0.003, self.enc, "swc", 30, "CHANNEL_OPEN_CONFIRMATION", ["channel 0 -> 3"], "SSH encrypted: CHANNEL_OPEN_CONFIRMATION", "resp")
        self.at(self.t + 0.005, self.enc, "eng", 60, "CHANNEL_REQUEST", ['"pty-req" xterm-256color 120x40', '"shell"'], "SSH encrypted: pty-req + shell", "cmd")
        self.at(self.t + 0.008, self.enc, "swc", 200, "CHANNEL_DATA", ["CORE-SW1 login banner", "CORE-SW1#"], "SSH encrypted: CHANNEL_DATA (banner + prompt)", "data")
        self.ok = True
        self.by["eng"].vars["Session"] = "logged in: engineer@CORE-SW1 (shell)"

    def command(self, cmd, send=True):
        if not send:
            return Frame(self.t, 0.0001, "eng", "swc", "SSH", "preview", pdu=ssh_pkt(1, "CHANNEL_DATA (keystroke)", ["'%s'" % cmd[:1]], 1))
        if not self.ok or not self.c.open:
            return None
        for i, ch in enumerate(cmd + "\r"):
            self.at(self.t + 0.06 * i, self.enc, "eng", 1, "CHANNEL_DATA", ["keystroke %r" % ch], "SSH encrypted: keystroke (1 byte payload, %d bytes on the wire)" % (4 + 1 + 16 + 16 + 16), "cmd")
            self.at(self.t + 0.06 * i + 0.002, self.enc, "swc", 1, "CHANNEL_DATA", ["echo %r" % ch], "SSH encrypted: echo", "ack")
        out = {"show interfaces status": "Gi1/0/1 connected 1000 full | Gi1/0/2 notconnect | Gi1/0/3 connected 100 full",
               "show version": "CommSim OS 7.2, uptime 41 days"}.get(cmd, "%% Unknown command '%s'" % cmd)
        self.at(self.t + 0.06 * (len(cmd) + 1) + 0.01, self.enc, "swc", 420, "CHANNEL_DATA", [out[:90], "CORE-SW1#"], "SSH encrypted: command output", "data")
        self.by["eng"].vars["Last output"] = out[:60]
        return None

    def forward(self, send=True):
        if not send:
            return Frame(self.t, 0.0001, "eng", "swc", "SSH", "preview", pdu=ssh_pkt(60, "CHANNEL_OPEN direct-tcpip", ['"direct-tcpip" 10.10.5.20:443'], 1))
        if not self.ok:
            return None
        self.enc("eng", 60, "CHANNEL_OPEN", ['SSH_MSG_CHANNEL_OPEN "direct-tcpip" to 10.10.5.20:443 from 127.0.0.1:8443'], "SSH encrypted: CHANNEL_OPEN direct-tcpip (local port forward 8443 -> 10.10.5.20:443)", "cmd")
        self.at(self.t + 0.003, self.enc, "swc", 30, "CHANNEL_OPEN_CONFIRMATION", ["channel 1 -> 4"], "SSH encrypted: CHANNEL_OPEN_CONFIRMATION (tunnel ready)", "resp")
        return None

    def on_fault(self, key, on):
        if not on:
            self.at(self.t + 0.3, self.connect)

    def tpls(self):
        return [Tpl("Run a command", [P("c", "Command", "show version", opts=["show version", "show interfaces status", "reload"])], lambda s, v, send: self.command(v["c"], send),
                    "Each keystroke is an encrypted packet; the switch echoes it."),
                Tpl("Local port forward", [], lambda s, v, send: self.forward(send), "Tunnel 127.0.0.1:8443 to a web interface behind the switch."),
                Tpl("Reconnect", [], lambda s, v, send: self.connect() if send else self.command("x", False), "New TCP connection and key exchange.")]


# ==================================================================== SNMP
from .power_a import T, Tint


def oid_enc(oid):
    a = [int(x) for x in oid.split(".")]
    out = bytearray([40 * a[0] + a[1]])
    for v in a[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


MIB = {"1.3.6.1.2.1.1.1.0": "sysDescr", "1.3.6.1.2.1.1.3.0": "sysUpTime", "1.3.6.1.2.1.1.5.0": "sysName", "1.3.6.1.2.1.1.6.0": "sysLocation",
       "1.3.6.1.2.1.2.2.1.2": "ifDescr", "1.3.6.1.2.1.2.2.1.7": "ifAdminStatus", "1.3.6.1.2.1.2.2.1.8": "ifOperStatus", "1.3.6.1.2.1.2.2.1.10": "ifInOctets",
       "1.3.6.1.2.1.33.1.2.4.0": "upsEstimatedChargeRemaining", "1.3.6.1.2.1.33.1.2.3.0": "upsEstimatedMinutesRemaining", "1.3.6.1.6.3.1.1.4.1.0": "snmpTrapOID"}
PDU_T = {0xA0: "GetRequest", 0xA1: "GetNextRequest", 0xA2: "Response", 0xA3: "SetRequest", 0xA5: "GetBulkRequest", 0xA7: "SNMPv2-Trap"}


def oid_name(o):
    if o in MIB:
        return MIB[o]
    base = ".".join(o.split(".")[:-1])
    return "%s.%s" % (MIB[base], o.split(".")[-1]) if base in MIB else o


def snmp_val(v):
    if v is None:
        return T(0x05, "value", b"", "NULL", "")
    if isinstance(v, tuple):
        tag, x = v
        names = {0x43: "TimeTicks", 0x41: "Counter32", 0x42: "Gauge32", 0x80: "noSuchObject", 0x06: "OBJECT IDENTIFIER"}
        if tag == 0x80:
            return T(0x80, "value", b"", "noSuchObject", "The agent does not implement this object.")
        if tag == 0x06:
            return T(0x06, "value", oid_enc(x), "%s (%s)" % (x, oid_name(x)), "")
        raw = int(x).to_bytes(max(1, (int(x).bit_length() + 8) // 8), "big")
        txt = "%d" % x if tag != 0x43 else "%d (%s)" % (x, "%dd %02d:%02d:%02d" % (x // 8640000, x // 360000 % 24, x // 6000 % 60, x // 100 % 60))
        return T(tag, "value (%s)" % names.get(tag, "0x%02X" % tag), raw, txt, "")
    if isinstance(v, int):
        return Tint(0x02, "value (INTEGER)", v)
    return T(0x04, "value (OCTET STRING)", v.encode(), '"%s"' % v, "")


def snmp_msg(community, ptype, rid, binds, err=0, eidx=0, nonrep=None, maxrep=None):
    vb = [T(0x30, "VarBind %s" % oid_name(o), [T(0x06, "name", oid_enc(o), "%s (%s)" % (o, oid_name(o)), "Object identifier, BER: first two arcs as 40 x a + b, then base-128."),
                                              snmp_val(v)]) for o, v in binds]
    f2 = Tint(0x02, "non-repeaters", nonrep) if ptype == 0xA5 else Tint(0x02, "error-status", err, "", "%d %s" % (err, {0: "noError", 2: "noSuchName", 5: "genErr", 17: "notWritable"}.get(err, "")))
    f3 = Tint(0x02, "max-repetitions", maxrep) if ptype == 0xA5 else Tint(0x02, "error-index", eidx)
    msg = T(0x30, "SNMP message", [Tint(0x02, "version", 1, "", "1 = SNMPv2c"), T(0x04, "community", community.encode(), '"%s"' % community, "A shared password, sent in clear (v1 / v2c)."),
                                   T(ptype, "PDU: %s" % PDU_T[ptype], [Tint(0x02, "request-id", rid), f2, f3, T(0x30, "variable-bindings", vb)])])
    b = Bld("Simple Network Management Protocol", "SNMPv2c (RFC 3416), BER-encoded ASN.1.")
    msg.put(b, 1)
    return b.done()


class SNMP(IpNet):
    key, name, cat = "snmp", "SNMP", "net"
    blurb = "Network device monitoring"
    medium = "A network monitoring system polls a switch, a router and a UPS with SNMPv2c (UDP 161) and receives traps (UDP 162)"
    faults = [("comm", "NMS configured with community 'publik'", "Agents silently drop requests with the wrong community: every poll times out."),
              ("link", "Switch port Gi1/0/3 goes down", "The switch sends a linkDown trap immediately; the next poll shows ifOperStatus = down(2)."),
              ("batt", "Mains failure: UPS on battery", "UPS trap 'on battery'; charge remaining starts to fall."),
              ("nosuch", "Dashboard polls an OID the router does not support", "The response carries noSuchObject for that variable binding.")]
    spec = [("Standards", "SNMPv1 RFC 1157, SNMPv2c RFC 1901 / 3416, SNMPv3 RFC 3411-3418 (USM authentication and privacy)"),
            ("Transport", "UDP 161 (agent), UDP 162 (traps / informs to the manager)"),
            ("Operations", "Get, GetNext (walk), GetBulk, Set, Response, SNMPv2-Trap, InformRequest, Report"),
            ("Data", "MIB objects named by OIDs, e.g. 1.3.6.1.2.1.1.3.0 sysUpTime, ifTable 1.3.6.1.2.1.2.2; types INTEGER, OCTET STRING, Counter32, Gauge32, TimeTicks"),
            ("Encoding", "ASN.1 BER: tag, length, value - nested SEQUENCEs")]
    frame = [["SNMP message", ("SEQUENCE", 16), ("version", 24), ("community", "n x 8"), ("PDU tag", 8), ("request-id", 24), ("error-status", 24), ("error-index", 24), ("varbinds", "n x 8")]]
    about = ("SNMP is how network equipment is monitored: every switch, router, printer and UPS runs an agent that exposes counters and status "
             "as a tree of numbered objects (the MIB). The manager polls them with Get requests and the agent can send unsolicited traps when "
             "something happens. Versions 1 and 2c protect access only with a clear-text 'community' string; SNMPv3 adds real security.")
    guide = ["Select a GetRequest: walk the BER tree - SEQUENCE, version, community, PDU, varbinds.",
             "Decode an OID by hand: 1.3.6.1.2.1.1.3.0 starts with 0x2B (= 40 x 1 + 3).",
             "Pull the switch port (fault): the linkDown trap arrives before the next poll.",
             "COMPOSE a GetNext walk of ifDescr."]

    def setup(self):
        hosts = [("nms", "MONITORING SYSTEM", "server", 40, 40, "10.0.0.5", "00:50:56:00:00:05", "SNMP manager"),
                 ("swa", "ACCESS SWITCH", "switch", 700, 40, "10.0.0.11", "00:1a:2b:00:00:11", "agent"),
                 ("rtr", "EDGE ROUTER", "router", 700, 290, "10.0.0.1", "00:1a:2b:00:00:01", "agent"),
                 ("ups", "UPS 3 kVA", "battery", 40, 290, "10.0.0.20", "00:20:85:00:00:20", "agent (UPS-MIB)")]
        self.star(hosts, sw=("sw", "MANAGEMENT SWITCH", 380, 160))
        self.user = "nms"
        self.rid = 7000
        self.oct = 1_234_567_890
        self.charge = 100
        self.by["nms"].vars.update({"Switch uplink": "-", "Router uptime": "-", "UPS charge": "-", "Timeouts": 0, "Traps": 0})
        self.every(3.0, self.poll, 1.0)
        self.every(1.0, self.physics, 0.5)

    def agent(self, k, o):
        up = int((41 * 86400 + self.t) * 100)
        if o == "1.3.6.1.2.1.1.3.0":
            return (0x43, up)
        if o == "1.3.6.1.2.1.1.1.0":
            return {"swa": "CommSim Switch 48P, OS 7.2", "rtr": "CommSim Edge Router ER-2", "ups": "CommSim UPS 3000 VA"}[k]
        if o == "1.3.6.1.2.1.1.5.0":
            return {"swa": "ACCESS-SW1", "rtr": "EDGE-RTR", "ups": "UPS-RACK3"}[k]
        if o.startswith("1.3.6.1.2.1.2.2.1.10."):
            return (0x41, self.oct & 0xFFFFFFFF)
        if o.startswith("1.3.6.1.2.1.2.2.1.8."):
            return 2 if (self.fault["link"] and o.endswith(".3")) else 1
        if o.startswith("1.3.6.1.2.1.2.2.1.2."):
            return "GigabitEthernet1/0/%s" % o.split(".")[-1]
        if o == "1.3.6.1.2.1.33.1.2.4.0":
            return self.charge
        if o == "1.3.6.1.2.1.33.1.2.3.0":
            return (0x42, int(self.charge * 0.45))
        return (0x80, 0)

    def get(self, k, oids, ptype=0xA0, send=True, maxrep=None):
        self.rid += 1
        comm = "publik" if self.fault["comm"] else "public"
        binds = [(o, None) for o in oids]
        req = snmp_msg(comm, ptype, self.rid, binds, nonrep=0, maxrep=maxrep)
        if not send:
            return Frame(self.t, 0.0001, "nms", k, "SNMP", "preview", pdu=udp_pdu(50161, 161, req, "10.0.0.5", self.lan.ip[k]))
        self.lan.udp("nms", k, 50161, 161, req, "%s %s request-id %d" % (PDU_T[ptype], ", ".join(oid_name(o) for o in oids), self.rid), "SNMP", "cmd", names={161: "snmp"})
        if self.fault["comm"]:
            self.by["nms"].vars["Timeouts"] += 1
            return None
        rid = self.rid
        out = []
        for o in oids:
            if ptype == 0xA1:
                parts = o.split(".")
                nxt = ".".join(parts[:-1] + [str(int(parts[-1]) + 1)]) if parts[-1].isdigit() and len(parts) > 10 else o + ".1"
                out.append((nxt, self.agent(k, nxt)))
            elif ptype == 0xA5:
                for i in range(1, (maxrep or 4) + 1):
                    oo = "%s.%d" % (o, i)
                    out.append((oo, self.agent(k, oo)))
            else:
                out.append((o, self.agent(k, o)))
        rsp = snmp_msg("public", 0xA2, rid, out)
        txt = ", ".join("%s = %s" % (oid_name(o), "noSuchObject" if isinstance(v, tuple) and v[0] == 0x80 else (v[1] if isinstance(v, tuple) else v)) for o, v in out)
        self.at(self.t + 0.002, lambda: self.lan.udp(k, "nms", 161, 50161, rsp, "Response request-id %d: %s" % (rid, txt[:100]), "SNMP", "resp", names={161: "snmp"}))
        return out

    def poll(self):
        r = self.get("swa", ["1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.2.2.1.10.1", "1.3.6.1.2.1.2.2.1.8.3"])
        if r:
            self.by["nms"].vars["Switch uplink"] = "%.1f Mbit/s, Gi1/0/3 %s" % (8 * 2_500_000 / 1e6, "DOWN" if r[2][1] == 2 else "up")
        self.at(self.t + 0.3, self._poll2)

    def _poll2(self):
        oids = ["1.3.6.1.2.1.1.3.0"] + (["1.3.6.1.4.1.99999.1.7.0"] if self.fault["nosuch"] else [])
        r = self.get("rtr", oids)
        if r:
            self.by["nms"].vars["Router uptime"] = "41 days"
        r = self.get("ups", ["1.3.6.1.2.1.33.1.2.4.0", "1.3.6.1.2.1.33.1.2.3.0"])
        if r:
            self.by["nms"].vars["UPS charge"] = "%d %%, %d min left" % (self.charge, int(self.charge * 0.45))

    def physics(self):
        self.oct += 2_500_000
        if self.fault["batt"]:
            self.charge = max(0, self.charge - 1)

    def trap(self, k, trap_oid, binds, what):
        up = int((41 * 86400 + self.t) * 100)
        m = snmp_msg("public", 0xA7, int(self.rng.integers(1, 2 ** 30)), [("1.3.6.1.2.1.1.3.0", (0x43, up)), ("1.3.6.1.6.3.1.1.4.1.0", (0x06, trap_oid))] + binds)
        self.lan.udp(k, "nms", 162, 162, m, "SNMPv2-Trap from %s: %s" % (self.by[k].label, what), "SNMP", "err", names={162: "snmptrap"})
        self.by["nms"].vars["Traps"] += 1

    def on_fault(self, key, on):
        if key == "link":
            self.trap("swa", "1.3.6.1.6.3.1.1.5.%d" % (3 if on else 4), [("1.3.6.1.2.1.2.2.1.1.3", 3), ("1.3.6.1.2.1.2.2.1.7.3", 1), ("1.3.6.1.2.1.2.2.1.8.3", 2 if on else 1)],
                      "%s Gi1/0/3 (ifIndex 3)" % ("linkDown" if on else "linkUp"))
        if key == "batt":
            self.trap("ups", "1.3.6.1.2.1.33.2.%d" % (1 if on else 2), [("1.3.6.1.2.1.33.1.2.3.0", (0x42, 45))], "upsTrapOnBattery" if on else "upsTraps: on mains again")
            if not on:
                self.charge = 100

    def tpls(self):
        ag = lambda v: self.by[v].label
        return [Tpl("Get", [P("k", "Agent", "swa", opts=["swa", "rtr", "ups"], fmt=ag),
                            P("o", "OID", "1.3.6.1.2.1.1.1.0", opts=["1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.33.1.2.4.0", "1.3.6.1.2.1.2.2.1.8.3"],
                              fmt=lambda v: "%s %s" % (v, oid_name(v)))], lambda s, v, send: self.get(v["k"], [v["o"]], 0xA0, send), "GetRequest for one object."),
                Tpl("GetNext (walk step)", [P("k", "Agent", "swa", opts=["swa", "rtr"], fmt=ag), P("o", "Start OID", "1.3.6.1.2.1.2.2.1.2", opts=["1.3.6.1.2.1.2.2.1.2", "1.3.6.1.2.1.2.2.1.2.1"])],
                    lambda s, v, send: self.get(v["k"], [v["o"]], 0xA1, send), "The agent returns the next object in the tree."),
                Tpl("GetBulk ifDescr", [P("k", "Agent", "swa", opts=["swa", "rtr"], fmt=ag), P("n", "max-repetitions", 6, 1, 24)],
                    lambda s, v, send: self.get(v["k"], ["1.3.6.1.2.1.2.2.1.2"], 0xA5, send, v["n"]), "One request returns many rows.")]


# ============================================================== MQTT (IoT)
from .industrial_c import mqtt_pkt, mq_connect, mq_publish, mstr


class MQTT(IpNet):
    key, name, cat = "mqtt", "MQTT", "net"
    blurb = "IoT messaging"
    medium = "Smart home on MQTT 3.1.1: sensors publish to a broker, a phone app subscribes with wildcards, retained values, last will, QoS 0 / 1 / 2"
    faults = [("auth", "Phone app has a wrong password", "CONNACK return code 5 (not authorized): no subscriptions, no data."),
              ("dupid", "Two devices use client ID 'plug-1'", "The broker drops the older session each time the other connects: a reconnect fight."),
              ("plug", "Smart plug loses power", "No PINGREQ within 1.5 x keep-alive: the broker publishes the plug's last will 'offline' (retained)."),
              ("stale", "Door sensor's retained message is a week old", "A new subscriber immediately gets 'open' - retained data can be stale.")]
    spec = [("Standard", "OASIS MQTT 3.1.1 / 5.0, ISO/IEC 20922; TCP 1883, TLS 8883, WebSocket 8083/443"),
            ("Model", "Publish / subscribe through a broker; topics are '/'-separated levels; filters with + (one level) and # (all below)"),
            ("QoS", "0 at most once, 1 at least once (PUBACK), 2 exactly once (PUBREC, PUBREL, PUBCOMP)"),
            ("Retained", "The broker keeps the last retained message per topic and hands it to every new subscriber"),
            ("Session", "Keep-alive with PINGREQ / PINGRESP; last will and testament published if the client vanishes; persistent sessions queue QoS 1/2")]
    frame = [["Fixed header", ("Type", 4), ("Flags (DUP QoS RETAIN)", 4), ("Remaining length", "1-4 x 8")], ["PUBLISH", ("Topic length", 16), ("Topic", "n x 8"), ("[Packet ID]", 16), ("Payload", "n x 8")]]
    about = ("MQTT is the lightweight messaging protocol of the IoT: devices keep a TCP connection to a broker, publish small messages to topics "
             "like home/kitchen/temperature, and subscribe to the topics they care about - with wildcards. The broker remembers retained values, "
             "detects dead clients through keep-alives and announces them with a pre-registered 'last will'.")
    guide = ["Find the phone's SUBSCRIBE with filters home/+/temperature and home/door/#, and the SUBACK granted QoS.",
             "See the retained values delivered right after subscribing (RETAIN flag set).",
             "COMPOSE 'plug ON' from the phone with QoS 2: PUBLISH, PUBREC, PUBREL, PUBCOMP.",
             "Unplug the smart plug: after the keep-alive timeout the broker publishes its last will."]

    def setup(self):
        hosts = [("brk", "MQTT BROKER", "broker", 380, 300, "192.168.1.5", "dc:a6:32:00:00:05", "home server"),
                 ("t1", "LIVING ROOM SENSOR", "temp", 40, 40, "192.168.1.31", "24:0a:c4:00:00:31", "home/livingroom"),
                 ("t2", "BEDROOM SENSOR", "temp", 250, 40, "192.168.1.32", "24:0a:c4:00:00:32", "home/bedroom"),
                 ("door", "DOOR SENSOR", "sensor", 520, 40, "192.168.1.33", "24:0a:c4:00:00:33", "home/door"),
                 ("plug", "SMART PLUG", "box", 740, 40, "192.168.1.34", "24:0a:c4:00:00:34", "home/plug"),
                 ("ph", "PHONE APP", "phone", 740, 300, "192.168.1.40", "a4:77:33:00:00:40", "subscriber")]
        self.star(hosts, sw=("sw", "WI-FI ACCESS POINT", 380, 160))
        self.user = "ph"
        self.c = {}
        self.pid = 0
        self.retained = {"home/door/state": ("closed", 1)}
        self.plug_on = False
        self.by["ph"].vars.update({"Connection": "-", "Living room": "-", "Bedroom": "-", "Door": "-", "Plug": "-"})
        self.by["brk"].vars.update({"Clients": 0, "Retained topics": 1})
        port = 49200
        for i, k in enumerate(("t1", "t2", "door", "plug", "ph")):
            self.at(0.05 + 0.15 * i, self.connect, k, port + i)
        self.every(5.0, self.sensor, 2.0, 0.0, "t1", 21.5)
        self.every(5.0, self.sensor, 2.6, 0.0, "t2", 19.0)
        self.every(11.0, self.door, 4.0)
        self.every(10.0, self.keepalive, 9.0)
        self.every(2.5, self.plug_ping, 2.5)

    def cid(self, k):
        return {"t1": "sensor-lr", "t2": "sensor-br", "door": "door-1", "plug": "plug-1", "ph": "phone-app"}[k]

    def connect(self, k, port):
        c = self.tcp(k, "brk", port, 1883, "MQTT")
        self.c[k] = c

        def opened():
            will = ("home/plug/status", b"offline") if k == "plug" else None
            user = ("phone", "wr0ng" if (self.fault["auth"] and k == "ph") else "s3cret") if k == "ph" else None
            ka = 3 if k == "plug" else 30
            c.send(k, mq_connect(self.cid(k), ka, will, user), "CONNECT client-id %s, keep-alive %d s%s%s" % (self.cid(k), ka, ", will home/plug/status" if will else "",
                                                                                                        ", user + password" if user else ""), "MQTT", "ctl")
            rc = 5 if (k == "ph" and self.fault["auth"]) else 0
            ca = mqtt_pkt(2, 0, bytes([0, rc]), b"", [("Session present", 1, "0", ""), ("Return code", 1, "%d %s" % (rc, {0: "accepted", 5: "not authorized"}[rc]), "")])
            self.at(self.t + 0.002, lambda: c.send("brk", ca, "CONNACK return code %d (%s)" % (rc, "accepted" if rc == 0 else "NOT AUTHORIZED"), "MQTT", "resp" if rc == 0 else "err"))
            if rc:
                self.by["ph"].vars["Connection"] = "refused: not authorized"
                self.at(self.t + 0.003, c.close, "brk")
                return
            self.by["brk"].vars["Clients"] = sum(1 for x in self.c.values() if x.open)
            if k == "ph":
                self.by["ph"].vars["Connection"] = "connected"
                self.at(self.t + 0.01, self.subscribe)
            if k == "plug":
                self.at(self.t + 0.01, self.publish, "plug", "home/plug/status", "online", 1, True)
                self.at(self.t + 0.02, self.sub_plug)
        c.connect(on_open=opened)

    def publish(self, k, topic, payload, qos=0, retain=False, send=True):
        self.pid = (self.pid % 65535) + 1
        p = mq_publish(topic, payload.encode(), qos, self.pid if qos else None, retain)
        if not send:
            return Frame(self.t, 0.0001, k, "brk", "MQTT", "preview", pdu=p)
        c = self.c.get(k)
        if not c or not c.open:
            return None
        pid = self.pid
        c.send(k, p, "PUBLISH %s = %s (QoS %d%s)" % (topic, payload, qos, ", retain" if retain else ""), "MQTT", "data")
        if qos == 1:
            self.at(self.t + 0.002, lambda: c.send("brk", mqtt_pkt(4, 0, struct.pack(">H", pid), b"", [("Packet identifier", 2, str(pid), "")]), "PUBACK %d" % pid, "MQTT", "ack"))
        elif qos == 2:
            self.at(self.t + 0.002, lambda: c.send("brk", mqtt_pkt(5, 0, struct.pack(">H", pid), b"", [("Packet identifier", 2, str(pid), "")]), "PUBREC %d (step 1 of exactly-once)" % pid, "MQTT", "ack"))
            self.at(self.t + 0.004, lambda: c.send(k, mqtt_pkt(6, 2, struct.pack(">H", pid), b"", [("Packet identifier", 2, str(pid), "")]), "PUBREL %d" % pid, "MQTT", "ctl"))
            self.at(self.t + 0.006, lambda: c.send("brk", mqtt_pkt(7, 0, struct.pack(">H", pid), b"", [("Packet identifier", 2, str(pid), "")]), "PUBCOMP %d (delivered once)" % pid, "MQTT", "ack"))
        if retain:
            self.retained[topic] = (payload, qos)
            self.by["brk"].vars["Retained topics"] = len(self.retained)
        self.at(self.t + 0.003 + (0.004 if qos == 2 else 0), self.route, topic, payload, qos)
        return None

    def route(self, topic, payload, qos, retained=False):
        subs = {"ph": ["home/+/temperature", "home/door/#", "home/plug/status"], "plug": ["home/plug/set"]}
        for k, filters in subs.items():
            c = self.c.get(k)
            if not c or not c.open or not getattr(self, "subbed_" + k, False):
                continue
            if any(self.match(f, topic) for f in filters):
                q = min(qos, 1)
                self.pid = (self.pid % 65535) + 1
                c.send("brk", mq_publish(topic, payload.encode(), q, self.pid if q else None, retained), "PUBLISH %s = %s to %s%s" % (topic, payload, self.cid(k),
                                                                                                                                          " (retained copy)" if retained else ""), "MQTT", "data")
                if k == "ph":
                    v = self.by["ph"].vars
                    if "temperature" in topic:
                        v["Living room" if "living" in topic else "Bedroom"] = payload + " degC"
                    elif "door" in topic:
                        v["Door"] = payload + (" (stale retained!)" if retained and self.fault["stale"] else "")
                    elif "plug" in topic:
                        v["Plug"] = payload
                if k == "plug" and topic == "home/plug/set":
                    self.plug_on = payload == "ON"
                    self.at(self.t + 0.05, self.publish, "plug", "home/plug/state", payload, 0, True)

    @staticmethod
    def match(f, t):
        fp, tp = f.split("/"), t.split("/")
        for i, x in enumerate(fp):
            if x == "#":
                return True
            if i >= len(tp) or (x != "+" and x != tp[i]):
                return False
        return len(fp) == len(tp)

    def subscribe(self):
        c = self.c["ph"]
        self.pid += 1
        filters = [("home/+/temperature", 0), ("home/door/#", 1), ("home/plug/status", 1)]
        var = struct.pack(">H", self.pid)
        pl = b"".join(mstr(f) + bytes([q]) for f, q in filters)
        rows = [("Packet identifier", 2, str(self.pid), "")] + [("Topic filter + options", 3 + len(f), "%s, max QoS %d" % (f, q), "+ matches one level, # everything below") for f, q in filters]
        c.send("ph", mqtt_pkt(8, 2, var, pl, rows), "SUBSCRIBE home/+/temperature, home/door/#, home/plug/status", "MQTT", "cmd")
        sa = mqtt_pkt(9, 0, var, bytes([0, 1, 1]), [("Packet identifier", 2, str(self.pid), ""), ("Return codes", 3, "0, 1, 1 (granted QoS)", "0x80 would mean failure")])
        self.at(self.t + 0.002, lambda: c.send("brk", sa, "SUBACK granted QoS 0, 1, 1", "MQTT", "resp"))
        self.subbed_ph = True
        for topic, (payload, qos) in list(self.retained.items()):
            if any(self.match(f, topic) for f, _ in filters):
                if topic == "home/door/state" and self.fault["stale"]:
                    payload = "open"
                self.at(self.t + 0.004, self.route, topic, payload, qos, True)

    def sub_plug(self):
        c = self.c["plug"]
        self.pid += 1
        var = struct.pack(">H", self.pid)
        c.send("plug", mqtt_pkt(8, 2, var, mstr("home/plug/set") + b"\x02", [("Packet identifier", 2, str(self.pid), ""), ("Topic filter + options", 16, "home/plug/set, max QoS 2", "")]),
               "SUBSCRIBE home/plug/set (QoS 2)", "MQTT", "cmd")
        self.at(self.t + 0.002, lambda: c.send("brk", mqtt_pkt(9, 0, var, b"\x02", [("Packet identifier", 2, str(self.pid), ""), ("Return code", 1, "2", "")]), "SUBACK QoS 2", "MQTT", "resp"))
        self.subbed_plug = True

    def sensor(self, k, base):
        v = base + 0.6 * math.sin(self.t / 9 + (1 if k == "t2" else 0)) + float(self.rng.normal(0, 0.05))
        room = "livingroom" if k == "t1" else "bedroom"
        self.publish(k, "home/%s/temperature" % room, "%.1f" % v, 0, True)

    def door(self):
        st = "open" if int(self.t / 11) % 2 else "closed"
        self.publish("door", "home/door/state", st, 1, True)

    def keepalive(self):
        for k, c in self.c.items():
            if not c.open or k == "plug":
                continue
            c.send(k, mqtt_pkt(12), "PINGREQ (keep-alive)", "MQTT", "ctl")
            self.at(self.t + 0.002, lambda c=c: c.send("brk", mqtt_pkt(13), "PINGRESP", "MQTT", "ack"))

    def plug_ping(self):
        c = self.c.get("plug")
        if not c or not c.open or self.fault["plug"]:
            return
        c.send("plug", mqtt_pkt(12), "PINGREQ (plug keep-alive 3 s)", "MQTT", "ctl")
        self.at(self.t + 0.002, lambda: c.send("brk", mqtt_pkt(13), "PINGRESP", "MQTT", "ack"))

    def on_fault(self, key, on):
        if key == "plug" and on:
            self.at(self.t + 4.5, self.will)
        if key == "plug" and not on:
            self.at(self.t + 0.5, self.connect, "plug", 49300 + int(self.t) % 100)
        if key == "dupid" and on:
            self.at(self.t + 0.5, self.dup_fight)
        if key == "auth" and not on:
            c = self.c.get("ph")
            if not c or not c.open:
                self.at(self.t + 0.5, self.connect, "ph", 49400 + int(self.t) % 100)

    def will(self):
        c = self.c.get("plug")
        if c:
            c.open = False
        self.log("Broker: no packet from plug-1 within 1.5 x keep-alive - publishing its last will")
        self.retained["home/plug/status"] = ("offline", 1)
        self.route("home/plug/status", "offline", 1)

    def dup_fight(self):
        if not self.fault["dupid"]:
            return
        self.log("Broker: new connection with client ID plug-1 - disconnecting the existing session")
        old = self.c.get("plug")
        if old and old.open:
            old.close("brk")
        self.at(self.t + 0.3, self.connect, "plug", 49500 + int(self.t * 10) % 400)
        self.at(self.t + 2.0, self.dup_fight)

    def tpls(self):
        return [Tpl("Phone: switch the plug", [P("v", "Command", "ON", opts=["ON", "OFF"]), P("q", "QoS", 2, opts=[0, 1, 2])],
                    lambda s, v, send: self.publish("ph", "home/plug/set", v["v"], v["q"], False, send), "PUBLISH home/plug/set; the broker forwards it to the plug's subscription."),
                Tpl("Publish any topic", [P("k", "From", "t1", opts=["t1", "t2", "door", "plug", "ph"], fmt=lambda v: self.by[v].label), P("tp", "Topic", "home/garage/temperature"),
                                          P("pl", "Payload", "12.5"), P("q", "QoS", 0, opts=[0, 1, 2]), P("r", "Retain", "no", opts=["no", "yes"])],
                    lambda s, v, send: self.publish(v["k"], v["tp"], v["pl"], v["q"], v["r"] == "yes", send), "Does home/+/temperature match your topic?")]


# ==================================================================== CoAP
COAP_T = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}
COAP_C = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE", 65: "2.01 Created", 68: "2.04 Changed", 69: "2.05 Content", 132: "4.04 Not Found", 160: "5.00 Internal Server Error", 0: "Empty"}
COAP_O = {3: "Uri-Host", 6: "Observe", 11: "Uri-Path", 12: "Content-Format", 14: "Max-Age", 17: "Accept", 23: "Block2", 60: "Size1"}


def coap_msg(mtype, code, mid, token=b"", opts=(), payload=b""):
    b = Bld("Constrained Application Protocol: %s %s" % (COAP_T[mtype], COAP_C.get(code, "%d.%02d" % (code >> 5, code & 31))),
            "RFC 7252: 4-byte header, token, delta-encoded options, 0xFF, payload.")
    b.u8("Ver | Type | TKL", 0x40 | (mtype << 4) | len(token), "version 1, %s, token length %d" % (COAP_T[mtype], len(token)), "CON needs an ACK; NON does not; RST rejects.")
    b.u8("Code", code, "%d.%02d %s" % (code >> 5, code & 31, COAP_C.get(code, "")), "Class.detail: 0.xx request method, 2.xx success, 4.xx client error, 5.xx server error.")
    b.u16("Message ID", mid, None, "Detects duplicates and pairs ACK / RST with CON.")
    if token:
        b.raw("Token", token, token.hex(), "Pairs responses (and notifications) with the request.")
    last = 0
    for num, val in sorted(opts, key=lambda o: o[0]):
        d = num - last
        last = num
        vb = val if isinstance(val, bytes) else (val.encode() if isinstance(val, str) else (int(val).to_bytes(max(0, (int(val).bit_length() + 7) // 8), "big")))
        hdr = bytes([((d if d < 13 else 13) << 4) | (len(vb) if len(vb) < 13 else 13)]) + (bytes([d - 13]) if d >= 13 else b"") + (bytes([len(vb) - 13]) if len(vb) >= 13 else b"")
        txt = val if isinstance(val, str) else ("%d" % val if isinstance(val, int) else val.hex())
        if num == 23 and isinstance(val, int):
            txt = "block %d, more %d, size %d" % (val >> 4, (val >> 3) & 1, 2 ** ((val & 7) + 4))
        if num == 12:
            txt = {0: "0 text/plain", 50: "50 application/json", 40: "40 application/link-format", 60: "60 application/cbor"}.get(val, str(val))
        b.raw("Option %s (%d)" % (COAP_O.get(num, "?"), num), hdr + vb, txt, "Delta %d from the previous option number, length %d." % (d, len(vb)))
    if payload:
        b.u8("Payload marker", 0xFF, "0xFF", "")
        b.raw("Payload", payload, payload.decode("latin-1")[:80], "")
    return b.done()


class CoAP(IpNet):
    key, name, cat = "coap", "CoAP", "net"
    blurb = "Constrained IoT devices"
    medium = "CoAP over UDP/IPv6: a gateway discovers resources on battery-powered nodes, observes a temperature, switches an LED and pulls a firmware block by block"
    faults = [("loss", "Lossy radio link (30 % loss)", "CON messages are retransmitted after ACK_TIMEOUT (2-3 s) with exponential back-off."),
              ("404", "Gateway uses an old resource path", "The node answers 4.04 Not Found."),
              ("reboot", "Gateway rebooted and forgot its observations", "It answers the next confirmable notification with RST: the node removes the observer.")]
    spec = [("Standard", "RFC 7252 (CoAP), RFC 7641 (Observe), RFC 7959 (block-wise), RFC 6690 (CoRE link format), RFC 8613 OSCORE; UDP 5683, DTLS 5684"),
            ("Messages", "CON (acknowledged), NON, ACK, RST; 16-bit message ID; token pairs requests and responses"),
            ("Methods", "GET, POST, PUT, DELETE (like HTTP) with response codes 2.05 Content, 2.04 Changed, 4.04 Not Found ..."),
            ("Options", "Delta-encoded: Uri-Path, Content-Format, Observe, Block2, Max-Age ..."),
            ("Reliability", "ACK_TIMEOUT 2 s x random(1..1.5), doubling, MAX_RETRANSMIT 4")]
    frame = [["CoAP message", ("Ver", 2), ("T", 2), ("TKL", 4), ("Code", 8), ("Message ID", 16), ("Token", "0-8 B"), ("Options", "n x 8"), ("0xFF", 8), ("Payload", "n x 8")]]
    about = ("CoAP is HTTP made small for sensors on low-power radios: a 4-byte binary header over UDP, the same REST methods and status codes, "
             "and built-in reliability for confirmable messages. A client can 'observe' a resource and receive a notification whenever it "
             "changes, and large bodies such as firmware are moved block by block.")
    guide = ["Read the /.well-known/core reply: the node's resources in link format.",
             "Follow the Observe registration and the notifications that share its token.",
             "Turn on loss: retransmissions of a CON request with the same message ID, at growing intervals.",
             "COMPOSE a block-wise GET of the firmware: Block2 option block 0, 1, 2 ..."]

    def setup(self):
        hosts = [("gw", "IOT GATEWAY (CLIENT)", "gateway", 40, 150, "2001:db8:1::1", "00:1b:21:00:00:01", "CoAP client"),
                 ("tn", "TEMPERATURE NODE", "temp", 700, 40, "2001:db8:1::a1", "00:12:4b:00:00:a1", "/sensors/temp"),
                 ("ln", "LED NODE", "lamp", 700, 290, "2001:db8:1::a2", "00:12:4b:00:00:a2", "/actuators/led")]
        self.star(hosts, sw=("sw", "6LoWPAN BORDER ROUTER", 380, 150))
        self.user = "gw"
        self.mid = 0x3A00
        self.obs = 0
        self.observing = False
        self.led = False
        self.by["gw"].vars.update({"Resources": "-", "Temperature (observed)": "-", "LED": "-", "Firmware": "-"})
        self.at(0.1, self.discover)
        self.at(0.6, self.observe)
        self.every(3.0, self.notify, 2.0)

    def send(self, src, dst, p, info, kind):
        return self.lan.udp(src, dst, 5683, 5683, p, info, "CoAP", kind, v6=True, names={5683: "coap"})

    def request(self, dst, code, path, token, opts=(), payload=b"", on_rsp=None, retry=0, mid=None):
        mid = mid or self.mid + 1
        if retry == 0:
            self.mid = mid
        p = coap_msg(0, code, mid, token, [(11, seg) for seg in path.strip("/").split("/")] + list(opts), payload)
        lost = self.fault["loss"] and self.rng.random() < 0.3
        fr = self.send("gw", dst, p, "CON %s %s mid 0x%04X%s" % (COAP_C[code], path, mid, " (retransmission %d)" % retry if retry else ""), "cmd")
        if lost:
            fr.err = "Lost on the radio link"
            if retry < 4:
                to = 2.0 * (2 ** retry) * (1 + 0.5 * float(self.rng.random()))
                self.at(self.t + to, self.request, dst, code, path, token, opts, payload, on_rsp, retry + 1, mid)
            return
        self.at(self.t + 0.03, on_rsp, mid, token) if on_rsp else None

    def ack(self, src, mid, token, code, opts=(), payload=b"", info=""):
        self.send(src, "gw", coap_msg(2, code, mid, token, opts, payload), "ACK %s mid 0x%04X %s" % (COAP_C.get(code, ""), mid, info), "resp" if code < 128 else "err")

    def discover(self):
        def rsp(mid, tok):
            lf = b'</sensors/temp>;rt="temperature-c";if="sensor";obs,</fw/image>;sz=2048,</.well-known/core>'
            self.ack("tn", mid, tok, 69, [(12, 40)], lf, "(link format)")
            self.by["gw"].vars["Resources"] = "/sensors/temp (obs), /fw/image"
        self.request("tn", 1, "/.well-known/core", b"\x11", on_rsp=rsp)

    def observe(self):
        def rsp(mid, tok):
            self.observing = True
            self.obs = 12
            self.ack("tn", mid, tok, 69, [(6, self.obs), (12, 50)], b'{"t": %.2f}' % self.temp(), "Observe %d (registered)" % self.obs)
        self.request("tn", 1, "/sensors/temp", b"\xa7\x3c", [(6, 0)], on_rsp=rsp)

    def temp(self):
        return 22.0 + 1.5 * math.sin(self.t / 8)

    def notify(self):
        if not self.observing:
            return
        self.obs += 1
        self.mid += 1
        con = self.obs % 4 == 0
        body = b'{"t": %.2f}' % self.temp()
        p = coap_msg(0 if con else 1, 69, self.mid, b"\xa7\x3c", [(6, self.obs), (12, 50)], body)
        lost = self.fault["loss"] and self.rng.random() < 0.3
        fr = self.send("tn", "gw", p, "%s notification 2.05 Observe %d: %s" % ("CON" if con else "NON", self.obs, body.decode()), "data")
        if lost:
            fr.err = "Lost on the radio link"
            return
        self.by["gw"].vars["Temperature (observed)"] = "%.2f degC (seq %d)" % (self.temp(), self.obs)
        if con:
            mid = self.mid
            if self.fault["reboot"]:
                self.at(self.t + 0.01, lambda: self.send("gw", "tn", coap_msg(3, 0, mid), "RST mid 0x%04X (unknown token: observation forgotten)" % mid, "err"))
                self.observing = False
                self.at(self.t + 0.02, lambda: self.by["gw"].vars.__setitem__("Temperature (observed)", "observer removed by the node"))
            else:
                self.at(self.t + 0.01, lambda: self.send("gw", "tn", coap_msg(2, 0, mid), "Empty ACK mid 0x%04X" % mid, "ack"))

    def led_put(self, on, send=True):
        path = "/actuators/led" if not self.fault["404"] else "/led"
        if not send:
            return Frame(self.t, 0.0001, "gw", "ln", "CoAP", "preview", pdu=coap_msg(0, 3, self.mid + 1, b"\x02", [(11, "actuators"), (11, "led"), (12, 0)], b"on" if on else b"off"))

        def rsp(mid, tok):
            if self.fault["404"]:
                self.ack("ln", mid, tok, 132, (), b"", "")
                self.by["gw"].vars["LED"] = "4.04 Not Found (%s)" % path
                return
            self.led = on
            self.ack("ln", mid, tok, 68, (), b"", "(LED %s)" % ("on" if on else "off"))
            self.by["gw"].vars["LED"] = "on" if on else "off"
        self.request("ln", 3, path, b"\x02", [(12, 0)], b"on" if on else b"off", on_rsp=rsp)
        return None

    def firmware(self, send=True, blk=0):
        if not send:
            return Frame(self.t, 0.0001, "gw", "tn", "CoAP", "preview", pdu=coap_msg(0, 1, self.mid + 1, b"\x55", [(11, "fw"), (11, "image"), (23, (blk << 4) | 2)]))

        def rsp(mid, tok):
            more = 1 if blk < 31 else 0
            self.ack("tn", mid, tok, 69, [(12, 42), (23, (blk << 4) | (more << 3) | 2)], bytes(64), "block %d (64 bytes)" % blk)
            self.by["gw"].vars["Firmware"] = "%d / 2048 bytes" % ((blk + 1) * 64)
            if more and blk < 7:
                self.at(self.t + 0.05, self.firmware, True, blk + 1)
        self.request("tn", 1, "/fw/image", b"\x55", [(23, (blk << 4) | 2)], on_rsp=rsp)
        return None

    def on_fault(self, key, on):
        if key == "reboot" and not on and not self.observing:
            self.at(self.t + 0.2, self.observe)

    def tpls(self):
        return [Tpl("PUT LED", [P("v", "State", "on", opts=["on", "off"])], lambda s, v, send: self.led_put(v["v"] == "on", send), "Confirmable PUT; the ACK carries 2.04 Changed."),
                Tpl("Block-wise firmware GET", [], lambda s, v, send: self.firmware(send), "Block2, 64-byte blocks (first 8 shown)."),
                Tpl("Discover resources", [], lambda s, v, send: self.discover() if send else Frame(self.t, 0.0001, "gw", "tn", "CoAP", "preview",
                                                                                                   pdu=coap_msg(0, 1, 1, b"\x11", [(11, ".well-known"), (11, "core")])),
                    "GET /.well-known/core")]
