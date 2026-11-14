"""Automotive and heavy equipment, part B: ISO-TP, UDS, OBD-II, Automotive
Ethernet (SOME/IP, DoIP, gPTP), ISO 9141-2, KWP2000, SAE J1850 VPW, SENT,
PSI5, MOST and ISOBUS."""
import math
import struct
from ..engine import Scenario, Bld, Wire, Frame, Tpl, P, Pdu
from ..bits import crcn, lsb, sum8
from .fam import serial_frame, IpNet
from .phys_b import CanNet
from .auto_a import j1939_id, j1939_split, j1939_idrows, j1939_dissect, PGNS

# =================================================================== ISO-TP
FS_NAMES = {0: "ContinueToSend", 1: "Wait", 2: "Overflow"}


class IsoTp:
    """ISO 15765-2 transport over a scenario's CanBus: single frame, or
    first frame + flow control + consecutive frames (block size, STmin)."""

    def __init__(self, scn, pad=0xCC):
        self.s, self.pad = scn, pad
        self.bs, self.stmin = 0, 0            # flow control announced by a receiver (default)
        self.lost_fc = self.bad_sn = self.slow_rx = self.wait_fc = False

    @staticmethod
    def pci_rows(b, off, d):
        t = d[0] >> 4
        if t == 0:
            b.rows.append([0, "ISO 15765-2 Single Frame", off, len(d), "The whole message fits in one CAN frame"])
            b.rows.append([1, "PCI 0x%02X: SF, length %d" % (d[0], d[0] & 15), off, 1, "Upper nibble 0 = single frame, lower nibble = number of data bytes (1-7)"])
        elif t == 1:
            n = ((d[0] & 15) << 8) | d[1]
            b.rows.append([0, "ISO 15765-2 First Frame", off, len(d), "First of a segmented message. The receiver must answer with a Flow Control frame."])
            b.rows.append([1, "PCI 0x%02X%02X: FF, total length %d" % (d[0], d[1], n), off, 2, "12-bit total message length (up to 4095 bytes)"])
        elif t == 2:
            b.rows.append([0, "ISO 15765-2 Consecutive Frame", off, len(d), "Seven more bytes of a segmented message"])
            b.rows.append([1, "PCI 0x%02X: CF, sequence number %d" % (d[0], d[0] & 15), off, 1, "Sequence number counts 1..15, 0, 1... so a lost frame is detected"])
        elif t == 3:
            b.rows.append([0, "ISO 15765-2 Flow Control", off, len(d), "The receiver tells the sender how to continue"])
            b.rows.append([1, "Flow status %d: %s" % (d[0] & 15, FS_NAMES.get(d[0] & 15, "?")), off, 1, "0 continue to send, 1 wait, 2 overflow (abort)"])
            if len(d) >= 3:
                b.rows.append([1, "Block size %d%s" % (d[1], " (send everything, no further flow control)" if d[1] == 0 else ""), off + 1, 1,
                               "Number of consecutive frames before the next flow control"])
                b.rows.append([1, "STmin %d ms" % d[2], off + 2, 1, "Minimum separation time between consecutive frames (0xF1-0xF9 = 100-900 us)"])

    @staticmethod
    def app_rows(b, off, d, payload, app):
        t = d[0] >> 4
        if not app or t not in (0, 1):
            return
        tmp = Bld()
        app(tmp, 0, bytes(payload))
        base = off + (1 if t == 0 else 2)
        lim = off + len(d)
        dd = 0
        if t == 1:
            b.rows.append([0, "Reassembled message: %d bytes (rest arrives in the consecutive frames)" % len(payload), None, 0,
                           "ISO-TP reassembly. Decoded here on the First Frame, like a protocol analyser does."])
            dd = 1
        for r in tmp.rows:
            o, n = r[2], max(0, r[3])
            if o is not None and base + o + n <= lim:
                b.rows.append([r[0] + dd, r[1], base + o, n, r[4]])
            else:
                b.rows.append([r[0] + dd, r[1], None, 0, r[4]])

    def send(self, frm, to, tx_id, rx_id, payload, info, kind="cmd", proto="ISO-TP", app=None, on_done=None, on_fail=None,
             ext=False, t0=None, fc=None):
        """fc = (block size, STmin ms) the receiver announces (default self.bs / self.stmin)."""
        s = self.s
        bus = s.bus
        t = s.t if t0 is None else t0
        payload = bytes(payload)
        n = len(payload)
        pad = self.pad

        def dis(b, off, d):
            self.pci_rows(b, off, d)
            self.app_rows(b, off, d, payload, app)
        if n <= 7:
            d = bytes([n]) + payload + bytes([pad] * (7 - n))
            bus.send(frm, tx_id, d, ext=ext, t=t, info=info, kind=kind, proto=proto, key="0x%X SF" % tx_id, dst=to, dissect=lambda b, o, d=d: dis(b, o, d))
            if on_done:
                s.at(t + 0.0004, on_done)
            return
        ff = bytes([0x10 | (n >> 8), n & 255]) + payload[:6]
        bus.send(frm, tx_id, ff, ext=ext, t=t, info="%s [FF %d bytes]" % (info, n), kind=kind, proto=proto, key="0x%X FF" % tx_id, dst=to,
                 dissect=lambda b, o, d=ff: dis(b, o, d))
        st = {"pos": 6, "sn": 1, "dead": False}
        name = info.split(" [")[0]
        bs, stmin = fc if fc is not None else (self.bs, self.stmin)
        lost_fc, bad_sn, slow, wait = self.lost_fc, self.bad_sn, self.slow_rx, self.wait_fc

        def fail(msg):
            s.log(msg)
            if on_fail:
                on_fail(msg)

        def flow(waited=False):
            if st["dead"]:
                s.at(s.t + 1.0, s.log, "N_Bs timeout: the receiver gave up, so no Flow Control came - sender aborts too")
                return
            if lost_fc:
                s.at(s.t + 1.0, fail, "N_Bs timeout (1000 ms): no Flow Control after the First Frame, %s aborted" % name)
                return
            if wait and not waited:
                d = bytes([0x31, 0, 0]) + bytes([pad] * 5)
                bus.send(to, rx_id, d, ext=ext, info="Flow Control WAIT (receiver busy)", kind="ctl", proto=proto, key="0x%X FC" % rx_id, dst=frm,
                         dissect=lambda b, o, d=d: self.pci_rows(b, o, d))
                s.at(s.t + 0.05, flow, True)
                return
            d = bytes([0x30, bs, stmin]) + bytes([pad] * 5)
            bus.send(to, rx_id, d, ext=ext, info="Flow Control CTS  BS=%d  STmin=%d ms" % (bs, stmin), kind="ctl", proto=proto, key="0x%X FC" % rx_id, dst=frm,
                     dissect=lambda b, o, d=d: self.pci_rows(b, o, d))
            s.at(s.t + 0.0006, cfs)

        def cfs():
            k = 0
            tt = s.t
            gap = max(stmin / 1000.0, 0.0003)
            while st["pos"] < n:
                chunk = payload[st["pos"]:st["pos"] + 7]
                sn = st["sn"] & 15
                if bad_sn and st["sn"] == 3:
                    sn = 5
                d = bytes([0x20 | sn]) + chunk + bytes([pad] * (7 - len(chunk)))
                bus.send(frm, tx_id, d, ext=ext, t=tt, info="%s [CF %d]" % (name, sn), kind=kind, proto=proto, key="0x%X CF" % tx_id, dst=to,
                         dissect=lambda b, o, d=d: self.pci_rows(b, o, d))
                if not st["dead"]:
                    if bad_sn and st["sn"] == 3:
                        st["dead"] = True
                        s.at(tt + 0.0005, fail, "N_WRONG_SN: receiver expected CF 3 and got 5, %s aborted" % name)
                    elif slow and stmin < 2 and st["sn"] == 5:
                        st["dead"] = True
                        s.at(tt + 0.0005, fail, "Receiver overrun: CF 5 lost (frames %.1f ms apart, receiver needs 2 ms), %s aborted" % (gap * 1000, name))
                st["pos"] += 7
                st["sn"] += 1
                k += 1
                tt += gap
                if bs and k >= bs and st["pos"] < n:
                    s.at(tt + 0.0003, flow)
                    return
            if not st["dead"] and on_done:
                s.at(tt + 0.0005, on_done)
        s.at(t + 0.0008, flow)


# ===================================================================== UDS
UDS_SID = {0x10: "DiagnosticSessionControl", 0x11: "ECUReset", 0x14: "ClearDiagnosticInformation", 0x19: "ReadDTCInformation", 0x22: "ReadDataByIdentifier",
           0x27: "SecurityAccess", 0x28: "CommunicationControl", 0x2E: "WriteDataByIdentifier", 0x31: "RoutineControl", 0x34: "RequestDownload", 0x36: "TransferData",
           0x37: "RequestTransferExit", 0x3E: "TesterPresent", 0x85: "ControlDTCSetting"}
SUBF = {0x10: {1: "defaultSession", 2: "programmingSession", 3: "extendedDiagnosticSession"}, 0x11: {1: "hardReset", 2: "keyOffOnReset", 3: "softReset"},
        0x19: {1: "reportNumberOfDTCByStatusMask", 2: "reportDTCByStatusMask", 0x0A: "reportSupportedDTC"}, 0x27: {1: "requestSeed", 2: "sendKey"},
        0x28: {0: "enableRxAndTx", 3: "disableRxAndTx"}, 0x31: {1: "startRoutine", 2: "stopRoutine", 3: "requestRoutineResults"}, 0x3E: {0: "zeroSubFunction"},
        0x85: {1: "on", 2: "off"}}
NRC = {0x10: "generalReject", 0x11: "serviceNotSupported", 0x12: "subFunctionNotSupported", 0x13: "incorrectMessageLengthOrInvalidFormat", 0x22: "conditionsNotCorrect",
       0x24: "requestSequenceError", 0x31: "requestOutOfRange", 0x33: "securityAccessDenied", 0x35: "invalidKey", 0x36: "exceedNumberOfAttempts",
       0x37: "requiredTimeDelayNotExpired", 0x70: "uploadDownloadNotAccepted", 0x72: "generalProgrammingFailure", 0x73: "wrongBlockSequenceCounter",
       0x78: "requestCorrectlyReceived-ResponsePending", 0x7E: "subFunctionNotSupportedInActiveSession", 0x7F: "serviceNotSupportedInActiveSession"}
DIDS = {0xF190: ("VIN", b"WVWZZZ1KZ6W612345"), 0xF18C: ("ECU serial number", b"SN0047110815"), 0xF187: ("Spare part number", b"8V0-907-115-B"),
        0xF189: ("Software version", b"SW 0712"), 0xF18A: ("System supplier", b"COMMSIM AUTOMOTIVE"), 0xF197: ("System name", b"ENGINE"),
        0x0123: ("Idle speed setpoint (rpm)", struct.pack(">H", 750))}
DTC_ST = [(0x01, "testFailed"), (0x02, "testFailedThisOperationCycle"), (0x04, "pendingDTC"), (0x08, "confirmedDTC"), (0x10, "testNotCompletedSinceLastClear"),
          (0x20, "testFailedSinceLastClear"), (0x40, "testNotCompletedThisOperationCycle"), (0x80, "warningIndicatorRequested")]
ROUTINES = {0xFF00: "eraseMemory", 0xFF01: "checkProgrammingDependencies", 0x0203: "checkProgrammingPreconditions"}


def uds_key(seed):
    """The (deliberately simple) secret of this simulated ECU."""
    return (((seed ^ 0x2F7A) * 3) + 0x1B) & 0xFFFF


def dtc_str(hi, lo):
    return "PCBU"[hi >> 6] + "%d%X%02X" % ((hi >> 4) & 3, hi & 15, lo)


def uds_dissect(b, off, msg):
    if not msg:
        return
    sid = msg[0]
    if sid == 0x7F and len(msg) >= 3:
        b.rows.append([0, "UDS Negative Response", off, len(msg), "ISO 14229-1: 0x7F + rejected service + negative response code (NRC)"])
        b.rows.append([1, "Rejected service: 0x%02X %s" % (msg[1], UDS_SID.get(msg[1], "")), off + 1, 1, ""])
        b.rows.append([1, "NRC 0x%02X: %s" % (msg[2], NRC.get(msg[2], "")), off + 2, 1, "Why the server refused. 0x78 means 'still working, the real response follows'."])
        return
    pos = bool(sid & 0x40) and (sid - 0x40) in UDS_SID
    base = sid - 0x40 if pos else sid
    b.rows.append([0, "UDS %s %s" % (UDS_SID.get(base, "service 0x%02X" % sid), "positive response" if pos else "request"), off, len(msg),
                   "ISO 14229-1 Unified Diagnostic Services. Positive response SID = request SID + 0x40."])
    b.rows.append([1, "SID 0x%02X" % sid, off, 1, ""])
    if base in SUBF and len(msg) > 1:
        sf = msg[1]
        b.rows.append([1, "Sub-function 0x%02X: %s%s" % (sf, SUBF[base].get(sf & 0x7F, ""), " (suppress positive response)" if sf & 0x80 else ""), off + 1, 1,
                       "Bit 7 = suppressPosRspMsgIndicationBit: the server stays silent if all is well"])
    if base == 0x10 and pos and len(msg) >= 6:
        b.rows.append([1, "P2 server max %d ms, P2* server max %d ms" % (msg[2] << 8 | msg[3], (msg[4] << 8 | msg[5]) * 10), off + 2, 4, "Response timing the tester must allow"])
    if base == 0x27 and len(msg) >= 4:
        b.rows.append([1, "%s: 0x%s" % ("Seed" if pos else "Key", msg[2:].hex().upper()), off + 2, len(msg) - 2,
                       "The ECU sends a random seed; the tester computes the key with the secret algorithm"])
    if base == 0x19 and pos and len(msg) > 3:
        b.rows.append([1, "Status availability mask 0x%02X" % msg[2], off + 2, 1, "Which status bits this ECU supports"])
        for k in range(3, len(msg) - 3, 4):
            st = msg[k + 3]
            b.rows.append([1, "DTC %s-%02X (0x%02X%02X%02X) status 0x%02X" % (dtc_str(msg[k], msg[k + 1]), msg[k + 2], msg[k], msg[k + 1], msg[k + 2], st), off + k, 4,
                           "3-byte DTC (2-byte SAE J2012 code + failure type) + status byte"])
            b.rows.append([2, ", ".join(nm for m_, nm in DTC_ST if st & m_) or "no status bits set", off + k + 3, 1, "ISO 14229-1 DTC status bits"])
    if base == 0x19 and not pos and len(msg) >= 3:
        b.rows.append([1, "DTC status mask 0x%02X" % msg[2], off + 2, 1, "Report DTCs with any of these status bits set"])
    if base in (0x22, 0x2E) and len(msg) >= 3:
        did = msg[1] << 8 | msg[2]
        b.rows.append([1, "Data identifier 0x%04X %s" % (did, DIDS.get(did, ("",))[0]), off + 1, 2, "DIDs 0xF180-0xF19F are standardised identification records"])
        if len(msg) > 3:
            v = msg[3:]
            txt = v.decode("latin-1") if all(32 <= x < 127 for x in v) else v.hex(" ").upper()
            if did == 0x0123 and len(v) == 2:
                txt = "%d rpm" % (v[0] << 8 | v[1])
            b.rows.append([1, "Data record: %s" % txt, off + 3, len(v), ""])
    if base == 0x31 and len(msg) >= 4:
        rid = msg[2] << 8 | msg[3]
        b.rows.append([1, "Routine identifier 0x%04X %s" % (rid, ROUTINES.get(rid, "")), off + 2, 2, "0xFF00 erase memory, 0xFF01 check programming dependencies"])
    if base == 0x14 and len(msg) >= 4:
        b.rows.append([1, "Group of DTC 0x%06X%s" % (msg[1] << 16 | msg[2] << 8 | msg[3], " (all groups)" if msg[1:4] == b"\xff\xff\xff" else ""), off + 1, 3, ""])
    if base == 0x34 and not pos and len(msg) >= 3:
        b.rows.append([1, "Data format 0x%02X, address/length format 0x%02X" % (msg[1], msg[2]), off + 1, 2, "0x00 = no compression/encryption; 0x44 = 4-byte address + 4-byte size"])
        if len(msg) >= 11:
            b.rows.append([1, "Memory address 0x%08X, size %d bytes" % (int.from_bytes(msg[3:7], "big"), int.from_bytes(msg[7:11], "big")), off + 3, 8, ""])
    if base == 0x34 and pos and len(msg) >= 4:
        b.rows.append([1, "maxNumberOfBlockLength %d bytes" % int.from_bytes(msg[2:2 + (msg[1] >> 4)], "big"), off + 1, len(msg) - 1,
                       "Largest TransferData request the ECU accepts (SID + counter + data)"])
    if base == 0x36 and len(msg) >= 2:
        b.rows.append([1, "Block sequence counter %d" % msg[1], off + 1, 1, "Starts at 1, wraps 0xFF -> 0x00"])
        if len(msg) > 2:
            b.rows.append([1, "Transfer data: %d bytes" % (len(msg) - 2), off + 2, len(msg) - 2, ""])


class UdsNet(CanNet):
    """Tester and ECUs reachable with ISO-TP (base of UDS, ISO-TP and OBD-II)."""
    cat = "auto"
    rate = 500000
    can_proto = "UDS"

    def mk(self, extra_ecu=True):
        nodes = [self.node("tester", "DIAGNOSTIC TESTER", "tool", 40, 60, "0x7E0", "sends on 0x7E0, ECU answers on 0x7E8"),
                 self.node("ecm", "ENGINE ECM", "ecu", 330, 60, "0x7E8", "UDS server"), self.node("tcm", "TRANSMISSION TCM", "ecu", 620, 60, "0x7E9")]
        if extra_ecu:
            nodes.append(self.node("bcm", "BODY CONTROLLER", "ecu", 470, 290, "0x7EC", "periodic traffic").at_top())
        self.can_trunk(nodes, 200, conn="dt")
        self.tp = IsoTp(self)
        self.user = "tester"
        if extra_ecu:
            self.every(0.1, lambda: self.bus.send("bcm", 0x3A1, bytes([0x00, 0x10, int(self.t * 10) & 255, 0, 0, 0, 0, 0]), info="BCM status (normal periodic traffic)", kind="data",
                                                  proto="CAN"), 0.003)


class UDS(UdsNet):
    key, name = "uds", "UDS (ISO 14229)"
    blurb = "Vehicle diagnostics"
    medium = "UDS on CAN (ISO 14229-1 over ISO 15765-2): tester 0x7E0 <-> engine ECU 0x7E8, 500 kbit/s, normal ECU traffic on the same bus"
    faults = [("lock", "ECU security locked out (time delay running)", "After too many invalid keys the ECU refuses seed requests with NRC 0x37 until a delay expires."),
              ("pending", "ECU slow to execute routines", "Long operations (erase, checks) first answer NRC 0x78 'response pending', the real response follows later."),
              ("s3", "Tester stops sending TesterPresent", "The S3 server timer (5 s) expires and the ECU drops back to the default session: extended services fail again.")]
    spec = [("Standard", "ISO 14229-1 (services), ISO 14229-3 (UDS on CAN), ISO 15765-2 (ISO-TP), ISO 13400 (DoIP on Ethernet)"),
            ("Addressing", "Physical: tester 0x7E0 -> ECU, ECU -> 0x7E8; functional 0x7DF (all ECUs)"),
            ("Format", "SID + sub-function or identifier + data; positive response = SID + 0x40"),
            ("Negative", "0x7F + SID + NRC: 0x11 not supported, 0x22 conditions not correct, 0x33 security denied, 0x35 invalid key, 0x78 response pending, 0x7F not in this session"),
            ("Sessions", "Default (01), programming (02), extended (03); S3 timer 5 s, kept alive with TesterPresent 0x3E 80"),
            ("Security", "SecurityAccess 0x27: request seed (odd level), send key (even level); a session change locks the ECU again"),
            ("Flashing", "Programming session, security, erase (0x31 FF00), RequestDownload 0x34, TransferData 0x36 blocks, RequestTransferExit 0x37, check (0x31 FF01), reset")]
    frame = [["Request", ("SID", 8), ("Sub-function / DID", "8-16"), ("Data", "n x 8")], ["Negative response", ("0x7F", 8), ("Rejected SID", 8), ("NRC", 8)]]
    about = ("UDS is the service menu every modern ECU offers to a tester: read identification and live data by data identifier (DID), read "
             "and clear trouble codes, run routines and reprogram the flash memory. Protected services need a session change and a seed/key "
             "exchange. Messages longer than 7 bytes are segmented by ISO-TP. In this simulator the secret key algorithm is "
             "key = ((seed XOR 0x2F7A) x 3 + 0x1B) AND 0xFFFF.")
    guide = ["COMPOSE ReadDataByIdentifier 0xF190: the VIN comes back as a multi-frame ISO-TP response (FF, FC, CFs).",
             "Try WriteDataByIdentifier 0x0123 in the default session: NRC 0x7F. Switch to the extended session (0x10 03) first.",
             "Request a seed (0x27 01), compute the key with the formula in ABOUT (or peek at the ECM's DEVICE panel) and send it (0x27 02).",
             "Read DTCs (0x19 02 FF), decode the status bits, clear them with 0x14 and read again.",
             "Run the flash programming script and follow every step in FLOW: session, security, erase, download, transfer, exit, check, reset.",
             "Stop TesterPresent (fault) and watch the session time out after 5 s."]

    def setup(self):
        self.mk()
        self.session = 1
        self.unlocked = False
        self.seed = 0
        self.attempts = 0
        self.lock_until = 0.0
        self.last_tp = 0.0
        self.dl = None
        self.dtcs = [(0x030100, 0x2F), (0x042000, 0x09)]
        self.by["ecm"].vars.update({"Session": "default", "Security": "locked", "DTCs": 2, "Flash": "application valid"})
        self.by["tester"].vars.update({"Last response": "-"})
        self.every(2.0, self.tester_present, 1.0)
        self.every(0.5, self.s3, 0.25)
        self.at(0.05, lambda: self.request(bytes([0x22, 0xF1, 0x90])))

    def ecu_send(self, msg, info, kind="resp"):
        self.by["tester"].vars["Last response"] = info
        self.tp.send("ecm", "tester", 0x7E8, 0x7E0, msg, info, kind, "UDS", app=uds_dissect, fc=(0, 0))

    def request(self, msg, send=True):
        msg = bytes(msg)
        info = "%s %s" % (UDS_SID.get(msg[0], "0x%02X" % msg[0]), msg[1:9].hex(" ").upper() + (" ..." if len(msg) > 9 else ""))
        if not send:
            d = (bytes([len(msg)]) + msg + bytes([0xCC] * (7 - len(msg)))) if len(msg) <= 7 else (bytes([0x10 | (len(msg) >> 8), len(msg) & 255]) + msg[:6])
            return self.preview_can("tester", 0x7E0, d, info=info,
                                    dissect=lambda b, o: (IsoTp.pci_rows(b, o, d), IsoTp.app_rows(b, o, d, msg, uds_dissect)))
        if msg[0] == 0x3E:
            self.last_tp = self.t
        done = None
        if not (len(msg) >= 2 and msg[0] == 0x3E and msg[1] & 0x80):
            done = lambda m=msg: self.at(self.t + 0.004, self.serve, m)
        self.tp.send("tester", "ecm", 0x7E0, 0x7E8, msg, info, "cmd", "UDS", app=uds_dissect, on_done=done, fc=(8, 1))
        return None

    def neg(self, sid, nrc):
        self.ecu_send(bytes([0x7F, sid, nrc]), "Negative response to 0x%02X: NRC 0x%02X %s" % (sid, nrc, NRC.get(nrc, "")), "err")

    def set_session(self, s):
        e = self.by["ecm"]
        if s != self.session:
            self.unlocked = False
            e.vars["Security"] = "locked"
        self.session = s
        self.last_tp = self.t
        e.vars["Session"] = {1: "default", 2: "programming", 3: "extended"}[s]

    def serve(self, m):
        if not self.by["ecm"].on:
            return
        sid = m[0]
        e = self.by["ecm"]
        if sid == 0x10 and len(m) >= 2:
            sf = m[1] & 0x7F
            if sf not in (1, 2, 3):
                return self.neg(sid, 0x12)
            if sf == 2 and self.session == 1:
                return self.neg(sid, 0x7E)
            self.set_session(sf)
            return self.ecu_send(bytes([0x50, sf, 0x00, 0x32, 0x01, 0xF4]), "Session %s active (P2 50 ms, P2* 5000 ms)" % e.vars["Session"])
        if sid == 0x3E:
            return self.ecu_send(bytes([0x7E, 0x00]), "TesterPresent positive response")
        if sid == 0x22 and len(m) >= 3:
            did = m[1] << 8 | m[2]
            if did not in DIDS:
                return self.neg(sid, 0x31)
            v = DIDS[did][1]
            return self.ecu_send(bytes([0x62, m[1], m[2]]) + v, "DID 0x%04X = %s" % (did, ("%d rpm" % (v[0] << 8 | v[1])) if did == 0x0123 else v.decode("latin-1")))
        if sid == 0x2E and len(m) >= 3:
            if self.session == 1:
                return self.neg(sid, 0x7F)
            if not self.unlocked:
                return self.neg(sid, 0x33)
            did = m[1] << 8 | m[2]
            if did != 0x0123 or len(m) != 5:
                return self.neg(sid, 0x31 if did != 0x0123 else 0x13)
            DIDS[did] = (DIDS[did][0], bytes(m[3:5]))
            return self.ecu_send(bytes([0x6E, m[1], m[2]]), "WriteDataByIdentifier 0x0123 accepted (%d rpm)" % (m[3] << 8 | m[4]))
        if sid == 0x27 and len(m) >= 2:
            if self.session == 1:
                return self.neg(sid, 0x7F)
            if self.fault["lock"] or self.t < self.lock_until:
                return self.neg(sid, 0x37)
            if m[1] == 1:
                if self.unlocked:
                    return self.ecu_send(bytes([0x67, 0x01, 0x00, 0x00]), "Seed 0x0000: already unlocked")
                self.seed = int(self.rng.integers(1, 0xFFFF))
                return self.ecu_send(bytes([0x67, 0x01]) + self.seed.to_bytes(2, "big"), "Seed 0x%04X" % self.seed)
            if m[1] == 2 and len(m) >= 4:
                if not self.seed:
                    return self.neg(sid, 0x24)
                k = m[2] << 8 | m[3]
                if k == uds_key(self.seed):
                    self.unlocked = True
                    self.attempts = 0
                    self.seed = 0
                    e.vars["Security"] = "UNLOCKED"
                    return self.ecu_send(bytes([0x67, 0x02]), "Security access granted")
                self.attempts += 1
                self.seed = 0
                if self.attempts >= 3:
                    self.lock_until = self.t + 10.0
                    self.attempts = 0
                    return self.neg(sid, 0x36)
                return self.neg(sid, 0x35)
            return self.neg(sid, 0x12)
        if sid == 0x19 and len(m) >= 3:
            sel = [(c, st) for c, st in self.dtcs if st & m[2]]
            body = bytes([0x59, 0x02, 0xFF]) + b"".join(bytes([c >> 16, (c >> 8) & 255, c & 255, st]) for c, st in sel)
            return self.ecu_send(body, "%d DTCs: %s" % (len(sel), ", ".join(dtc_str(c >> 16, (c >> 8) & 255) for c, _ in sel) or "none"))
        if sid == 0x14:
            self.dtcs = []
            e.vars["DTCs"] = 0
            return self.ecu_send(bytes([0x54]), "DTC memory cleared")
        if sid == 0x11 and len(m) >= 2:
            self.set_session(1)
            self.ecu_send(bytes([0x51, m[1]]), "ECU reset")
            e.state = "RESET"
            self.at(self.t + 0.3, lambda: setattr(e, "state", ""))
            return None
        if sid in (0x28, 0x85) and len(m) >= 2:
            if self.session == 1:
                return self.neg(sid, 0x7F)
            return self.ecu_send(bytes([sid + 0x40, m[1]]), "%s 0x%02X accepted" % (UDS_SID[sid], m[1]))
        if sid == 0x31 and len(m) >= 4:
            rid = m[2] << 8 | m[3]
            if rid in (0xFF00, 0xFF01) and (self.session != 2 or not self.unlocked):
                return self.neg(sid, 0x33 if self.session == 2 else 0x7F)
            res = bytes([0x71, m[1], m[2], m[3], 0x00])
            txt = "Routine 0x%04X %s finished OK" % (rid, ROUTINES.get(rid, ""))
            if rid == 0xFF00:
                e.vars["Flash"] = "ERASED"
            if rid == 0xFF01:
                e.vars["Flash"] = "application valid (new software)" if self.dl and self.dl.get("done") else "INVALID (nothing programmed)"
            if self.fault["pending"]:
                self.neg(sid, 0x78)
                self.at(self.t + 1.2, self.ecu_send, res, txt)
                return None
            return self.ecu_send(res, txt)
        if sid == 0x34 and len(m) >= 3:
            if self.session != 2 or not self.unlocked:
                return self.neg(sid, 0x33 if self.session == 2 else 0x7F)
            size = int.from_bytes(m[7:11], "big") if len(m) >= 11 else 1024
            self.dl = {"size": size, "got": 0, "ctr": 1, "done": False}
            e.vars["Flash"] = "downloading 0/%d" % size
            return self.ecu_send(bytes([0x74, 0x20, 0x02, 0x02]), "RequestDownload accepted: blocks up to 514 bytes")
        if sid == 0x36 and len(m) >= 2:
            if not self.dl:
                return self.neg(sid, 0x24)
            if m[1] != self.dl["ctr"]:
                return self.neg(sid, 0x73)
            self.dl["got"] += len(m) - 2
            self.dl["ctr"] = (self.dl["ctr"] + 1) & 0xFF
            e.vars["Flash"] = "downloading %d/%d" % (self.dl["got"], self.dl["size"])
            return self.ecu_send(bytes([0x76, m[1]]), "TransferData block %d accepted (%d/%d bytes)" % (m[1], self.dl["got"], self.dl["size"]))
        if sid == 0x37:
            if not self.dl:
                return self.neg(sid, 0x24)
            self.dl["done"] = self.dl["got"] >= self.dl["size"]
            e.vars["Flash"] = "download complete" if self.dl["done"] else "INCOMPLETE"
            return self.ecu_send(bytes([0x77]), "RequestTransferExit")
        return self.neg(sid, 0x11)

    def tester_present(self):
        if self.session != 1 and not self.fault["s3"] and self.by["tester"].on:
            self.request(bytes([0x3E, 0x80]))

    def s3(self):
        if self.session != 1 and self.t - self.last_tp > 5.0:
            self.set_session(1)
            self.by["ecm"].vars["Session"] = "default (S3 timeout)"
            self.log("S3 server timer expired: ECU back in the default session, security locked")

    def inspect(self, n):
        rows = super().inspect(n)
        if n.id == "ecm":
            rows.append(("Last seed -> correct key", "0x%04X -> 0x%04X" % (self.seed, uds_key(self.seed)) if self.seed else "(request a seed)"))
        return rows

    def flash(self, send=True):
        steps = [bytes([0x10, 0x03]), bytes([0x10, 0x02]), bytes([0x27, 0x01]), None, bytes([0x31, 0x01, 0xFF, 0x00]),
                 bytes([0x34, 0x00, 0x44]) + struct.pack(">II", 0x00040000, 1024)]
        blk = bytes((i * 37 + 11) & 255 for i in range(512))
        steps += [bytes([0x36, 0x01]) + blk, bytes([0x36, 0x02]) + blk, bytes([0x37]), bytes([0x31, 0x01, 0xFF, 0x01]), bytes([0x11, 0x01])]
        if not send:
            return self.request(steps[0], False)
        t = 0.0
        for i, st in enumerate(steps):
            if st is None:
                self.at(self.t + t, lambda: self.request(bytes([0x27, 0x02]) + uds_key(self.seed).to_bytes(2, "big")))
            else:
                self.at(self.t + t, self.request, st)
            t += 0.25 if not (st and st[0] == 0x31 and self.fault["pending"]) else 1.5
        self.log("Flash programming script started (%d steps)" % len(steps))
        return None

    def tpls(self):
        did_opts = sorted(DIDS.keys())
        return [Tpl("ReadDataByIdentifier (0x22)", [P("did", "DID", 0xF190, opts=did_opts, fmt=lambda v: "0x%04X %s" % (v, DIDS[v][0]))],
                    lambda s, v, send: self.request(bytes([0x22, v["did"] >> 8, v["did"] & 255]), send), "Identification and live data records."),
                Tpl("DiagnosticSessionControl (0x10)", [P("s", "Session", 3, opts=[1, 2, 3], fmt=lambda v: {1: "01 default", 2: "02 programming", 3: "03 extended"}[v])],
                    lambda s, v, send: self.request(bytes([0x10, v["s"]]), send), "Write and security services need the extended session; flashing needs programming."),
                Tpl("SecurityAccess requestSeed (0x27 01)", [], lambda s, v, send: self.request(bytes([0x27, 0x01]), send), "The ECU answers with a 2-byte seed."),
                Tpl("SecurityAccess sendKey (0x27 02)", [P("k", "Key", 0x1234, 0, 0xFFFF, fmt=lambda v: "0x%04X" % v)],
                    lambda s, v, send: self.request(bytes([0x27, 0x02, v["k"] >> 8, v["k"] & 255]), send),
                    "key = ((seed XOR 0x2F7A) x 3 + 0x1B) AND 0xFFFF. Three wrong keys trigger a 10 s lock-out (NRC 0x36, then 0x37)."),
                Tpl("WriteDataByIdentifier 0x0123", [P("v", "Idle rpm", 800, 500, 1200)], lambda s, v, send: self.request(bytes([0x2E, 0x01, 0x23]) + struct.pack(">H", v["v"]), send),
                    "Needs the extended session and security access."),
                Tpl("ReadDTCInformation (0x19 02)", [P("m", "Status mask", 0xFF, 0, 255, fmt=lambda v: "0x%02X" % v)], lambda s, v, send: self.request(bytes([0x19, 0x02, v["m"]]), send),
                    "DTCs whose status matches the mask (0x08 = confirmed only)."),
                Tpl("ClearDiagnosticInformation (0x14)", [], lambda s, v, send: self.request(bytes([0x14, 0xFF, 0xFF, 0xFF]), send), "Clear all DTCs."),
                Tpl("TesterPresent (0x3E 00)", [], lambda s, v, send: self.request(bytes([0x3E, 0x00]), send), "Keeps a non-default session alive (with a response)."),
                Tpl("ECUReset (0x11 01)", [], lambda s, v, send: self.request(bytes([0x11, 0x01]), send), "Hard reset: session and security drop."),
                Tpl("Flash programming script", [], lambda s, v, send: self.flash(send),
                    "Runs the complete reprogramming sequence: extended -> programming session, seed/key, erase, RequestDownload, 2 x TransferData (512 B), exit, check, reset.")]


class ISOTP(UdsNet):
    key, name = "isotp", "ISO-TP (ISO 15765-2)"
    blurb = "Transporting larger messages over CAN"
    can_proto = "ISO-TP"
    medium = "ISO 15765-2: the tester downloads a 120-byte block to the ECU every 3 s; the ECU's flow control sets block size and STmin (DEVICE knobs)"
    faults = [("nofc", "ECU never sends Flow Control", "After the First Frame the tester waits N_Bs (1 s) for flow control, then aborts the transfer."),
              ("sn", "Tester skips a sequence number", "The ECU sees CF sequence number 5 where 3 was expected and aborts the reception (N_WRONG_SN)."),
              ("slow", "ECU needs 2 ms per frame but announces STmin 0", "Consecutive frames arrive faster than the ECU can store them: overrun, transfer lost. Fix: STmin >= 2 ms."),
              ("wait", "ECU busy: answers Flow Control WAIT", "FS = 1 tells the sender to hold on; the ECU sends CTS when its buffer is ready.")]
    spec = [("Standard", "ISO 15765-2 (used by UDS, OBD-II on CAN, J1939-independent applications)"),
            ("Frames", "SF (<= 7 bytes), FF (12-bit length, up to 4095 bytes), CF (sequence 0-15), FC (CTS / WAIT / OVFLW)"),
            ("Flow control", "Block size: CFs per FC (0 = all at once); STmin: minimum gap 0-127 ms or 100-900 us"),
            ("Timers", "N_As/N_Ar (frame sent), N_Bs (wait for FC, 1000 ms), N_Cr (wait for next CF, 1000 ms)"),
            ("Padding", "Unused bytes padded (0xCC, 0xAA or 0x55) so every frame has DLC 8"), ("CAN FD", "Up to 64-byte frames; escape sequence for longer lengths")]
    frame = [["PCI types (first byte)", ("SF: 0 | length", 8), ("FF: 1 | length (12 bit)", 16), ("CF: 2 | SN", 8), ("FC: 3 | FS, BS, STmin", 24)]]
    about = ("A CAN frame carries 8 bytes, but diagnostics need hundreds. ISO-TP splits a message: a First Frame announces the total length, the "
             "receiver replies with a Flow Control frame that says how many Consecutive Frames to send before the next flow control (block size) and "
             "how far apart (STmin), and the sender streams numbered Consecutive Frames. A lost or reordered frame shows up as a wrong sequence number.")
    guide = ["Watch one transfer in FLOW: FF from the tester, FC from the ECU, then CFs with sequence numbers 1..15, 0, 1...",
             "Turn the ECU's BS knob to 4: a new Flow Control appears after every 4 consecutive frames.",
             "Set STmin to 10 ms and compare the CF spacing in the ANALYZER time column.",
             "Inject 'ECU needs 2 ms' - the transfer fails - then fix it with STmin 2 ms.",
             "Drop the Flow Control and watch the sender give up after N_Bs."]

    def setup(self):
        self.mk(False)
        e = self.by["ecm"]
        e.vars.update({"Block size": 0, "STmin ms": 0, "Last reception": "-"})
        e.ctl = [("Block size", "BS", 0, 15, 1, lambda v: "%d" % v), ("STmin ms", "STMIN", 0, 20, 1, lambda v: "%d ms" % v)]
        self.by["tester"].vars.update({"Last transfer": "-"})
        self.every(3.0, lambda: self.xfer(120, "download"), 0.3)

    def xfer(self, n, direction="download", send=True):
        e = self.by["ecm"]
        bs, st = int(e.vars["Block size"]), int(e.vars["STmin ms"])
        if direction == "download":
            data = bytes([0x36, 0x01]) + bytes((i * 7 + 3) & 255 for i in range(max(0, n - 2)))
        else:
            data = bytes([0x22, 0xF1, 0xA0])
        if not send:
            d = (bytes([len(data)]) + data + bytes([0xCC] * (7 - len(data)))) if len(data) <= 7 else bytes([0x10 | (len(data) >> 8), len(data) & 255]) + data[:6]
            return self.preview_can("tester", 0x7E0, d, dissect=lambda b, o: (IsoTp.pci_rows(b, o, d), IsoTp.app_rows(b, o, d, data, uds_dissect)))
        tp = self.tp
        tp.lost_fc, tp.bad_sn, tp.slow_rx, tp.wait_fc = self.fault["nofc"], self.fault["sn"], self.fault["slow"], self.fault["wait"]
        tv = self.by["tester"].vars

        def ok_dl():
            e.vars["Last reception"] = "OK, %d bytes" % len(data)
            tv["Last transfer"] = "OK (%d bytes, BS %d, STmin %d ms)" % (len(data), bs, st)
            tp.lost_fc = tp.bad_sn = tp.slow_rx = tp.wait_fc = False
            self.at(self.t + 0.002, lambda: tp.send("ecm", "tester", 0x7E8, 0x7E0, bytes([0x76, 0x01]), "Positive response: block received", "resp", "ISO-TP", app=uds_dissect))

        def bad(msg):
            e.vars["Last reception"] = "ABORTED"
            tv["Last transfer"] = "FAILED: " + msg.split(":")[0]
        if direction == "download":
            tp.send("tester", "ecm", 0x7E0, 0x7E8, data, "TransferData %d bytes" % len(data), "cmd", "ISO-TP", app=uds_dissect, on_done=ok_dl, on_fail=bad, fc=(bs, st))
        else:
            tp.lost_fc = tp.bad_sn = tp.slow_rx = tp.wait_fc = False
            tp.send("tester", "ecm", 0x7E0, 0x7E8, data, "ReadDataByIdentifier 0xF1A0", "cmd", "ISO-TP", app=uds_dissect)
            rec = bytes([0x62, 0xF1, 0xA0]) + bytes((i * 5 + 1) & 255 for i in range(max(0, n - 3)))
            self.at(self.t + 0.004, lambda: tp.send("ecm", "tester", 0x7E8, 0x7E0, rec, "Record 0xF1A0 (%d bytes)" % len(rec), "resp", "ISO-TP", app=uds_dissect, fc=(bs, st),
                                                    on_done=lambda: tv.__setitem__("Last transfer", "upload OK (%d bytes)" % len(rec))))
        return None

    def tpls(self):
        return [Tpl("Segmented transfer", [P("n", "Message bytes", 120, 8, 4095), P("dir", "Direction", "download", opts=["download", "upload"]),
                                           P("bs", "Block size", 0, 0, 15), P("st", "STmin ms", 0, 0, 127)],
                    lambda s, v, send: self._go(v, send), "Download: tester -> ECU (the ECU announces BS/STmin). Upload: ECU -> tester (the tester announces them).")]

    def _go(self, v, send):
        if send:
            self.by["ecm"].vars.update({"Block size": v["bs"], "STmin ms": v["st"]})
        return self.xfer(v["n"], v["dir"], send)


# =================================================================== OBD-II
OBD_PID = {0x00: "PIDs supported [01-20]", 0x01: "Monitor status since DTCs cleared", 0x04: "Calculated engine load", 0x05: "Engine coolant temperature",
           0x0B: "Intake manifold absolute pressure", 0x0C: "Engine RPM", 0x0D: "Vehicle speed", 0x0F: "Intake air temperature", 0x10: "MAF air flow rate",
           0x11: "Throttle position", 0x1F: "Run time since engine start", 0x20: "PIDs supported [21-40]", 0x2F: "Fuel tank level input",
           0x40: "PIDs supported [41-60]", 0x42: "Control module voltage", 0x46: "Ambient air temperature"}


def obd_decode(pid, d):
    a = d[0] if d else 0
    b = d[1] if len(d) > 1 else 0
    if pid in (0x00, 0x20, 0x40):
        bm = int.from_bytes(bytes(d[:4]), "big")
        return "supported: " + " ".join("%02X" % (pid + i) for i in range(1, 33) if bm & (1 << (32 - i)))
    return {0x04: "%.1f %%" % (a * 100 / 255.0), 0x05: "%d degC" % (a - 40), 0x0B: "%d kPa" % a, 0x0C: "%.2f rpm" % ((256 * a + b) / 4.0), 0x0D: "%d km/h" % a,
            0x0F: "%d degC" % (a - 40), 0x10: "%.2f g/s" % ((256 * a + b) / 100.0), 0x11: "%.1f %%" % (a * 100 / 255.0), 0x1F: "%d s" % (256 * a + b),
            0x2F: "%.1f %%" % (a * 100 / 255.0), 0x42: "%.3f V" % ((256 * a + b) / 1000.0), 0x46: "%d degC" % (a - 40),
            0x01: "MIL %s, %d DTCs" % ("ON" if a & 0x80 else "off", a & 0x7F)}.get(pid, bytes(d).hex())


OBD_FORMULA = {0x04: "A x 100 / 255", 0x05: "A - 40", 0x0B: "A", 0x0C: "(256 A + B) / 4", 0x0D: "A", 0x0F: "A - 40", 0x10: "(256 A + B) / 100", 0x11: "A x 100 / 255",
               0x1F: "256 A + B", 0x2F: "A x 100 / 255", 0x42: "(256 A + B) / 1000", 0x46: "A - 40", 0x01: "A7 = MIL, A6..A0 = DTC count"}


class OBD2(UdsNet):
    key, name = "obd2", "OBD-II"
    blurb = "Vehicle diagnostic interface and standards"
    can_proto = "OBD-II"
    medium = "SAE J1979 / ISO 15031-5 on ISO 15765-4 CAN (500 kbit/s): scan tool on the J1962 connector, engine ECM 0x7E8, transmission TCM 0x7E9"
    faults = [("misfire", "Cylinder 1 misfire", "The misfire monitor sets pending P0300 + P0301, confirms them after a few seconds and turns on the MIL."),
              ("cat", "Catalyst efficiency below threshold", "P0420 becomes pending, then confirmed."),
              ("off", "ECM not responding", "Only the TCM answers; the scan tool reports NO DATA for engine PIDs."),
              ("ext", "Vehicle uses 29-bit OBD identifiers", "ISO 15765-4 also allows 29-bit IDs (functional 0x18DB33F1, responses 0x18DAF1xx). The tool's 11-bit requests "
                                                         "go unanswered until its protocol search switches to 29-bit.")]
    spec = [("Standards", "SAE J1979 / ISO 15031-5 (services), SAE J1962 (connector), ISO 15765-4 (CAN), plus legacy ISO 9141-2, ISO 14230-4, SAE J1850"),
            ("Connector", "J1962 16-pin: 4/5 ground, 6 CAN-H, 14 CAN-L, 7 K-line, 15 L-line, 2/10 J1850, 16 battery +"),
            ("Addressing", "Functional request 0x7DF; ECU responses 0x7E8-0x7EF; physical requests (and flow control) 0x7E0-0x7E7"),
            ("Services", "01 current data, 02 freeze frame, 03 stored DTCs, 04 clear, 06 monitor results, 07 pending DTCs, 09 vehicle info (VIN), 0A permanent DTCs"),
            ("Formulas", "RPM = (256 A + B) / 4, coolant = A - 40 degC, speed = A km/h, load = 100 A / 255 %"),
            ("Mandatory", "US cars from 1996, EU petrol 2001 / diesel 2004 (EOBD); CAN mandatory in the US from 2008")]
    frame = [["Mode 01 request (single frame)", ("PCI 02", 8), ("Mode 01", 8), ("PID", 8), ("padding", 40)],
             ["Response", ("PCI", 8), ("Mode + 0x40", 8), ("PID", 8), ("A", 8), ("B", 8), ("C", 8), ("D", 8)]]
    about = ("OBD-II is the legally mandated emissions diagnostics on every car. A scan tool plugged into the J1962 connector sends a functional "
             "request (ID 0x7DF) such as 'mode 01 PID 0C' and every emissions ECU answers on its own ID. Stored trouble codes come back with mode "
             "03, pending ones with mode 07 and the VIN with mode 09 - long enough to need ISO-TP segmentation.")
    guide = ["COMPOSE mode 01 PID 0C and compute RPM = (256 A + B) / 4 from the response bytes.",
             "Request PID 00: both ECUs answer with a bitmap of the PIDs they support.",
             "Inject the misfire: first mode 07 (pending) shows P0301, a few seconds later mode 03 (confirmed) and the MIL in PID 01.",
             "Clear with mode 04: the MIL goes out, but the codes return while the misfire persists.",
             "Read the VIN with mode 09 PID 02 (multi-frame).",
             "Switch the car to 29-bit IDs and watch the tool's protocol search."]

    def setup(self):
        self.mk(False)
        self.tp.pad = 0x55
        t = self.by["tester"]
        t.label, t.sub = "SCAN TOOL", "J1962 DLC"
        t.vars.update({"Protocol": "ISO 15765-4 CAN 11/500", "Last result": "-"})
        e = self.by["ecm"]
        e.vars.update({"RPM": 850.0, "Speed km/h": 0, "Coolant C": 89, "Throttle %": 2.0, "MIL": "off", "Battery V": 14.1, "Pending": "-", "Confirmed": "-"})
        e.ctl = [("Throttle %", "THROTTLE", 0.0, 100.0, 0, lambda v: "%.0f%%" % v), ("Coolant C", "COOLANT", -40, 130, 1, lambda v: "%d C" % v)]
        self.k = 0
        self.ext29 = False
        self.miss = 0
        self.age = {}
        self.pending, self.confirmed = set(), set()
        self.every(0.25, self.scan, 0.2)
        self.every(0.1, self.engine, 0.05)
        self.every(1.0, self.monitors, 0.5)

    def engine(self):
        e = self.by["ecm"]
        thr = e.vars["Throttle %"]
        e.vars["RPM"] = round(e.vars["RPM"] + ((760 + thr * 45) - e.vars["RPM"]) * 0.1 + (self.rng.normal(0, 25) if self.fault["misfire"] else 0), 1)
        e.vars["Speed km/h"] = int(max(0, min(200, e.vars["Speed km/h"] + (thr - 15) * 0.02)))

    def monitors(self):
        failing = set()
        if self.fault["misfire"]:
            failing |= {(0x03, 0x00), (0x03, 0x01)}
        if self.fault["cat"]:
            failing.add((0x04, 0x20))
        for c in failing:
            self.age[c] = self.age.get(c, 0) + 1
            self.pending.add(c)
            if self.age[c] >= 3:
                self.confirmed.add(c)
        for c in list(self.age):
            if c not in failing:
                self.age.pop(c)
                self.pending.discard(c)
        e = self.by["ecm"]
        e.vars["MIL"] = "ON" if self.confirmed else "off"
        e.vars["Pending"] = ", ".join(dtc_str(*c) for c in sorted(self.pending)) or "-"
        e.vars["Confirmed"] = ", ".join(dtc_str(*c) for c in sorted(self.confirmed)) or "-"

    def bitmap(self, base, pids):
        bm = 0
        for p in pids:
            if base < p <= base + 32:
                bm |= 1 << (32 - (p - base))
        return bm.to_bytes(4, "big")

    def pid_data(self, pid):
        e = self.by["ecm"]
        if pid in (0x00, 0x20, 0x40):
            return self.bitmap(pid, OBD_PID.keys())
        if pid == 0x01:
            return bytes([(0x80 if self.confirmed else 0) | len(self.confirmed), 0x07, 0x65, 0x00])
        rpm = int(e.vars["RPM"] * 4)
        return {0x04: bytes([min(255, int(e.vars["Throttle %"] * 2.0 + 30))]), 0x05: bytes([int(e.vars["Coolant C"]) + 40]),
                0x0B: bytes([32 + int(e.vars["Throttle %"] * 0.6)]), 0x0C: bytes([rpm >> 8, rpm & 255]), 0x0D: bytes([int(e.vars["Speed km/h"])]), 0x0F: bytes([25 + 40]),
                0x10: struct.pack(">H", int(250 + e.vars["Throttle %"] * 30)), 0x11: bytes([int(e.vars["Throttle %"] * 2.55)]), 0x1F: struct.pack(">H", int(self.t) & 0xFFFF),
                0x2F: bytes([170]), 0x42: struct.pack(">H", int(e.vars["Battery V"] * 1000)), 0x46: bytes([18 + 40])}.get(pid)

    def scan(self):
        pids = [0x0C, 0x0D, 0x05, 0x11]
        self.k = (self.k + 1) % len(pids)
        self.request(1, pids[self.k])

    def obd_rows(self, b, off, msg):
        mode = msg[0]
        if mode == 0x7F and len(msg) >= 3:
            b.rows.append([0, "OBD-II negative response: mode 0x%02X, code 0x%02X" % (msg[1], msg[2]), off, 3, "0x12 = sub-function / PID not supported"])
            return
        rq = mode < 0x40
        m = mode if rq else mode - 0x40
        b.rows.append([0, "OBD-II %s, mode 0x%02X" % ("request" if rq else "response", m), off, len(msg), "SAE J1979: response mode = request mode + 0x40"])
        b.rows.append([1, "Mode (service) 0x%02X" % mode, off, 1, {1: "current powertrain data", 3: "stored (confirmed) DTCs", 4: "clear DTCs", 7: "pending DTCs", 9: "vehicle information"}.get(m, "")])
        if m == 1 and len(msg) >= 2:
            b.rows.append([1, "PID 0x%02X: %s" % (msg[1], OBD_PID.get(msg[1], "")), off + 1, 1, "Formula: %s" % OBD_FORMULA.get(msg[1], "bitmap / see SAE J1979")])
            if not rq and len(msg) > 2:
                b.rows.append([1, "Value: %s (A..D = %s)" % (obd_decode(msg[1], msg[2:]), msg[2:].hex(" ").upper()), off + 2, len(msg) - 2, "Data bytes A, B, C, D"])
        if m in (3, 7) and not rq and len(msg) >= 2:
            b.rows.append([1, "Number of DTCs: %d" % msg[1], off + 1, 1, "On CAN the count byte follows the mode"])
            for k in range(2, len(msg) - 1, 2):
                b.rows.append([1, "DTC %s (0x%02X%02X)" % (dtc_str(msg[k], msg[k + 1]), msg[k], msg[k + 1]), off + k, 2,
                               "First 2 bits: P powertrain, C chassis, B body, U network; then 2-bit digit and three hex digits"])
        if m == 9 and len(msg) >= 2:
            b.rows.append([1, "Info type 0x%02X%s" % (msg[1], " (VIN)" if msg[1] == 2 else ""), off + 1, 1, ""])
            if not rq and len(msg) > 3:
                b.rows.append([1, "Number of data items: %d" % msg[2], off + 2, 1, ""])
                b.rows.append([1, "VIN: %s" % msg[3:].decode("latin-1"), off + 3, len(msg) - 3, "17 characters (ISO 3779)"])

    def ids(self, node):
        if self.ext29:
            sa = {"ecm": 0x10, "tcm": 0x18}[node]
            return 0x18DAF100 | sa, 0x18DA00F1 | (sa << 8), True
        return {"ecm": 0x7E8, "tcm": 0x7E9}[node], {"ecm": 0x7E0, "tcm": 0x7E1}[node], False

    def request(self, mode, pid=None, send=True):
        msg = bytes([mode]) + (bytes([pid]) if pid is not None else b"")
        ext = self.ext29
        cid = 0x18DB33F1 if ext else 0x7DF
        info = "Mode %02X%s" % (mode, (" PID %02X %s" % (pid, OBD_PID.get(pid, ""))) if pid is not None else "")
        if not send:
            d = bytes([len(msg)]) + msg + bytes([0x55] * (7 - len(msg)))
            return self.preview_can("tester", cid, d, ext=ext, info=info, dissect=lambda b, o: (IsoTp.pci_rows(b, o, d), IsoTp.app_rows(b, o, d, msg, self.obd_rows)))
        self.tp.send("tester", None, cid, 0x7E8, msg, info + " (functional)", "cmd", "OBD-II", app=self.obd_rows, ext=ext)
        tv = self.by["tester"].vars
        if ext != self.fault["ext"]:
            tv["Last result"] = "NO DATA"
            self.miss += 1
            if self.miss >= 3:
                self.miss = 0
                self.ext29 = not self.ext29
                tv["Protocol"] = "ISO 15765-4 CAN %s/500" % ("29" if self.ext29 else "11")
                self.by["tester"].addr = "0x18DB33F1" if self.ext29 else "0x7E0"
                self.by["ecm"].addr = "0x18DAF110" if self.ext29 else "0x7E8"
                self.by["tcm"].addr = "0x18DAF118" if self.ext29 else "0x7E9"
                self.log("Scan tool protocol search: no answer, switching to %s-bit identifiers" % ("29" if self.ext29 else "11"))
            return None
        self.miss = 0
        self.at(self.t + 0.003, self.answer, "ecm", mode, pid)
        if (mode == 1 and pid in (0x00, 0x01)) or mode in (3, 4, 7):
            self.at(self.t + 0.0045, self.answer, "tcm", mode, pid)
        return None

    def answer(self, node, mode, pid):
        tv = self.by["tester"].vars
        if node == "ecm" and (self.fault["off"] or not self.by["ecm"].on):
            tv["Last result"] = "NO DATA from the ECM"
            return
        rid, fcid, ext = self.ids(node)
        if mode == 1:
            if node == "tcm":
                d = self.bitmap(0, [0x01, 0x05]) if pid == 0 else bytes([0x00, 0x00, 0x00, 0x00])
            else:
                d = self.pid_data(pid)
            if d is None:
                msg, info = bytes([0x7F, 0x01, 0x12]), "PID not supported"
            else:
                msg, info = bytes([0x41, pid]) + d, "PID %02X: %s" % (pid, obd_decode(pid, d))
        elif mode in (3, 7):
            dl = sorted(self.confirmed if mode == 3 else self.pending) if node == "ecm" else []
            msg = bytes([0x40 + mode, len(dl)]) + b"".join(bytes(x) for x in dl)
            info = "%s DTCs: %s" % ("Stored" if mode == 3 else "Pending", ", ".join(dtc_str(*x) for x in dl) or "none")
        elif mode == 4:
            if node == "ecm":
                self.confirmed.clear()
                self.pending.clear()
                self.age.clear()
                self.by["ecm"].vars.update({"MIL": "off", "Pending": "-", "Confirmed": "-"})
            msg, info = bytes([0x44]), "DTCs and freeze frames cleared"
        elif mode == 9 and pid == 2 and node == "ecm":
            msg, info = bytes([0x49, 0x02, 0x01]) + b"1FTFW1ET5DFC10312", "VIN 1FTFW1ET5DFC10312"
        else:
            msg, info = bytes([0x7F, mode, 0x12]), "Not supported"
        self.tp.send(node, "tester", rid, fcid, msg, "%s: %s" % (node.upper(), info), "resp", "OBD-II", app=self.obd_rows, ext=ext, fc=(0, 0))
        if node == "ecm":
            tv["Last result"] = info

    def tpls(self):
        return [Tpl("Mode 01 current data", [P("pid", "PID", 0x0C, opts=sorted(OBD_PID.keys()), fmt=lambda v: "%02X %s" % (v, OBD_PID[v]))],
                    lambda s, v, send: self.request(1, v["pid"], send), "Live data. Decode with the J1979 formula shown in the tree."),
                Tpl("Mode 03 stored DTCs", [], lambda s, v, send: self.request(3, None, send), "Confirmed trouble codes, two bytes each."),
                Tpl("Mode 07 pending DTCs", [], lambda s, v, send: self.request(7, None, send), "Codes detected in the current or last drive cycle."),
                Tpl("Mode 04 clear DTCs", [], lambda s, v, send: self.request(4, None, send), "Clears codes and freeze frames, resets monitors, turns off the MIL."),
                Tpl("Mode 09 PID 02 VIN", [], lambda s, v, send: self.request(9, 2, send), "17-character VIN in a multi-frame response.")]


# ======================================================= Automotive Ethernet
def ptp_hdr(b, mtype, seq, length, port_id, interval=-3, two_step=True):
    b.u8("transportSpecific | messageType", 0x10 | mtype, "0x%02X: transportSpecific 1 (802.1AS), %s" % (0x10 | mtype, {0: "Sync", 8: "Follow_Up", 2: "Pdelay_Req", 3: "Pdelay_Resp"}.get(mtype, "")), "")
    b.u8("versionPTP", 2, None, "")
    b.u16("messageLength", length, None, "")
    b.u8("domainNumber", 0, None, "gPTP uses domain 0")
    b.u8("reserved", 0, None, "")
    b.u16("flags", 0x0208 if two_step else 0x0008, None, "twoStepFlag, ptpTimescale")
    b.raw("correctionField", bytes(8), "0", "Residence and link delays accumulated by bridges (scaled ns)")
    b.raw("reserved", bytes(4), None, "")
    b.raw("sourcePortIdentity", port_id, port_id[:8].hex(":") + " port %d" % (port_id[8] << 8 | port_id[9]), "Clock identity (EUI-64) + port number")
    b.u16("sequenceId", seq, None, "")
    b.u8("controlField", {0: 0, 8: 2}.get(mtype, 5), None, "")
    b.u8("logMessageInterval", interval & 0xFF, "%d (2^%d s = %g ms)" % (interval, interval, 1000 * 2.0 ** interval), "")


class AutoEth(IpNet):
    key, name, cat = "auto_eth", "Automotive Ethernet", "auto"
    blurb = "High-bandwidth vehicle systems"
    phy = "t1"
    link_rate = 100e6
    nets = [("TRX", "100BASE-T1 single pair (PAM-3, full duplex)")]
    lines = ["M"]
    medium = "100BASE-T1 single unshielded pair per link, zonal architecture: central compute, automotive switch, front camera, zone controller, DoIP test port"
    faults = [("phy", "Camera PHY and switch port both SLAVE", "100BASE-T1 needs one MASTER per link (it sets the clock): two slaves never train, the link stays down."),
              ("svc", "Camera application not running", "No SOME/IP-SD OfferService for the camera service: the central computer cannot subscribe and gets no object lists."),
              ("doip", "Tester uses an unregistered source address", "DoIP routing activation is refused (response code 0x00: unknown source address)."),
              ("gptp", "gPTP grandmaster lost", "802.1AS Sync / Follow_Up stop: time-sensitive data loses its common time base.")]
    spec = [("Physical", "IEEE 802.3bw 100BASE-T1 / 802.3bp 1000BASE-T1: one unshielded twisted pair, full duplex with echo cancellation, MASTER/SLAVE, 15 m"),
            ("Coding", "100BASE-T1: 4B/3B, 3B2T, PAM-3 at 66.67 MBd"), ("Middleware", "SOME/IP (AUTOSAR): service-oriented RPC and events; SOME/IP-SD on UDP 30490 for discovery"),
            ("Diagnostics", "DoIP (ISO 13400-2) on UDP/TCP 13400 carrying UDS"), ("Time / TSN", "gPTP (IEEE 802.1AS), AVB / TSN shapers for audio, video and control"),
            ("Security", "MACsec, IPsec or TLS; VLANs separate domains")]
    frame = [["SOME/IP header", ("Service ID", 16), ("Method / Event ID", 16), ("Length", 32), ("Client ID", 16), ("Session ID", 16), ("Proto ver", 8), ("Iface ver", 8),
              ("Msg type", 8), ("Return code", 8)], ["DoIP header", ("Version 0x02", 8), ("Inverse 0xFD", 8), ("Payload type", 16), ("Length", 32)]]
    about = ("Cameras, radars and central computers need far more than CAN's megabit, so cars now run Ethernet - over a single unshielded pair with "
             "100BASE-T1 or 1000BASE-T1 PHYs designed for the automotive environment. On top run SOME/IP services that are discovered at start-up, "
             "DoIP for diagnostics (UDS over TCP) and gPTP, which gives every ECU the same clock.")
    guide = ["Watch SOME/IP-SD OfferService, SubscribeEventgroup and SubscribeEventgroupAck at start-up.",
             "Select a camera NOTIFICATION: SOME/IP header fields in the tree.",
             "COMPOSE a DoIP diagnostic request: TCP handshake, routing activation, then UDS inside a diagnostic message.",
             "SCOPE: PAM-3, three signal levels on one pair.",
             "Set both PHYs to SLAVE and see the camera disappear from the network."]

    def setup(self):
        hosts = [("hpc", "CENTRAL COMPUTE", "ecu", 40, 40, "10.0.0.1", "02:00:00:00:00:01"), ("cam", "FRONT CAMERA", "camera", 700, 40, "10.0.0.20", "02:00:00:00:00:20"),
                 ("zone", "ZONE CONTROLLER FL", "gw", 40, 290, "10.0.0.30", "02:00:00:00:00:30", "DoIP entity 0x1001"),
                 ("dlc", "DoIP TESTER", "tool", 700, 290, "10.0.0.99", "02:00:00:00:00:99", "SA 0x0E80")]
        self.star(hosts, sw=("sw", "AUTOMOTIVE SWITCH", 380, 160), style="t1", conn="dt")
        self.user = "dlc"
        self.sess = 0
        self.seq = 0
        self.by["cam"].vars.update({"Link": "UP (MASTER)", "Service 0x1234": "offered"})
        self.by["hpc"].vars.update({"Subscribed": "no", "gPTP offset": "-", "Objects": 0})
        self.by["dlc"].vars.update({"Routing": "not activated", "Last response": "-"})
        self.routing = False
        self._c = None
        self.at(0.005, self.announce)
        self.at(0.01, self.sd_offer)
        self.every(1.0, self.sd_offer, 1.0)
        self.every(0.033, self.objlist, 0.1)
        self.every(0.125, self.gptp, 0.02)

    def someip(self, svc, mid, mtype, payload, client=0x0001, rc=0, title=None):
        if svc == 0xFFFF:
            client, sess = 0, 1
        else:
            self.sess = (self.sess % 0xFFFF) + 1
            sess = self.sess
        pl = payload if isinstance(payload, Pdu) else Pdu(payload, [[1, "Payload: %s" % bytes(payload).hex(" ").upper(), 0, len(payload), "Serialized arguments / event data"]] if payload else [])
        b = Bld(title or "SOME/IP", "Scalable service-Oriented MiddlewarE over IP (AUTOSAR)")
        b.u16("Service ID", svc, "0x%04X%s" % (svc, " (Service Discovery)" if svc == 0xFFFF else ""), "")
        b.u16("Method/Event ID", mid, "0x%04X %s" % (mid, "(event / notification)" if mid & 0x8000 else "(method)"), "Bit 15 set = event")
        b.u32("Length", 8 + len(pl.b), None, "Bytes from Client ID to the end of the payload")
        b.u16("Client ID", client, "0x%04X" % client, "")
        b.u16("Session ID", sess, None, "")
        b.u8("Protocol version", 1, None, "")
        b.u8("Interface version", 1, None, "")
        b.u8("Message type", mtype, "0x%02X %s" % (mtype, {0: "REQUEST", 1: "REQUEST_NO_RETURN", 2: "NOTIFICATION", 0x80: "RESPONSE", 0x81: "ERROR"}.get(mtype, "")), "")
        b.u8("Return code", rc, "0x%02X %s" % (rc, "E_OK" if rc == 0 else "E_NOT_OK"), "")
        b.sub(pl)
        return b.done()

    def sd(self, entries, opt=None):
        b = Bld()
        b.layer("SOME/IP-SD", "Service Discovery: entries array + options array")
        b.u8("Flags", 0xC0, "0xC0 (reboot, unicast supported)", "")
        b.raw("Reserved", bytes(3), None, "")
        b.u32("Length of entries array", 16 * len(entries), None, "")
        for e, txt in entries:
            b.raw("Entry", e, txt, "16 bytes: type, option indexes and counts, service, instance, major version, TTL, minor version or eventgroup")
        ob = b""
        if opt:
            ip, port = opt
            ob = struct.pack(">HBB", 9, 0x04, 0) + bytes(int(x) for x in ip.split(".")) + bytes([0, 0x11]) + struct.pack(">H", port)
        b.u32("Length of options array", len(ob), None, "")
        if ob:
            b.raw("IPv4 endpoint option", ob, "%s UDP %d" % opt, "Where the service (or the subscriber) listens")
        return b.done()

    def sd_offer(self):
        if self.fault["svc"] or not self.by["cam"].on or self.fault["phy"]:
            return
        ent = struct.pack(">BBBBHHB", 0x01, 0, 0, 0x10, 0x1234, 0x0001, 1) + (3).to_bytes(3, "big") + struct.pack(">I", 0)
        p = self.someip(0xFFFF, 0x8100, 0x02, self.sd([(ent, "OfferService 0x1234 instance 1 v1.0 TTL 3 s")], ("10.0.0.20", 30501)))
        self.lan.udp("cam", None, 30490, 30490, p, "SOME/IP-SD OfferService 0x1234 (camera objects) TTL 3 s", "SOME/IP-SD", "bcast", dip="224.244.224.245", dmac="01:00:5e:74:e0:f5")
        if self.by["hpc"].vars["Subscribed"] == "no":
            self.at(self.t + 0.002, self.subscribe)

    def subscribe(self):
        ent = struct.pack(">BBBBHHB", 0x06, 0, 0, 0x10, 0x1234, 0x0001, 1) + (3).to_bytes(3, "big") + struct.pack(">HH", 0, 0x0001)
        self.lan.udp("hpc", "cam", 30490, 30490, self.someip(0xFFFF, 0x8100, 0x02, self.sd([(ent, "SubscribeEventgroup 0x1234/1 eventgroup 1 TTL 3 s")], ("10.0.0.1", 30501))),
                     "SOME/IP-SD SubscribeEventgroup 0x1234 eventgroup 1", "SOME/IP-SD", "cmd")
        ack = struct.pack(">BBBBHHB", 0x07, 0, 0, 0x00, 0x1234, 0x0001, 1) + (3).to_bytes(3, "big") + struct.pack(">HH", 0, 0x0001)
        self.at(self.t + 0.001, lambda: self.lan.udp("cam", "hpc", 30490, 30490, self.someip(0xFFFF, 0x8100, 0x02, self.sd([(ack, "SubscribeEventgroupAck 0x1234/1")])),
                                                     "SOME/IP-SD SubscribeEventgroupAck", "SOME/IP-SD", "resp"))
        self.by["hpc"].vars["Subscribed"] = "yes (eventgroup 1)"

    def objlist(self):
        h = self.by["hpc"]
        if self.fault["svc"] or self.fault["phy"] or not self.by["cam"].on:
            h.vars["Subscribed"] = "no"
            return
        if h.vars["Subscribed"] == "no":
            return
        n = 3
        objs = Bld()
        objs.u8("Number of objects", n, None, "")
        for i in range(n):
            x = 1200 + 300 * i - int(40 * math.sin(self.t + i))
            objs.raw("Object %d" % (i + 1), struct.pack(">hhh", x, -40 + 90 * i, 0), "x %.2f m, y %.2f m, class car" % (x / 100.0, (-40 + 90 * i) / 100.0), "")
        h.vars["Objects"] = n
        self.lan.udp("cam", "hpc", 30501, 30501, self.someip(0x1234, 0x8001, 0x02, objs.done()), "SOME/IP NOTIFICATION 0x1234.0x8001 ObjectList (%d objects)" % n, "SOME/IP", "data")

    def gptp(self):
        if self.fault["gptp"]:
            self.by["hpc"].vars["gPTP offset"] = "UNSYNCHRONISED (no grandmaster)"
            return
        self.seq = (self.seq + 1) & 0xFFFF
        pid = bytes.fromhex("020000fffe000030") + b"\x00\x01"
        b = Bld("gPTP Sync (IEEE 802.1AS)", "Two-step: the precise send time follows in Follow_Up")
        ptp_hdr(b, 0, self.seq, 44, pid)
        b.raw("reserved (originTimestamp)", bytes(10), None, "")
        self.lan.l2("zone", None, 0x88F7, b.done(), "gPTP Sync seq %d (grandmaster: zone controller)" % self.seq, "gPTP", "sync", dmac="01:80:c2:00:00:0e")
        f = Bld("gPTP Follow_Up (IEEE 802.1AS)", "")
        ptp_hdr(f, 8, self.seq, 76, pid)
        ns = int((self.t % 1) * 1e9)
        f.raw("preciseOriginTimestamp", struct.pack(">HII", 0, int(self.t), ns), "%d.%09d s" % (int(self.t), ns), "When the Sync actually left the grandmaster port")
        f.raw("Follow_Up information TLV", bytes(32), None, "cumulativeScaledRateOffset, gmTimeBaseIndicator...")
        self.lan.l2("zone", None, 0x88F7, f.done(), "gPTP Follow_Up seq %d" % self.seq, "gPTP", "sync", dmac="01:80:c2:00:00:0e")
        self.by["hpc"].vars["gPTP offset"] = "%+d ns" % int(8 + 6 * math.sin(self.t))

    def doip(self, ptype, fields, title, uds=None):
        b = Bld("DoIP (ISO 13400-2): %s" % title, "Diagnostics over IP")
        b.u8("Protocol version", 0x02, "0x02 (ISO 13400-2:2012)", "")
        b.u8("Inverse protocol version", 0xFD, None, "")
        b.u16("Payload type", ptype, "0x%04X %s" % (ptype, {4: "Vehicle announcement", 5: "Routing activation request", 6: "Routing activation response",
                                                             0x8001: "Diagnostic message", 0x8002: "Diagnostic message positive ACK"}.get(ptype, "")), "")
        n = sum(len(v) for _, v, _ in fields) + (len(uds) if uds else 0)
        b.u32("Payload length", n, None, "")
        for lab, v, txt in fields:
            b.raw(lab, v, txt, "")
        if uds:
            k = len(b.b)
            b.raw("User data (UDS)", uds, None, "")
            tmp = Bld()
            uds_dissect(tmp, 0, uds)
            for r in tmp.rows:
                b.rows.append([r[0] + 1, r[1], None if r[2] is None else r[2] + k, r[3], r[4]])
        return b.done()

    def announce(self):
        p = self.doip(0x0004, [("VIN", b"WAUZZZ8V0RA012345", "WAUZZZ8V0RA012345"), ("Logical address", b"\x10\x01", "0x1001"), ("EID", bytes.fromhex("020000000030"), None),
                               ("GID", bytes.fromhex("020000000030"), None), ("Further action", b"\x00", "0x00 none required")], "vehicle announcement")
        self.lan.udp("zone", None, 13400, 13400, p, "DoIP vehicle announcement: VIN WAUZZZ8V0RA012345, entity 0x1001", "DoIP", "bcast", dip="255.255.255.255")

    def diag(self, did, send=True):
        req = bytes([0x22, did >> 8, did & 255])
        if not send:
            return Frame(self.t, 1e-5, "dlc", "zone", "DoIP", "preview", pdu=self.doip(0x8001, [("Source address", b"\x0e\x80", "0x0E80"), ("Target address", b"\x10\x01", "0x1001")],
                                                                                         "diagnostic message", uds=req))
        if self._c is None or not self._c.open:
            self._c = self.tcp("dlc", "zone", 50013, 13400, "DoIP")
            self._c.connect(on_open=lambda: self.activate(did))
            return None
        if not self.routing:
            self.activate(did)
            return None
        c = self._c
        c.send("dlc", self.doip(0x8001, [("Source address", b"\x0e\x80", "0x0E80"), ("Target address", b"\x10\x01", "0x1001")], "diagnostic message", uds=req),
               "DoIP diagnostic message: UDS ReadDataByIdentifier 0x%04X" % did, "DoIP", "cmd", auto_ack=False)
        self.at(self.t + 0.001, lambda: c.send("zone", self.doip(0x8002, [("Source address", b"\x10\x01", "0x1001"), ("Target address", b"\x0e\x80", "0x0E80"),
                                                                           ("ACK code", b"\x00", "0x00 routing confirmation")], "diagnostic message ACK"),
                                               "DoIP diagnostic message positive ACK", "DoIP", "ack", auto_ack=False))
        val = b"WAUZZZ8V0RA012345" if did == 0xF190 else DIDS.get(did, ("", b"?"))[1]
        rsp = bytes([0x62, did >> 8, did & 255]) + val

        def answer():
            c.send("zone", self.doip(0x8001, [("Source address", b"\x10\x01", "0x1001"), ("Target address", b"\x0e\x80", "0x0E80")], "diagnostic message", uds=rsp),
                   "DoIP diagnostic message: UDS positive response %s" % val.decode("latin-1"), "DoIP", "resp")
            self.by["dlc"].vars["Last response"] = "0x%04X = %s" % (did, val.decode("latin-1"))
        self.at(self.t + 0.004, answer)
        return None

    def activate(self, did=None):
        c = self._c
        sa = b"\x0e\x00" if self.fault["doip"] else b"\x0e\x80"
        c.send("dlc", self.doip(5, [("Source address", sa, "0x%s" % sa.hex().upper()), ("Activation type", b"\x00", "0x00 default"), ("Reserved", bytes(4), None)],
                                "routing activation request"), "DoIP routing activation request, SA 0x%s" % sa.hex().upper(), "DoIP", "cmd", auto_ack=False)
        code = 0x00 if self.fault["doip"] else 0x10
        ok = code == 0x10
        self.at(self.t + 0.002, lambda: c.send("zone", self.doip(6, [("Tester address", sa, "0x%s" % sa.hex().upper()), ("Entity address", b"\x10\x01", "0x1001"),
                                                                     ("Response code", bytes([code]), "0x%02X %s" % (code, "routing successfully activated" if ok else "denied: unknown source address")),
                                                                     ("Reserved", bytes(4), None)], "routing activation response"),
                                               "DoIP routing activation response 0x%02X %s" % (code, "SUCCESS" if ok else "DENIED (unknown source address)"), "DoIP", "resp" if ok else "err"))
        self.routing = ok
        self.by["dlc"].vars["Routing"] = "active" if ok else "DENIED (0x00)"
        if not ok:
            self.at(self.t + 0.004, lambda: c.close("zone") if c.open else None)
        if ok and did is not None:
            self.at(self.t + 0.004, self.diag, did)

    def on_fault(self, key, on):
        if key == "phy":
            self.by["cam"].vars["Link"] = "DOWN (both ends SLAVE)" if on else "UP (MASTER)"
            self.by["cam"].state = "LINK DOWN" if on else ""
        if key == "svc":
            self.by["cam"].vars["Service 0x1234"] = "NOT OFFERED" if on else "offered"
        if key == "doip":
            self.routing = False
            self.by["dlc"].vars["Routing"] = "not activated"

    def tpls(self):
        return [Tpl("DoIP: UDS ReadDataByIdentifier", [P("did", "DID", 0xF190, opts=[0xF190, 0xF18C, 0xF189], fmt=lambda v: "0x%04X %s" % (v, DIDS[v][0]))],
                    lambda s, v, send: self.diag(v["did"], send), "TCP 13400: routing activation first, then diagnostic messages carrying UDS from tester 0x0E80 to entity 0x1001."),
                Tpl("SOME/IP method call SetMode", [P("m", "Mode", 2, 0, 5)], lambda s, v, send: self._method(v, send), "Request / response method on the camera service.")]

    def _method(self, v, send):
        p = self.someip(0x1234, 0x0001, 0x00, bytes([v["m"]]))
        if not send:
            return Frame(self.t, 1e-5, "hpc", "cam", "SOME/IP", "preview", pdu=p)
        self.lan.udp("hpc", "cam", 30501, 30501, p, "SOME/IP REQUEST 0x1234.0x0001 SetMode(%d)" % v["m"], "SOME/IP", "cmd")
        if not (self.fault["phy"] or self.fault["svc"]):
            self.at(self.t + 0.0015, lambda: self.lan.udp("cam", "hpc", 30501, 30501, self.someip(0x1234, 0x0001, 0x80, b""), "SOME/IP RESPONSE 0x1234.0x0001 E_OK", "SOME/IP", "resp"))
        return None


# ========================================================== K-line protocols
class KLine(Scenario):
    """Scan tool and ECU on a K-line (ISO 9141-2 / ISO 14230 KWP2000)."""
    cat = "auto"
    phy, rate = "kline", 10400
    nets = [("K", "K-line (bidirectional, pin 7)"), ("L", "L-line (init only, pin 15)")]
    lines = ["B", "L"]
    proto_name = "K-line"
    layer_name = "K-line message"

    def mkk(self):
        t = self.node("tester", "SCAN TOOL", "tool", 60, 150, "0xF1", "K-line interface").at_right()
        e = self.node("ecu", "ENGINE ECU", "ecu", 680, 150, "0x10", "K-line").at_left()
        self.seg([t.port, e.port], "wire", net="K", label="K-line (pin 7) + L-line (pin 15), 510 Ω pull-up to 12 V", c0="j1962", c1="screw", col=(200, 170, 60), w=4)
        self.term(370, t.port[1], "510 Ω", True, "pullup", vert=True)
        self.user = "tester"
        e.vars.update({"RPM": 850.0, "Coolant C": 87, "Link": "not initialised"})
        e.ctl = [("RPM", "RPM", 600.0, 6000.0, 10.0, lambda v: "%.0f" % v)]
        self.linked = False
        self.last_msg = 0.0

    def byte_label(self, i, d):
        return "Data"

    def kpdu(self, data, title=None):
        b = Bld(title or self.layer_name, "")
        for i, x in enumerate(data):
            b.u8(self.byte_label(i, data), x, None, "")
        return b.done()

    def kframe(self, src, data, info, kind, err=None, title=None):
        return serial_frame(self, src, "ecu" if src == "tester" else "tester", self.proto_name, info, self.kpdu(data, title), 10400, 8, "N", 1, line="B", kind=kind, err=err,
                            extra=lambda w, sp: w.set("L", 0.0, 1))

    def kmsg(self, src, data, info, kind, err=None, title=None):
        return self.tx(self.kframe(src, data, info, kind, err, title), bus="k")

    def init_5baud(self, addr=0x33, baud=5):
        b = Bld("%d-baud initialisation" % baud, "The tester sends the ECU address at 5 bit/s (2 seconds) on K and L")
        b.u8("Address", addr, "0x%02X at %d baud" % (addr, baud), "0x33 = OBD (ISO 9141-2) functional address")
        bit = 1.0 / baud
        dur = 0.3 + 10 * bit + 0.1

        def wf(fr):
            w = Wire(bit=bit)
            w.set("B", 0.0, 1)
            w.set("L", 0.0, 1)
            w.uart("B", bytes([addr]), baud, 0.3, 8, "N", 1, labels=["ADDRESS 0x%02X @ %d baud" % (addr, baud)])
            w.uart("L", bytes([addr]), baud, 0.3, 8, "N", 1, labels=["ADDRESS (L-line)"])
            w.end(dur)
            return w
        return self.tx(Frame(self.t, dur, "tester", "ecu", self.proto_name, "%d-baud init: address 0x%02X" % (baud, addr), pdu=b.done(), kind="ctl", wirefn=wf, key="5-baud init"), bus="k")

    def cond(self, net):
        c = super().cond(net)
        if self.fault.get("no_pullup"):
            c["atten"] = 0.05
        return c


class ISO9141(KLine):
    key, name = "iso9141", "ISO 9141-2"
    blurb = "Older vehicle diagnostics"
    proto_name = "ISO 9141-2"
    layer_name = "ISO 9141-2 message"
    medium = "ISO 9141-2 K-line, 10400 bit/s 8N1: 5-baud init to address 0x33, keywords 08 08, OBD requests 68 6A F1, responses 48 6B 10"
    faults = [("init", "Tool sends the address at 10 baud", "The ECU only recognises the 5-baud address byte: no sync byte comes back."),
              ("keep", "Tool pauses more than 5 s between requests", "P3max expired: the ECU forgets the connection and a new 5-baud init is needed."),
              ("no_pullup", "K-line pull-up resistor missing", "The K-line is open collector: without the 510 Ω pull-up nothing drives it high."),
              ("cks", "ECU checksum wrong (noise)", "The last byte is the 8-bit sum of the message; the tool rejects the reply.")]
    spec = [("Standard", "ISO 9141-2 (CARB requirements), OBD-II on many 1996-2004 European and Asian cars"),
            ("Physical", "Single K-line (+ optional L-line), 12 V open collector, 510 Ω pull-up, 10.4 kbit/s"),
            ("Init", "5-baud address 0x33 -> sync 0x55 -> keywords 08 08 (or 94 94) -> tester sends ~KB2 -> ECU sends ~0x33 (0xCC)"),
            ("Message", "Header 68 6A F1 (request) / 48 6B 10 (response) + data + checksum (sum mod 256)"),
            ("Timing", "W1-W4 during init; P1 inter-byte (ECU), P2 25-50 ms response, P3 55 ms-5 s between messages, P4 inter-byte (tester)")]
    frame = [["Request", ("68", 8), ("6A", 8), ("F1 (tester)", 8), ("Mode", 8), ("PID", 8), ("Checksum", 8)]]
    about = ("Before CAN, OBD-II on many cars used ISO 9141-2: one K-line shared by the tool and the ECU. The connection is opened with a deliberately "
             "slow 5-baud transmission of the address; the ECU answers with a 0x55 sync byte at full speed (so the tool can measure its baud rate) "
             "and two keyword bytes. Requests then carry a 3-byte header and a simple checksum, and must keep coming at least every 5 s.")
    guide = ["Watch the 2-second 5-baud init in LOGIC (press FIT), then the 0x55 sync and keywords.",
             "Select a request: 68 6A F1 01 0C + checksum. Add the bytes yourself to check it.",
             "Pull the 510 Ω pull-up (click it on the panel) and see the line die on the SCOPE.",
             "Inject the 5 s pause and watch the ECU drop the link and the tool re-initialise."]

    def byte_label(self, i, d):
        if i == len(d) - 1 and len(d) > 3:
            return "Checksum"
        return ["Header 1 (priority/type)", "Header 2 (target)", "Source", "Mode", "PID"][i] if i < 5 else "Data"

    def build(self):
        self.mkk()
        self.initing = False
        self.every(0.5, self.cycle, 0.1)

    def cycle(self):
        e = self.by["ecu"]
        if not self.by["tester"].on or self.fault["no_pullup"]:
            self.linked = False
            e.vars["Link"] = "not initialised"
            return
        if not self.linked:
            if not self.initing:
                self.initing = True
                fr = self.init_5baud(0x33, 10 if self.fault["init"] else 5)
                self.at(fr.t + fr.dur + 0.03, self.sync)
            return
        if self.fault["keep"]:
            if self.t - self.last_msg > 5.0:
                self.linked = False
                e.vars["Link"] = "dropped (P3max)"
                self.log("P3max (5 s) expired: ECU dropped the connection")
            return
        self.req(0x01, 0x0C if int(self.t * 2) % 3 else 0x05)

    def sync(self):
        self.initing = False
        if self.fault["init"] or not self.by["ecu"].on:
            self.log("Address not recognised (not sent at 5 baud): no sync byte")
            return
        self.kmsg("ecu", bytes([0x55]), "Sync byte 0x55 (tool measures the baud rate)", "ctl", title="Sync")
        self.at(self.t + 0.012, lambda: self.kmsg("ecu", bytes([0x08, 0x08]), "Keywords KB1 KB2 = 08 08 (ISO 9141-2)", "ctl", title="Keywords"))
        self.at(self.t + 0.045, lambda: self.kmsg("tester", bytes([0xF7]), "Tester sends ~KB2 = 0xF7", "ctl", title="Inverted KB2"))
        self.at(self.t + 0.080, self.linkup)

    def linkup(self):
        self.kmsg("ecu", bytes([0xCC]), "ECU sends ~address = 0xCC: link established", "ctl", title="Inverted address")
        self.linked = True
        self.last_msg = self.t
        self.by["ecu"].vars["Link"] = "established"

    def req(self, mode, pid, send=True):
        body = bytes([0x68, 0x6A, 0xF1, mode, pid])
        msg = body + bytes([sum8(body)])
        if not send:
            return self.kframe("tester", msg, "Request mode %02X PID %02X" % (mode, pid), "cmd")
        if not self.linked:
            self.log("Request ignored: no link yet (5-baud init in progress)")
            return None
        self.kmsg("tester", msg, "Request mode %02X PID %02X %s" % (mode, pid, OBD_PID.get(pid, "")), "cmd")
        self.last_msg = self.t
        e = self.by["ecu"]
        rpm = int(e.vars["RPM"] * 4)
        data = {0x0C: bytes([rpm >> 8, rpm & 255]), 0x05: bytes([int(e.vars["Coolant C"]) + 40]), 0x0D: bytes([0])}.get(pid, bytes([0]))
        rb = bytes([0x48, 0x6B, 0x10, 0x40 + mode, pid]) + data
        rmsg = rb + bytes([(sum8(rb) + (1 if self.fault["cks"] else 0)) & 255])
        err = "Checksum mismatch: the tool discards the response" if self.fault["cks"] else None
        self.at(self.t + 0.035, lambda: self.kmsg("ecu", rmsg, "Response mode %02X PID %02X: %s" % (0x40 + mode, pid, obd_decode(pid, data)), "resp", err))
        return None

    def on_fault(self, key, on):
        if key in ("no_pullup", "init") and on:
            self.linked = False

    def tpls(self):
        return [Tpl("OBD request", [P("pid", "Mode 01 PID", 0x0C, opts=[0x0C, 0x05, 0x0D], fmt=lambda v: "%02X %s" % (v, OBD_PID[v]))], lambda s, v, send: self.req(1, v["pid"], send),
                    "Only answered once the 5-baud init has completed.")]


KWP_SID = {0x81: "StartCommunication", 0x82: "StopCommunication", 0x10: "StartDiagnosticSession", 0x1A: "ReadEcuIdentification", 0x18: "ReadDTCByStatus",
           0x14: "ClearDiagnosticInformation", 0x21: "ReadDataByLocalIdentifier", 0x27: "SecurityAccess", 0x3E: "TesterPresent"}


class KWP2000(KLine):
    key, name = "kwp2000", "KWP2000 (ISO 14230)"
    blurb = "Older vehicle diagnostics"
    proto_name = "KWP2000"
    layer_name = "KWP2000 message (ISO 14230-2)"
    medium = "ISO 14230 KWP2000 on K-line, 10400 bit/s: fast init (25 ms wake-up) + StartCommunication, physical addressing tester 0xF1 -> ECU 0x10"
    faults = [("p2", "ECU answers after 80 ms (P2max 50 ms)", "The tester stops waiting before the reply arrives and reports a timeout."),
              ("tp", "Tester stops sending TesterPresent", "The diagnostic session times out (P3max 5 s); the ECU drops the communication."),
              ("fmt", "Tester sends a wrong length in the format byte", "The ECU discards the malformed message: no response at all.")]
    spec = [("Standard", "ISO 14230-1/2/3 (KWP2000 on K-line), ISO 14230-4 (emissions OBD); KWP on CAN = ISO 15765-3"),
            ("Init", "Fast init: 25 ms low + 25 ms high wake-up pattern, then StartCommunication (0x81); 5-baud init also allowed"),
            ("Header", "Format byte (address mode A1 A0 + length L5..L0), target, source, [length byte], data, checksum"),
            ("Services", "0x10 session, 0x1A identification, 0x18 DTCs, 0x21 local identifier, 0x27 security, 0x3E tester present"),
            ("Negative", "0x7F + service + code (0x11 not supported, 0x12 sub-function, 0x22 conditions, 0x78 pending)"),
            ("Successor", "UDS (ISO 14229): many service numbers were kept")]
    frame = [["KWP message", ("Format (A1 A0 L5..L0)", 8), ("Target", 8), ("Source", 8), ("Service", 8), ("Data", "n x 8"), ("Checksum", 8)]]
    about = ("KWP2000 is the diagnostic protocol between ISO 9141 and UDS. A fast-init wake-up pattern on the K-line replaces the slow 5-baud "
             "address; the first message is StartCommunication. Every message carries a format byte with the addressing mode and length, target and "
             "source addresses, the service and a checksum. Many UDS service numbers come straight from KWP2000.")
    guide = ["In LOGIC, find the 25 ms low / 25 ms high wake-up pattern, then StartCommunication (C1 33 F1 81).",
             "Decode a format byte: 0x80 + length = physical addressing with target and source bytes.",
             "COMPOSE ReadEcuIdentification 0x1A 0x90 (VIN).",
             "Inject the P2 timeout and watch the late response."]

    def byte_label(self, i, d):
        if i == len(d) - 1:
            return "Checksum"
        return ["Format", "Target", "Source", "Service"][i] if i < 4 else "Data"

    def build(self):
        self.mkk()
        self.e_tp = 0.0
        self.at(0.05, self.fast_init)
        self.every(2.0, self.tester_present, 2.5)
        self.every(0.5, self.p3, 0.3)

    def fast_init(self):
        b = Bld("KWP2000 fast initialisation", "TiniL: 25 ms low, then 25 ms high (wake-up pattern) on K")

        def wf(fr):
            w = Wire(bit=1 / 10400.0)
            w.set("B", 0.0, 1)
            w.set("L", 0.0, 1)
            w.set("B", 0.002, 0)
            w.set("L", 0.002, 0)
            w.set("B", 0.027, 1)
            w.set("L", 0.027, 1)
            w.seg(0.002, 0.027, "TiniL 25 ms low", 8, 1)
            w.seg(0.027, 0.052, "25 ms high", 7, 1)
            w.end(0.052)
            return w
        self.tx(Frame(self.t, 0.052, "tester", "ecu", "KWP2000", "Fast init wake-up pattern (25 ms + 25 ms)", pdu=b.done(), kind="ctl", wirefn=wf, key="fast init"), bus="k")
        self.at(self.t + 0.053, lambda: self.service(bytes([0x81])))

    def msg(self, src, svc_data, bad_len=False):
        tgt, srcb = (0x10, 0xF1) if src == "tester" else (0xF1, 0x10)
        n = len(svc_data)
        fmt = 0x80 | ((n + 2) if bad_len else n)
        body = bytes([fmt, tgt, srcb]) + svc_data
        return body + bytes([sum8(body)])

    def service(self, sd, send=True):
        bad = self.fault["fmt"] and sd[0] != 0x81
        m = self.msg("tester", sd, bad)
        sid = sd[0]
        info = "%s %s" % (KWP_SID.get(sid, "0x%02X" % sid), sd[1:].hex(" ").upper())
        if not send:
            return self.kframe("tester", m, info, "cmd")
        self.kmsg("tester", m, info, "cmd", err="Format byte says %d data bytes, %d sent" % (len(sd) + 2, len(sd)) if bad else None)
        if bad:
            return None
        e = self.by["ecu"]
        if sid == 0x81:
            rsp, txt = bytes([0xC1, 0xEF, 0x8F]), "StartCommunication positive: key bytes EF 8F"
            self.linked = True
            self.e_tp = self.t
            e.vars["Link"] = "communication started"
        elif not self.linked:
            return None
        elif sid == 0x1A:
            rsp, txt = bytes([0x5A, sd[1] if len(sd) > 1 else 0x90]) + b"WDB2030461A123456", "ReadEcuIdentification: VIN WDB2030461A123456"
        elif sid == 0x21:
            rpm = int(e.vars["RPM"])
            rsp, txt = bytes([0x61, sd[1] if len(sd) > 1 else 1]) + struct.pack(">H", rpm), "ReadDataByLocalIdentifier %02X: %d rpm" % (sd[1] if len(sd) > 1 else 1, rpm)
        elif sid == 0x10:
            rsp, txt = bytes([0x50, sd[1] if len(sd) > 1 else 0x81]), "Diagnostic session 0x%02X started" % (sd[1] if len(sd) > 1 else 0x81)
        elif sid == 0x3E:
            rsp, txt = bytes([0x7E]), "TesterPresent positive"
        elif sid == 0x18:
            rsp, txt = bytes([0x58, 0x01, 0x03, 0x01, 0xE0]), "1 DTC: P0301 (status 0xE0)"
        elif sid == 0x27:
            if len(sd) > 1 and sd[1] % 2 == 1:
                rsp, txt = bytes([0x67, sd[1], 0x5A, 0x3C]), "SecurityAccess seed 5A 3C"
            else:
                rsp, txt = bytes([0x67, sd[1] if len(sd) > 1 else 2, 0x34]), "SecurityAccess granted (0x34)"
        elif sid == 0x82:
            rsp, txt = bytes([0xC2]), "StopCommunication positive"
            self.linked = False
            e.vars["Link"] = "stopped"
        else:
            rsp, txt = bytes([0x7F, sid, 0x11]), "Negative response: serviceNotSupported"
        self.e_tp = self.t
        late = self.fault["p2"]
        rm = self.msg("ecu", rsp)
        err = "Late: arrived after P2max (50 ms), the tester already reported a timeout" if late else None
        self.at(self.t + (0.08 if late else 0.03), lambda: self.kmsg("ecu", rm, txt, "resp" if rsp[0] != 0x7F else "err", err))
        return None

    def tester_present(self):
        if self.linked and not self.fault["tp"]:
            self.service(bytes([0x3E]))

    def p3(self):
        if self.linked and self.t - self.e_tp > 5.0:
            self.linked = False
            self.by["ecu"].vars["Link"] = "timed out (P3max 5 s)"
            self.log("P3max expired: ECU ended the communication; tester will fast-init again")
            self.at(self.t + 0.3, self.fast_init)

    def tpls(self):
        return [Tpl("KWP service", [P("svc", "Service", 0x1A, opts=[0x10, 0x1A, 0x18, 0x21, 0x3E, 0x27, 0x82], fmt=lambda v: "0x%02X %s" % (v, KWP_SID[v])), P("p", "Parameter", 0x90, 0, 255)],
                    lambda s, v, send: self.service(bytes([v["svc"], v["p"]]) if v["svc"] not in (0x3E, 0x82) else bytes([v["svc"]]), send),
                    "0x1A 0x90 VIN, 0x21 0x01 local identifier 1, 0x10 0x85 programming session, 0x27 0x01 seed.")]


# =============================================================== SAE J1850
class J1850(Scenario):
    key, name, cat = "j1850", "SAE J1850", "auto"
    blurb = "Legacy automotive networking"
    phy, rate = "vpw", 10400
    medium = "SAE J1850 VPW (GM Class 2 style): single wire, 7 V active, 10.4 kbit/s variable pulse width, CRC-8; PCM, BCM, instrument cluster, radio, scan tool"
    nets = [("BUS", "J1850 VPW bus (pin 2)")]
    lines = ["B"]
    faults = [("noise", "Ignition noise on the bus", "Pulse widths are mis-measured: CRC errors."),
              ("arb", "Radio and BCM start transmitting together", "Bitwise arbitration: the frame whose bits hold the bus dominant longer (lower value) wins; the loser retries."),
              ("short", "Bus shorted to battery", "The bus is stuck active: no communication.")]
    spec = [("Standard", "SAE J1850 (1994): VPW 10.4 kbit/s single wire (GM, Chrysler) and PWM 41.6 kbit/s differential (Ford)"),
            ("VPW symbols", "Active (high) and passive (low) alternate; '0' = 64 us passive or 128 us active, '1' = 128 us passive or 64 us active"),
            ("Framing", "SOF 200 us active, EOD 200 us passive, EOF 280 us passive, optional in-frame response (IFR)"),
            ("Header", "1 or 3 bytes: priority (3 bits), H, K (IFR), Y (addressing), type; target; source"),
            ("CRC", "CRC-8 SAE J1850 (poly 0x1D, init 0xFF, final XOR 0xFF)"), ("Arbitration", "Bitwise; a '0' dominates, so lower header values win")]
    frame = [["J1850 VPW frame", ("SOF", "200 us"), ("Header", 8), ("Target", 8), ("Source", 8), ("Data 0-8 B", "n x 8"), ("CRC-8", 8), ("EOD", "200 us"), ("IFR", "opt"), ("EOF", "280 us")]]
    about = ("J1850 VPW encodes bits as pulse durations on one wire that alternates between active (7 V) and passive levels: whether a symbol means "
             "0 or 1 depends on its length and on the level. A 0 always holds the bus dominant longer, so nodes can arbitrate bit by bit, like CAN. "
             "GM's Class 2 network and Chrysler's SCI successors used it until CAN replaced it around 2008.")
    guide = ["In LOGIC, measure symbol widths: 64 us and 128 us, plus the 200 us SOF.",
             "Decode a header byte in the tree: priority, H, K, Y and type bits.",
             "Check the CRC-8 with the Reference tab's CRC calculator.",
             "Inject the arbitration fault and see which frame wins."]

    def build(self):
        nodes = [self.node("pcm", "PCM", "ecu", 30, 40, "0x10"), self.node("bcm", "BCM", "ecu", 250, 40, "0x40"), self.node("ipc", "INSTRUMENTS", "display", 470, 40, "0x60"),
                 self.node("rad", "RADIO", "radio", 690, 40, "0x80"), self.node("tool", "SCAN TOOL", "tool", 380, 290, "0xF1")]
        nodes[4].at_top()
        self.trunk(190, 30, 860, nodes, "wire", net="BUS", label="J1850 VPW single wire (DLC pin 2)", drop_conn="dt")
        self.user = "tool"
        self.by["pcm"].vars.update({"RPM": 900.0})
        self.by["pcm"].ctl = [("RPM", "RPM", 600.0, 6000.0, 10.0, lambda v: "%.0f" % v)]
        self.by["ipc"].vars.update({"Tacho": 0, "Doors": "-"})
        self.every(0.1, self.pcm_tx, 0.02)
        self.every(0.5, lambda: self.send("bcm", 0x88, 0xFF, bytes([0x40, 0x00]), "BCM: doors closed, lights off"), 0.13)
        self.every(1.0, self.radio, 0.31)

    def pcm_tx(self):
        rpm = self.by["pcm"].vars["RPM"]
        self.send("pcm", 0x28, 0xFF, bytes([0x0C]) + struct.pack(">H", int(rpm * 4)), "PCM: engine speed %.0f rpm" % rpm)
        self.by["ipc"].vars["Tacho"] = int(rpm)

    def vpw(self, data):
        w = Wire(bit=64e-6)
        w.set("B", 0.0, 0)
        t = 0.1e-3
        w.set("B", t, 1)
        w.seg(t, t + 200e-6, "SOF", 7, 1)
        t += 200e-6
        active = False
        for i, byte in enumerate(data):
            t0 = t
            for k in range(8):
                bit = (byte >> (7 - k)) & 1
                dur = (64e-6 if bit else 128e-6) if active else (128e-6 if bit else 64e-6)
                w.set("B", t, 1 if active else 0)
                t += dur
                active = not active
            w.seg(t0, t, "%02X" % byte, i % 2, 0)
            w.seg(t0, t, ["HEADER", "TARGET", "SOURCE"][i] if i < 3 else ("CRC" if i == len(data) - 1 else "DATA"), 2 if i < 3 else (5 if i == len(data) - 1 else 0), 1)
        w.set("B", t, 0)
        w.seg(t, t + 200e-6, "EOD", 7, 1)
        w.seg(t + 200e-6, t + 280e-6, "EOF", 7, 1)
        w.end(t + 280e-6)
        return w

    def mk(self, src, hdr, tgt, data):
        body = bytes([hdr, tgt, int(self.by[src].addr, 16)]) + data
        c = crcn("CRC-8/SAE-J1850", body)
        b = Bld("SAE J1850 VPW frame", "")
        b.u8("Header", hdr, "0x%02X" % hdr, "3-byte header form: priority/type byte, target, source")
        b.bitf(0, 1, 8, 5, 3, "Priority", "%d (0 = highest)" % (hdr >> 5))
        b.bitf(0, 1, 8, 4, 1, "H (header type)", "%s" % ("1-byte header" if hdr & 0x10 else "3-byte header"))
        b.bitf(0, 1, 8, 3, 1, "K (in-frame response)", "IFR %s" % ("not allowed" if hdr & 8 else "required"))
        b.bitf(0, 1, 8, 2, 1, "Y (addressing)", "physical" if hdr & 4 else "functional")
        b.bitf(0, 1, 8, 0, 2, "Message type", "%d" % (hdr & 3))
        b.u8("Target", tgt, "0x%02X%s" % (tgt, {0xFF: " (all nodes)", 0x6A: " (OBD functional request)", 0x6B: " (OBD response)"}.get(tgt, "")), "")
        b.u8("Source", body[2], "0x%02X" % body[2], "Physical address of the sender")
        b.raw("Data", data, None, "")
        b.u8("CRC", c, "0x%02X [correct]" % c, "CRC-8 SAE J1850 over header + data")
        return b.done(), body + bytes([c])

    def send(self, src, hdr, tgt, data, info, kind="data", err=None):
        if self.fault["short"] or not self.by[src].on:
            return None
        p, allb = self.mk(src, hdr, tgt, data)
        if self.fault["noise"] and self.rng.random() < 0.3:
            err = "CRC error: pulse widths corrupted by noise"
        dur = 0.1e-3 + 200e-6 + len(allb) * 8 * 96e-6 + 280e-6
        fr = Frame(self.t, dur, src, None, "J1850 VPW", info, pdu=p, kind=kind, err=err, wirefn=lambda fr, d=allb: self.vpw(d), key="hdr 0x%02X src 0x%02X" % (hdr, allb[2]))
        return self.tx(fr, ifs=300e-6)

    def radio(self):
        if self.fault["arb"]:
            self.send("bcm", 0x88, 0xFF, bytes([0x41]), "BCM wins arbitration (header 0x88 < 0x8A)", "data")
            self.send("rad", 0x8A, 0xFF, bytes([0x20, 0x05]), "Radio lost arbitration at bit 6 and retried after the BCM frame", "data")
            self.bcm_lost = getattr(self, "bcm_lost", 0) + 1
        else:
            self.send("rad", 0x8A, 0xFF, bytes([0x20, 0x05]), "Radio: volume 5")

    def cond(self, net):
        c = super().cond(net)
        if self.fault["noise"]:
            c["noise"] = 0.6
        if self.fault["short"]:
            c["atten"], c["off"] = 0.0, 12.0
        return c

    def tpls(self):
        return [Tpl("OBD request over J1850", [P("pid", "Mode 01 PID", 0x0C, opts=[0x0C, 0x05, 0x0D], fmt=lambda v: "%02X %s" % (v, OBD_PID[v]))], lambda s, v, send: self._obd(v, send),
                    "Header 68 6A F1, like ISO 9141-2.")]

    def _obd(self, v, send):
        if not send:
            p, allb = self.mk("tool", 0x68, 0x6A, bytes([0x01, v["pid"]]))
            return Frame(self.t, 0.002, "tool", None, "J1850 VPW", "preview", pdu=p, wirefn=lambda fr: self.vpw(allb))
        self.send("tool", 0x68, 0x6A, bytes([0x01, v["pid"]]), "Scan tool: mode 01 PID %02X" % v["pid"], "cmd")
        rpm = int(self.by["pcm"].vars["RPM"] * 4)
        d = {0x0C: bytes([rpm >> 8, rpm & 255]), 0x05: bytes([128]), 0x0D: bytes([0])}[v["pid"]]
        self.at(self.t + 0.02, lambda: self.send("pcm", 0x48, 0x6B, bytes([0x41, v["pid"]]) + d, "PCM: %s" % obd_decode(v["pid"], d), "resp"))
        return None


# ===================================================================== SENT
CRC4_TAB = [0, 13, 7, 10, 14, 3, 9, 4, 1, 12, 6, 11, 15, 2, 8, 5]


def sent_crc4(nibbles, seed=5):
    """SAE J2716 recommended CRC-4 (x^4 + x^3 + x^2 + 1, seed 0101), augmented with a zero nibble."""
    c = seed
    for n in list(nibbles) + [0]:
        c = n ^ CRC4_TAB[c]
    return c


class SENT(Scenario):
    key, name, cat = "sent", "SENT (SAE J2716)", "auto"
    blurb = "Digital sensor communication"
    phy, rate = "sent", 333333
    medium = "SAE J2716 SENT: dual throttle position sensor -> ECU, 3 us tick, two complementary 12-bit fast-channel signals, slow serial channel"
    nets = [("SIG", "SENT signal line (5 V)")]
    lines = ["S"]
    faults = [("drift", "Sensor clock +25 % (tick 3.75 us)", "The ECU measures the 56-tick sync pulse to calibrate; J2716 tolerates +/-20 %, so these frames are rejected."),
              ("crc", "Noise on the signal line", "A nibble changes value; the CRC-4 catches it."),
              ("plaus", "Second track of the dual sensor drifts", "S1 + S2 should equal 4095; the ECU's plausibility check fails (limp home)."),
              ("open", "Sensor connector open", "No pulses: the ECU flags a timeout after a few frame periods.")]
    spec = [("Standard", "SAE J2716 (Single Edge Nibble Transmission), 2016 revision"), ("Direction", "Unidirectional, sensor to ECU, 3 wires (5 V, signal, ground)"),
            ("Timing", "Tick 3-90 us (3 us typical); each nibble = falling edge to falling edge, 12 + value ticks (12-27)"),
            ("Frame", "Sync / calibration pulse 56 ticks, status nibble, 1-6 data nibbles, CRC nibble, optional pause pulse"),
            ("Slow channel", "Status bits 2 and 3 over 16 or 18 frames: diagnostic codes, sensor ID, temperature"),
            ("Benefit", "Digital accuracy on the same 3 wires as an analogue sensor")]
    frame = [["SENT frame (ticks)", ("Sync 56", 56), ("Status 12-27", 12), ("D1", 12), ("D2", 12), ("D3", 12), ("D4", 12), ("D5", 12), ("D6", 12), ("CRC", 12), ("Pause", "opt")]]
    about = ("SENT replaces an analogue sensor voltage with a digital pulse train on the same wire. Every nibble is the time between two falling "
             "edges - 12 ticks plus the nibble value - so a frame of six data nibbles carries two 12-bit measurements. A long sync pulse starts each "
             "frame and lets the ECU measure the sensor's exact tick time, so cheap RC oscillators are fine.")
    guide = ["In LOGIC, measure the sync pulse (56 ticks = 168 us) and a few nibble pulses.",
             "Compute a nibble value: (pulse length / 3 us) - 12.",
             "Turn the THROTTLE knob: signal 1 rises, signal 2 falls (complementary tracks).",
             "Inject the +25 % clock drift: every frame is rejected even though the data is fine."]

    def build(self):
        s = self.node("tps", "THROTTLE SENSOR", "sensor", 60, 150, "SENT", "dual Hall, 3 us tick").at_right()
        e = self.node("ecu", "ENGINE ECU", "ecu", 680, 150, "SENT input").at_left()
        self.seg([s.port, e.port], "wire", net="SIG", label="3 wires: 5 V / SIG / GND", c0="dt", c1="dt", col=(80, 160, 220), w=4)
        s.vars.update({"Position %": 18.0, "Slow channel": "-"})
        s.ctl = [("Position %", "THROTTLE", 0.0, 100.0, 0, lambda v: "%.1f%%" % v)]
        e.vars.update({"Signal 1": 0, "Signal 2": 0, "Plausible": "yes", "CRC errors": 0, "Rejected": 0})
        self.fno = 0
        self.silent = 0
        self.every(0.001, self.frame_tx, 0.001)

    def frame_tx(self):
        s, e = self.by["tps"], self.by["ecu"]
        if not s.on or self.fault["open"]:
            self.silent += 1
            if self.silent > 3:
                e.vars["Plausible"] = "TIMEOUT (no SENT frames)"
            return
        self.silent = 0
        self.fno += 1
        s1 = int(s.vars["Position %"] / 100 * 4000)
        s2 = 4095 - s1 - (180 if self.fault["plaus"] else 0)
        nib = [(s1 >> 8) & 15, (s1 >> 4) & 15, s1 & 15, s2 & 15, (s2 >> 4) & 15, (s2 >> 8) & 15]
        sc_bit = (0x5A >> (7 - (self.fno % 8))) & 1
        status = ((1 if self.fno % 16 == 0 else 0) << 3) | (sc_bit << 2)
        c = sent_crc4(nib)
        err = None
        tick = 3e-6 * (1.25 if self.fault["drift"] else 1.0)
        if self.fault["drift"]:
            err = "Sync pulse 25 % too long: outside the +/-20 % calibration window, frame rejected"
        sent_n = list(nib)
        if self.fault["crc"] and self.rng.random() < 0.3:
            sent_n[2] ^= 1
            err = err or "CRC-4 mismatch: a data nibble was corrupted"
        b = Bld("SENT fast channel frame", "SAE J2716")
        b.note("Sync / calibration pulse: 56 ticks = %.0f us (tick %.2f us)" % (56 * tick * 1e6, tick * 1e6), "Receivers measure this to calibrate the tick", d=1)
        b.note("Status nibble 0x%X" % status, "Bits 0-1 sensor status, bit 2 slow-channel data bit, bit 3 slow-channel start bit", d=1)
        b.note("Data nibbles: %s" % " ".join("%X" % x for x in sent_n), "Six 4-bit nibbles, each sent as 12 + value ticks", d=1)
        b.note("Signal 1 (track 1): %d / 4095 = %.1f %%" % (s1, s1 / 40.95), "12 bits from nibbles 1-3, most significant first", d=2)
        b.note("Signal 2 (track 2): %d (S1 + S2 = %d)" % (s2, s1 + s2), "Nibbles 4-6 in reverse order; complementary to signal 1", d=2)
        b.note("CRC-4: 0x%X%s" % (c, "" if not err or "CRC" not in err else " [mismatch: data gives 0x%X]" % sent_crc4(sent_n)), "SAE J2716 recommended CRC over the six data nibbles (seed 0101)", d=1)
        allv = [status] + sent_n + [c]

        def wf(fr, allv=allv, tick=tick):
            w = Wire(bit=tick)
            w.set("S", 0.0, 1)
            t = 5e-6
            items = [(56, "SYNC 56 ticks", 7)]
            for i, v in enumerate(allv):
                lab = ("STATUS %X" % v) if i == 0 else (("CRC %X" % v) if i == len(allv) - 1 else ("D%d = %X" % (i, v)))
                items.append((12 + v, lab, i % 2))
            for ticks, lab, col in items:
                w.set("S", t, 0)
                w.set("S", t + 5 * tick, 1)
                w.seg(t, t + ticks * tick, lab, col, 1)
                w.seg(t, t + ticks * tick, "%d" % ticks, col, 0)
                t += ticks * tick
            w.set("S", t, 0)
            w.set("S", t + 5 * tick, 1)
            w.end(t + 10 * tick)
            return w
        total = (56 + sum(12 + v for v in allv) + 10) * tick + 5e-6
        self.tx(Frame(self.t, total, "tps", "ecu", "SENT", "S1 %d  S2 %d  (%.1f %%)" % (s1, s2, s1 / 40.95), pdu=b.done(), kind="data", err=err, wirefn=wf, key="fast channel"))
        if err:
            e.vars["Rejected"] += 1
            if "CRC" in err:
                e.vars["CRC errors"] += 1
            return
        e.vars["Signal 1"], e.vars["Signal 2"] = s1, s2
        e.vars["Plausible"] = "yes" if abs(s1 + s2 - 4095) < 40 else "NO (S1 + S2 = %d) - limp home" % (s1 + s2)
        if self.fno % 16 == 0:
            s.vars["Slow channel"] = "message 0x5A assembled from status bit 2 of 16 frames"


# ===================================================================== PSI5
class PSI5(Scenario):
    key, name, cat = "psi5", "PSI5", "auto"
    blurb = "Automotive sensor interfaces"
    phy, rate = "psi5", 125000
    medium = "PSI5 synchronous parallel bus: airbag ECU supplies the line and sends a sync pulse every 500 us; two acceleration sensors answer in time slots by current modulation"
    nets = [("I", "sensor current (mA)"), ("V", "supply voltage with sync pulses")]
    lines = ["V", "I"]
    faults = [("slot", "Sensor 2 configured for slot 1", "Both sensors modulate the current at the same time: Manchester violations, both values lost."),
              ("sync", "Sync pulses missing", "In synchronous mode the sensors only answer after a sync pulse: silence."),
              ("defect", "Sensor 1 reports an internal error", "Instead of acceleration data it sends a code from the reserved status/error range."),
              ("batt", "Line shorted to battery", "The ECU detects the over-voltage and switches the channel off.")]
    spec = [("Standard", "PSI5 v2.x (Peripheral Sensor Interface 5)"), ("Wiring", "2 wires: power and data on the same pair"),
            ("Upstream", "Sensors modulate their supply current (~ +26 mA) with Manchester code, 125 or 189 kbit/s"),
            ("Downstream", "Voltage sync pulses from the ECU (synchronous and bus modes)"),
            ("Frame", "2 start bits + 10 (up to 28) data bits + 1 parity bit or 3-bit CRC"),
            ("Data range", "10-bit two's complement: +/-480 sensor data; values above are status and error codes"),
            ("Use", "Airbag satellites (acceleration, pressure), also powertrain and chassis sensors")]
    frame = [["PSI5 sensor frame", ("Start 0 0", 2), ("Data, LSB first", 10), ("Parity", 1)]]
    about = ("Airbag systems need fast, robust remote sensors. PSI5 powers each sensor over two wires; the ECU marks time with voltage sync pulses "
             "and each sensor on the bus answers in its own time slot by modulating its supply current with a Manchester-coded frame. Two wires, "
             "yet microsecond-deterministic data.")
    guide = ["Probe V on CH1 and I on CH2: the sync pulse on the voltage, then two current-modulated replies in their slots.",
             "Decode a frame in LOGIC: two start bits, ten data bits LSB first, even parity.",
             "Turn the ACCEL knob on sensor 1 and watch the data value change.",
             "Put both sensors in slot 1 and see the collision."]

    def build(self):
        e = self.node("ecu", "AIRBAG ECU", "ecu", 40, 150, "PSI5 master", "sync every 500 us").at_right()
        s1 = self.node("s1", "FRONT SENSOR L", "sensor", 420, 40, "slot 1", "acceleration").at_left()
        s2 = self.node("s2", "FRONT SENSOR R", "sensor", 650, 260, "slot 2", "acceleration").at_left()
        self.seg([e.port, (330, e.port[1]), (330, s1.port[1]), s1.port], "wire", net="I", label="PSI5 2-wire bus", c0="dt", c1="dt", col=(220, 200, 60), w=4)
        self.seg([(330, e.port[1]), (330, s2.port[1]), s2.port], "wire", net="I", c1="dt", col=(220, 200, 60), w=4)
        s1.vars.update({"Accel g": 0.0})
        s1.ctl = [("Accel g", "ACCEL", -120.0, 120.0, 0, lambda v: "%+.1f g" % v)]
        s2.vars.update({"Accel g": 0.0})
        s2.ctl = [("Accel g", "ACCEL", -120.0, 120.0, 0, lambda v: "%+.1f g" % v)]
        e.vars.update({"Sensor 1": "-", "Sensor 2": "-", "Errors": 0, "Channel": "on"})
        self.every(0.0005, self.cycle, 0.0002)

    def cycle(self):
        e = self.by["ecu"]
        if self.fault["batt"]:
            e.vars["Channel"] = "OFF (short to battery)"
            return
        e.vars["Channel"] = "on"
        tb = 8e-6
        vals = {}
        for k in ("s1", "s2"):
            raw = int(max(-480, min(480, round(self.by[k].vars["Accel g"] * 4))))
            if k == "s1" and self.fault["defect"]:
                raw = 0x1F0
            vals[k] = raw & 0x3FF
        coll = self.fault["slot"]
        sync = not self.fault["sync"]
        if not sync:
            e.vars["Errors"] += 1
            e.vars["Sensor 1"] = e.vars["Sensor 2"] = "NO DATA (no sync pulses)"
            return
        b = Bld("PSI5 sync period (500 us)", "")
        if sync:
            b.note("ECU voltage sync pulse", "Starts the period; the sensors answer in their time slots", d=1)
        for k in ("s1", "s2"):
            v = vals[k]
            sv = v - 1024 if v & 0x200 else v
            b.note("%s: data 0x%03X = %+d LSB%s, parity %d" % ("Sensor 1 (slot 1)" if k == "s1" else ("Sensor 2 (slot %d)" % (1 if coll else 2)), v, sv,
                                                              (" = %+.2f g" % (sv / 4.0)) if abs(sv) <= 480 else " (status/error code range)", bin(v).count("1") & 1),
                   "10-bit two's complement, 0.25 g per LSB here; values above +480 are reserved for status and error codes", d=1)
        err = "Manchester code violation: two sensors in the same slot" if coll else None

        def wf(fr):
            w = Wire(bit=tb)
            w.set("V", 0.0, 0)
            w.set("I", 0.0, 0)
            w.set("V", 5e-6, 1)
            w.set("V", 25e-6, 0)
            w.seg(5e-6, 25e-6, "SYNC", 7, 1)
            if coll:
                a, b2 = vals["s1"], vals["s2"]
                bits1 = [0, 0] + lsb(a, 10) + [bin(a).count("1") & 1]
                bits2 = [0, 0] + lsb(b2, 10) + [bin(b2).count("1") & 1]
                t = 44e-6
                for x, y in zip(bits1, bits2):
                    h1, h2 = (1 if x else 0) + (1 if y else 0), (0 if x else 1) + (0 if y else 1)
                    w.set("I", t, min(1, h1))
                    w.set("I", t + tb / 2, min(1, h2))
                    t += tb
                w.set("I", t, 0)
                w.seg(44e-6, t, "COLLISION S1 + S2", 8, 1)
                w.end(500e-6)
                return w
            for k, t0 in (("s1", 44e-6), ("s2", 220e-6)):
                v = vals[k]
                bits = [0, 0] + lsb(v, 10) + [bin(v).count("1") & 1]
                t = t0
                for i, bt in enumerate(bits):
                    a = 1 if bt else 0
                    w.set("I", t, a)
                    w.set("I", t + tb / 2, 1 - a)
                    w.seg(t, t + tb, ("S" if i < 2 else ("P" if i == 12 else "D%d" % (i - 2))) + "=%d" % bt, i % 2, 0)
                    t += tb
                w.set("I", t, 0)
                w.seg(t0, t, "%s 0x%03X" % ("SENSOR 1" if k == "s1" else "SENSOR 2", v), 1 if k == "s1" else 2, 1)
            w.end(500e-6)
            return w
        self.tx(Frame(self.t, 500e-6, "s1", "ecu", "PSI5", "S1 %+.1f g, S2 %+.1f g" % (self.by["s1"].vars["Accel g"], self.by["s2"].vars["Accel g"]),
                      pdu=b.done(), kind="data", err=err, wirefn=wf, key="sync period"))
        if err:
            e.vars["Errors"] += 1
            return
        e.vars["Sensor 1"] = "SENSOR DEFECT (error code)" if self.fault["defect"] else "%+.1f g" % self.by["s1"].vars["Accel g"]
        e.vars["Sensor 2"] = "%+.1f g" % self.by["s2"].vars["Accel g"]


# ===================================================================== MOST
FBLOCKS = {0x01: "NetBlock", 0x22: "AudioAmplifier", 0x31: "AudioDiskPlayer", 0x50: "Navigation", 0x28: "Telephone", 0x10: "HMI"}


class MOST(Scenario):
    key, name, cat = "most", "MOST", "auto"
    blurb = "Automotive multimedia networks"
    phy, rate = "pof", 22.5792e6
    medium = "MOST25 optical ring (plastic fibre, 650 nm): head unit = timing master, amplifier, CD changer, navigation, phone; 44.1 kHz frames, control messages"
    nets = [("OPTICAL", "light in the POF")]
    lines = ["O"]
    faults = [("break", "Ring broken between navigation and phone", "Light stops at the gap: the phone loses lock, the master sees no light return and the ring goes down."),
              ("bend", "Fibre bent too tightly at the amplifier", "Extra attenuation: occasional unlock events and audio drop-outs."),
              ("wake", "CD changer does not wake up", "It does not pass the light on: every device after it stays dark and the ring cannot start.")]
    spec = [("Standard", "MOST Cooperation: MOST25 (POF), MOST50 (electrical or optical), MOST150 (with Ethernet channel)"),
            ("Topology", "Unidirectional ring; the timing master generates the frame clock"),
            ("Frame", "MOST25: 512 bits at 44.1 kHz (22.58 Mbit/s, bi-phase coded): preamble, boundary descriptor, synchronous + asynchronous area (60 B), control channel (2 B)"),
            ("Control", "16 frames form a control message: target, source, FBlockID.InstID.FktID.OPType, data"),
            ("OPTypes", "0 Set, 1 Get, 2 SetGet, 3 Increment, 4 Decrement, 0xC Status, 0xF Error"),
            ("Function blocks", "NetBlock 0x01, AudioAmplifier 0x22, Telephone 0x28, AudioDiskPlayer 0x31, Navigation 0x50")]
    frame = [["MOST25 frame (512 bits)", ("Preamble", 4), ("Boundary", 4), ("Synchronous + asynchronous data 60 B", 480), ("Control 2 B", 16), ("Frame control", 7), ("Parity", 1)]]
    about = ("MOST carried audio and video around luxury cars on plastic optical fibre. The head unit is the timing master: it sends 44,100 frames a "
             "second around a one-way ring; each device takes its data, adds its own and regenerates the light. Streaming audio uses reserved "
             "synchronous channels, while commands travel as control messages addressed to function blocks, such as AudioAmplifier.Volume.")
    guide = ["Select a control message: FBlockID.InstID.FktID.OPType in the tree.",
             "COMPOSE AudioAmplifier.Volume.Set and see the amplifier answer with a Status message.",
             "Break the ring and read each device's lock state in DEVICE.",
             "SCOPE: bi-phase coded light pulses."]

    def build(self):
        order = [("hu", "HEAD UNIT", "display", 60, 60, "0x100", "timing master"), ("amp", "AMPLIFIER", "meter", 380, 40, "0x101", ""),
                 ("cd", "CD CHANGER", "box", 700, 60, "0x102", ""), ("nav", "NAVIGATION", "gps", 650, 280, "0x103", ""), ("ph", "PHONE MODULE", "phone", 220, 280, "0x104", "")]
        self.order = [o[0] for o in order]
        for nid, lab, kind, x, y, a, sub in order:
            n = self.node(nid, lab, kind, x, y, a, sub)
            n.vars.update({"Lock": "locked"})
        g = self.by
        routes = [[(g["hu"].x + 118, 86), (300, 86), (300, 66), (380, 66)],
                  [(498, 66), (600, 66), (600, 86), (700, 86)],
                  [(759, 112), (759, 200), (709, 200), (709, 280)],
                  [(650, 306), (338, 306)],
                  [(220, 306), (119, 306), (119, 112)]]
        self.ring = []
        for i, pts in enumerate(routes):
            self.ring.append(self.seg(pts, "pof", net="OPTICAL", c0="pof", c1="pof", label="POF ring (one direction)" if i == 3 else ""))
        inner = {"hu": [(119, 112), (178, 86)], "amp": [(380, 66), (498, 66)], "cd": [(700, 86), (759, 112)], "nav": [(709, 280), (650, 306)], "ph": [(338, 306), (220, 306)]}
        for nid, pts in inner.items():
            self.by[nid].port = pts[1]
            self.by[nid].extra["in"] = pts[0]
        self.user = "hu"
        g["amp"].vars.update({"Volume": 18, "Source": "CD (sync channels 0-3)"})
        self.every(0.1, self.frames, 0.01)
        self.every(1.0, self.status, 0.3)

    def path(self, a, b):
        if a not in self.order or b not in self.order or a == b:
            return None
        i = self.order.index(a)
        pts = [self.by[a].port]
        while True:
            seg = self.ring[i]
            if seg.broken:
                return pts + list(seg.pts)[:2]
            pts += list(seg.pts)
            i = (i + 1) % len(self.order)
            if self.order[i] == b:
                return pts
            pts.append(self.by[self.order[i]].port)

    def dark(self):
        """Devices without light at their input."""
        if self.fault["wake"]:
            return {"nav", "ph", "hu"}
        if self.fault["break"]:
            return {"ph", "hu"}
        return set()

    def ring_ok(self):
        return not self.dark()

    def bphase(self, data, tb):
        w = Wire(bit=tb)
        lvl = 0
        w.set("O", 0.0, lvl)
        t = 0.0
        for i, byte in enumerate(data):
            t0 = t
            for k in range(8):
                bit = (byte >> (7 - k)) & 1
                lvl ^= 1
                w.set("O", t, lvl)
                if bit:
                    lvl ^= 1
                    w.set("O", t + tb / 2, lvl)
                t += tb
            w.seg(t0, t, "%02X" % byte, i % 2, 0)
        w.end(t)
        return w

    def cpdu(self, src, dst, fb, inst, fkt, op, data):
        b = Bld("MOST control message", "Assembled from the 2-byte control channel of 16 frames")
        b.u16("Target address", int(self.by[dst].addr, 16) if dst else 0x03C8, None, "Logical node address (0x03C8 = broadcast)")
        b.u16("Source address", int(self.by[src].addr, 16), None, "")
        b.u8("FBlockID", fb, "0x%02X %s" % (fb, FBLOCKS.get(fb, "")), "Function block")
        b.u8("InstID", inst, None, "Instance of the function block")
        b.u16("FktID | OPType", (fkt << 4) | op, "FktID 0x%03X, OPType 0x%X (%s)" % (fkt, op, {0: "Set", 1: "Get", 2: "SetGet", 3: "Increment", 4: "Decrement", 0xC: "Status", 0xF: "Error"}.get(op, "")),
              "12-bit function ID + 4-bit operation type")
        b.u8("Length", len(data), None, "")
        b.raw("Data", data, None, "")
        return b.done()

    def ctrl(self, src, dst, fb, inst, fkt, op, data, info, kind):
        p = self.cpdu(src, dst, fb, inst, fkt, op, data)
        err = None if self.ring_ok() else "Ring down: no light at the timing master input, control message lost"
        return self.tx(Frame(self.t, 16 / 44100.0, src, dst, "MOST", info, pdu=p, kind=kind, err=err, wirefn=lambda fr, d=p.b: self.bphase(d[:20], 1 / self.rate),
                             key="%02X.%03X.%X" % (fb, fkt, op)))

    def frames(self):
        dk = self.dark()
        for n in self.nodes:
            if n.id in dk:
                n.vars["Lock"] = "UNLOCK (no light at input)" if n.id != "hu" else "ring open: no light returns"
                n.state = "NO LIGHT"
            elif dk:
                n.vars["Lock"] = "locked to master, ring open"
                n.state = ""
            else:
                ev = self.fault["bend"] and n.id == "amp" and self.rng.random() < 0.3
                n.vars["Lock"] = "UNLOCK event" if ev else "locked"
                n.state = ""
        if dk:
            return
        b = Bld("MOST25 frame (sample)", "One of 44,100 frames per second, shown every 100 ms")
        b.u8("Boundary descriptor", 6, "6 (24 bytes synchronous)", "Splits the 60 data bytes into synchronous and asynchronous areas")
        b.raw("Synchronous area", bytes((i * 11 + int(self.t * 1000)) & 255 for i in range(24)), "CD audio on channels 0-3 (16-bit stereo)", "Streaming data, no addressing")
        b.raw("Asynchronous area", bytes(36), "idle", "Packet data (navigation maps, ...)")
        b.raw("Control channel", b"\x00\x00", "idle", "2 bytes per frame; 16 frames = one control message")
        p = b.done()
        bad = self.fault["bend"] and self.rng.random() < 0.2
        self.tx(Frame(self.t, 1 / 44100.0, "hu", None, "MOST", "Frame: synchronous audio CD -> amplifier", pdu=p, kind="sync", key="frame",
                      err="Unlock at the amplifier: bent fibre attenuation" if bad else None, wirefn=lambda fr, d=p.b: self.bphase(d[:16], 1 / self.rate)))

    def status(self):
        a = self.by["amp"]
        self.ctrl("amp", "hu", 0x22, 1, 0x400, 0xC, bytes([int(a.vars["Volume"])]), "AudioAmplifier.Volume.Status = %d" % a.vars["Volume"], "resp")

    def on_fault(self, key, on):
        if key == "break":
            self.ring[3].broken = on
            self._paths.clear()

    def tpls(self):
        return [Tpl("AudioAmplifier.Volume.Set", [P("v", "Volume", 25, 0, 40)], lambda s, v, send: self._vol(v, send), "Control message to FBlock 0x22, FktID 0x400, OPType Set (0)."),
                Tpl("AudioDiskPlayer.DeckStatus.Set", [P("st", "State", "Play", opts=["Play", "Stop", "Pause"])], lambda s, v, send: self._deck(v, send), "Start or stop the CD changer.")]

    def _vol(self, v, send):
        if not send:
            return Frame(self.t, 16 / 44100.0, "hu", "amp", "MOST", "preview", pdu=self.cpdu("hu", "amp", 0x22, 1, 0x400, 0x0, bytes([v["v"]])))
        self.ctrl("hu", "amp", 0x22, 1, 0x400, 0x0, bytes([v["v"]]), "AudioAmplifier.Volume.Set(%d)" % v["v"], "cmd")
        if self.ring_ok():
            self.by["amp"].vars["Volume"] = v["v"]
            self.at(self.t + 0.004, self.status)
        return None

    def _deck(self, v, send):
        code = {"Play": 0, "Stop": 1, "Pause": 2}[v["st"]]
        if not send:
            return Frame(self.t, 16 / 44100.0, "hu", "cd", "MOST", "preview", pdu=self.cpdu("hu", "cd", 0x31, 1, 0x200, 0x0, bytes([code])))
        self.ctrl("hu", "cd", 0x31, 1, 0x200, 0x0, bytes([code]), "AudioDiskPlayer.DeckStatus.Set(%s)" % v["st"], "cmd")
        if self.ring_ok():
            self.at(self.t + 0.004, lambda: self.ctrl("cd", "hu", 0x31, 1, 0x200, 0xC, bytes([code]), "AudioDiskPlayer.DeckStatus.Status = %s" % v["st"], "resp"))
        return None


# =================================================================== ISOBUS
def iso_name(identity, mfr, func, ig=2, aac=1, vsys=0, ecu_inst=0):
    return (aac << 63) | (ig << 60) | (vsys << 49) | (func << 40) | (ecu_inst << 32) | (mfr << 21) | identity


ISO_PGN = {65096: "Wheel-based speed and distance", 65097: "Ground-based speed and distance", 65093: "Rear hitch status", 0xE600: "VT to ECU", 0xE700: "ECU to VT",
           0xCB00: "Process data (task controller)", 60928: "Address claimed", 0xC800: "ETP connection management", 0xC700: "ETP data transfer"}
ETP_CB = {20: "RTS (request to send)", 21: "CTS (clear to send)", 22: "DPO (data packet offset)", 23: "EOMA (end of message ack)", 255: "Abort"}
DDI = {1: "Setpoint volume per area application rate", 2: "Actual volume per area application rate", 161: "Actual condensed work state (1-16)", 290: "Setpoint condensed work state (1-16)"}


def iso_idrows(b, o, cid):
    prio, pgn, sa, da, pf, ps = j1939_split(cid)
    b.note("Priority: %d" % prio, "3 bits: 0 highest .. 7 lowest", d=1)
    b.note("PGN: %d (0x%05X) %s" % (pgn, pgn, ISO_PGN.get(pgn) or PGNS.get(pgn, ("",))[0]), "Parameter Group Number (ISO 11783-3, same scheme as J1939)", d=1)
    b.note("PDU format %d -> %s" % (pf, "PDU1: destination 0x%02X" % ps if pf < 240 else "PDU2: group extension 0x%02X (broadcast)" % ps), "PF < 240 = addressed", d=1)
    b.note("Source address: 0x%02X" % sa, "Claimed with the address claim procedure (ISO 11783-5)", d=1)


class ISOBUS(CanNet):
    key, name, cat = "isobus", "ISOBUS (ISO 11783)", "auto"
    blurb = "Agricultural machinery"
    rate = 250000
    can_proto = "ISOBUS"
    medium = "ISO 11783 on 250 kbit/s CAN: tractor ECU, virtual terminal, task controller and a sprayer ECU behind the breakaway connector, TBC at both ends"
    faults = [("claim", "Second implement also wants SA 0x80", "Address claim: the lower NAME keeps 0x80; the other ECU (arbitrary-address capable) moves to a free address."),
              ("vtver", "Sprayer needs VT version 4, terminal is version 3", "The object pool is rejected; the implement has no user interface in the cab."),
              ("no_term1", "Terminating bias circuit missing at the hitch", "ISOBUS ends the bus with active TBCs; without one it is unterminated: reflections and errors."),
              ("lost", "Implement disconnected at the breakaway", "The sprayer disappears: the VT shows 'implement lost' and the TC stops section control.")]
    spec = [("Standard", "ISO 11783 parts 1-14 (AEF conformance tests); network management and transport from SAE J1939"),
            ("Physical", "CAN 250 kbit/s, 4 wires (CAN_H, CAN_L, TBC_PWR, TBC_RTN), breakaway connector at the hitch, terminating bias circuits"),
            ("Roles", "Tractor ECU (speeds, hitch, PTO), Virtual Terminal (user interface for any implement), Task Controller (section and rate control), implement ECUs"),
            ("VT", "Implements upload an object pool (masks, soft keys, graphics) with ETP; the VT reports key presses and value changes"),
            ("TC", "Process data with DDIs (ISO 11783-11 data dictionary): setpoints, actual rates, work states"),
            ("Addresses", "Preferred SAs: TECU 0xF0, VT 0x26, TC 0xF7; implements claim any free address")]
    frame = [["VT to ECU (PGN 0xE600)", ("VT function", 8), ("Parameters", 56)], ["TC process data (PGN 0xCB00)", ("Command | element", 16), ("DDI", 16), ("Value", 32)]]
    about = ("ISOBUS lets any tractor work with any implement. It reuses J1939's identifiers, address claim and transport protocols, then adds a "
             "Virtual Terminal in the cab that draws whatever user interface the implement uploads, and a Task Controller that switches sprayer "
             "sections and sets application rates from a prescription map. The tractor broadcasts speed and hitch data that every implement can use.")
    guide = ["Watch the address claims at start-up: industry group 2 (agriculture) in each NAME.",
             "Follow the object pool upload: ETP RTS, CTS, DPO, data packets, EOMA, then End of Object Pool.",
             "Select the tractor's wheel-based speed (PGN 65096) and turn the SPEED knob.",
             "COMPOSE a soft key press from the VT, or a new application rate from the TC.",
             "Add the second implement with the same preferred address and watch the conflict resolve."]

    def setup(self):
        nodes = [self.node("tecu", "TRACTOR ECU", "ecu", 30, 60, "SA 0xF0"), self.node("vt", "VIRTUAL TERMINAL", "display", 280, 60, "SA 0x26", "VT version 3"),
                 self.node("tc", "TASK CONTROLLER", "server", 530, 60, "SA 0xF7"), self.node("spr", "SPRAYER ECU", "valve", 400, 290, "SA 0x80", "behind breakaway"),
                 self.node("spr2", "SECOND IMPLEMENT", "ecu", 680, 290, "SA 0x80 (preferred)", "powered off")]
        nodes[3].at_top()
        nodes[4].at_top()
        nodes[4].on = False
        self.can_trunk(nodes, 200, label="ISOBUS 4-wire (CAN + TBC power)", conn="deutsch")
        for t in self.terms:
            t.label = "TBC"
        self.sa = {"tecu": 0xF0, "vt": 0x26, "tc": 0xF7, "spr": 0x80, "spr2": 0x80}
        self.names = {"tecu": iso_name(0x101, 111, 134), "vt": iso_name(0x202, 111, 29), "tc": iso_name(0x303, 111, 130), "spr": iso_name(0x1234, 120, 132),
                      "spr2": iso_name(0x0777, 222, 132)}
        self.user = "vt"
        self.dist = 0.0
        self.by["tecu"].vars.update({"Speed km/h": 8.5, "Hitch %": 80})
        self.by["tecu"].ctl = [("Speed km/h", "SPEED", 0.0, 40.0, 0, lambda v: "%.1f" % v)]
        self.by["spr"].vars.update({"Sections": "ON ON ON ON", "Rate L/ha": 200, "UI in cab": "loading..."})
        self.by["vt"].vars.update({"Active working set": "-"})
        self.at(0.01, self.claims)
        self.at(0.3, self.pool)
        self.every(0.1, self.speeds, 0.1)
        self.every(1.0, self.vt_status, 0.2)
        self.every(0.5, self.tc, 0.35)

    def jsend(self, node, pgn, data, da=0xFF, prio=6, info="", kind="data"):
        sa = self.sa[node]
        cid = j1939_id(prio, pgn, sa, da)
        dst = None
        if da != 0xFF and ((pgn >> 8) & 0xFF) < 240:
            dst = next((k for k, v in self.sa.items() if v == da and self.by[k].on and k != node), None)
        self.bus.send(node, cid, bytes(data), ext=True, info=info, kind=kind, key="PGN %d" % pgn, dst=dst, idrows=lambda b, o, cid=cid: iso_idrows(b, o, cid),
                      sd="SA 0x%02X" % sa, dd=("SA 0x%02X" % da) if dst else None,
                      dissect=lambda b, o, cid=cid, d=bytes(data): self.isodis(b, o, cid, d))

    def isodis(self, b, off, cid, d):
        prio, pgn, sa, da, pf, ps = j1939_split(cid)
        if pgn == 60928:
            j1939_dissect(b, off, cid, d)
            return
        b.rows.append([0, "ISO 11783: %s" % ISO_PGN.get(pgn, "PGN %d" % pgn), off, len(d), ""])
        if pgn == 65096 and len(d) >= 6:
            b.rows.append([1, "Wheel-based machine speed: %.2f km/h" % (struct.unpack("<H", d[0:2])[0] * 0.001 * 3.6), off, 2, "0.001 m/s per bit"])
            b.rows.append([1, "Wheel-based distance: %.1f m" % (struct.unpack("<I", d[2:6])[0] * 0.001), off + 2, 4, "0.001 m per bit"])
        if pgn in (0xE600, 0xE700):
            b.rows.append([1, "Function 0x%02X: %s" % (d[0], {0x00: "Soft key activation", 0x01: "Button activation", 0x11: "Object pool transfer", 0x12: "End of object pool",
                                                            0xC0: "Get hardware", 0xC7: "Get versions", 0xFE: "VT status", 0xFF: "Working set maintenance"}.get(d[0], "")), off, 1, ""])
            if d[0] == 0x00:
                b.rows.append([1, "Key %s, object ID %d" % ({0: "released", 1: "pressed", 2: "held", 3: "aborted"}.get(d[1], "?"), struct.unpack("<H", d[2:4])[0]), off + 1, 3, ""])
            if d[0] == 0xFE:
                b.rows.append([1, "Active working set master SA 0x%02X, data mask %d, soft key mask %d" % (d[1], struct.unpack("<H", d[2:4])[0], struct.unpack("<H", d[4:6])[0]), off + 1, 5, ""])
            if d[0] == 0x12 and pgn == 0xE600:
                b.rows.append([1, "Error codes 0x%02X (%s)" % (d[1], "no errors" if d[1] == 0 else "pool rejected"), off + 1, 1, ""])
        if pgn == 0xCB00 and len(d) >= 8:
            ddi = struct.unpack("<H", d[2:4])[0]
            val = struct.unpack("<i", d[4:8])[0]
            b.rows.append([1, "Command %d (%s), element %d" % (d[0] & 15, {3: "value", 2: "request value", 0xD: "acknowledge"}.get(d[0] & 15, ""), (d[0] >> 4) | (d[1] << 4)), off, 2, ""])
            vt = "%.1f L/ha" % (val / 100.0) if ddi in (1, 2) else ("sections %s" % " ".join(["off", "ON", "err", "n/a"][(val >> (2 * i)) & 3] for i in range(4)) if ddi in (161, 290) else str(val))
            b.rows.append([1, "DDI %d %s = %d (%s)" % (ddi, DDI.get(ddi, ""), val, vt), off + 2, 6, "ISO 11783-11 data dictionary identifier"])
        if pgn == 0xC800 and len(d) >= 8:
            b.rows.append([1, "Control byte %d: %s" % (d[0], ETP_CB.get(d[0], "")), off, 1, "Extended transport protocol for messages over 1785 bytes"])
            b.rows.append([1, "PGN of the packeted message: 0x%05X" % (d[5] | d[6] << 8 | d[7] << 16), off + 5, 3, ""])
        if pgn == 0xC700:
            b.rows.append([1, "Sequence number %d + 7 data bytes" % d[0], off, 8, "Relative to the last data packet offset (DPO)"])

    def name_bytes(self, node):
        return self.names[node].to_bytes(8, "little")

    def claims(self):
        for n in ("tecu", "vt", "tc", "spr"):
            self.jsend(n, 60928, self.name_bytes(n), 0xFF, 6, "Address claimed SA 0x%02X (industry group 2: agriculture)" % self.sa[n], "ctl")

    def pool(self):
        s = self.by["spr"]
        if not s.on:
            return
        self.jsend("spr", 0xE700, bytes([0xC7] + [0xFF] * 7), self.sa["vt"], 7, "Get versions (is a stored pool available?)", "cmd")
        if self.fault["vtver"]:
            self.at(self.t + 0.01, lambda: self.jsend("vt", 0xE600, bytes([0xC0, 0x03] + [0xFF] * 6), self.sa["spr"], 7, "Get hardware response: VT version 3", "resp"))
            self.at(self.t + 0.02, lambda: self.log("Sprayer: object pool needs VT version 4 - not uploaded"))
            s.vars["UI in cab"] = "NONE (VT version 3 too old)"
            return
        T = self.t + 0.01
        self.at(T, lambda: self.jsend("spr", 0xC800, bytes([20]) + struct.pack("<I", 20000) + bytes([0x00, 0xE7, 0x00]), self.sa["vt"], 7, "ETP RTS: object pool, 20000 bytes", "ctl"))
        self.at(T + 0.01, lambda: self.jsend("vt", 0xC800, bytes([21, 255, 1, 0, 0, 0x00, 0xE7, 0x00]), self.sa["spr"], 7, "ETP CTS: 255 packets from packet 1", "ctl"))
        self.at(T + 0.02, lambda: self.jsend("spr", 0xC800, bytes([22, 255, 0, 0, 0, 0x00, 0xE7, 0x00]), self.sa["vt"], 7, "ETP DPO: offset 0", "ctl"))
        for i in range(4):
            self.at(T + 0.025 + 0.002 * i, lambda i=i: self.jsend("spr", 0xC700, bytes([i + 1]) + (bytes([0x11]) if i == 0 else b"") + bytes((7 if i else 6)), self.sa["vt"], 7,
                                                                   "ETP DT packet %d (object pool data...)" % (i + 1), "data"))
        self.at(T + 0.05, lambda: self.jsend("vt", 0xC800, bytes([23]) + struct.pack("<I", 20000) + bytes([0x00, 0xE7, 0x00]), self.sa["spr"], 7, "ETP EOMA: 20000 bytes received", "ack"))
        self.at(T + 0.06, lambda: self.jsend("spr", 0xE700, bytes([0x12] + [0xFF] * 7), self.sa["vt"], 7, "End of object pool", "cmd"))
        self.at(T + 0.08, lambda: self.jsend("vt", 0xE600, bytes([0x12, 0x00] + [0xFF] * 6), self.sa["spr"], 7, "End of object pool response: no errors", "resp"))
        self.at(T + 0.08, lambda: (s.vars.__setitem__("UI in cab", "object pool loaded"), self.by["vt"].vars.__setitem__("Active working set", "SPRAYER (SA 0x%02X)" % self.sa["spr"])))

    def speeds(self):
        t = self.by["tecu"]
        if t.on:
            v = t.vars["Speed km/h"] / 3.6
            self.dist += v * 0.1
            self.jsend("tecu", 65096, struct.pack("<HIBB", int(v * 1000), int(self.dist * 1000) & 0xFFFFFFFF, 0xFF, 0x15), info="Wheel-based speed %.1f km/h" % t.vars["Speed km/h"], prio=3)

    def vt_status(self):
        self.jsend("vt", 0xE600, bytes([0xFE, self.sa["spr"]]) + struct.pack("<HH", 1000, 2000) + bytes([0x00, 0xFF]), 0xFF, 6, "VT status (active working set SA 0x%02X)" % self.sa["spr"], "sync")

    def tc(self):
        s = self.by["spr"]
        if self.fault["lost"] or not s.on:
            s.state = "LOST"
            self.by["vt"].vars["Active working set"] = "IMPLEMENT LOST"
            return
        s.state = ""
        r = int(s.vars["Rate L/ha"])
        self.jsend("tc", 0xCB00, struct.pack("<HHi", 0x0013, 1, r * 100), self.sa["spr"], 6, "TC: setpoint rate %d L/ha (DDI 1)" % r, "cmd")
        self.jsend("tc", 0xCB00, struct.pack("<HHi", 0x0013, 290, -171), self.sa["spr"], 6, "TC: sections 1-4 ON (DDI 290)", "cmd")
        self.jsend("spr", 0xCB00, struct.pack("<HHi", 0x0013, 2, int(r * 99.5)), self.sa["tc"], 6, "Sprayer: actual rate %.1f L/ha (DDI 2)" % (r * 0.995), "resp")

    def can_fault(self, key, on):
        if key == "claim":
            n = self.by["spr2"]
            n.on = on
            n.sub = "powered on" if on else "powered off"
            if on:
                self.sa["spr2"] = 0x80
                self.jsend("spr2", 60928, self.name_bytes("spr2"), 0xFF, 6, "Address claimed SA 0x80 by the second implement", "ctl")
                self.at(self.t + 0.002, lambda: self.jsend("spr", 60928, self.name_bytes("spr"), 0xFF, 6, "Sprayer defends SA 0x80 (its NAME is lower)", "ctl"))
                self.at(self.t + 0.25, self.reclaim)
            else:
                self.sa["spr2"] = 0x80
                n.addr = "SA 0x80 (preferred)"
        if key == "vtver":
            self.by["vt"].sub = "VT version 3" if on else "VT version 4"
            self.at(self.t + 0.05, self.pool)
        if key == "lost":
            self.by["spr"].on = not on
            if not on:
                self.at(self.t + 0.05, lambda: self.jsend("spr", 60928, self.name_bytes("spr"), 0xFF, 6, "Sprayer reconnected: address claimed SA 0x80", "ctl"))
                self.at(self.t + 0.2, self.pool)

    def reclaim(self):
        n = self.by["spr2"]
        if not n.on:
            return
        self.sa["spr2"] = 0x81
        n.addr = "SA 0x81"
        self.jsend("spr2", 60928, self.name_bytes("spr2"), 0xFF, 6, "Second implement lost the conflict: claims SA 0x81 instead", "ctl")

    def tpls(self):
        return [Tpl("VT soft key activation", [P("k", "Soft key ID", 5001, 0, 65534), P("st", "State", "pressed", opts=["pressed", "released"])], lambda s, v, send: self._key(v, send),
                    "The VT tells the working set master which soft key the driver pressed."),
                Tpl("TC rate setpoint", [P("r", "Rate L/ha", 250, 0, 1000)], lambda s, v, send: self._rate(v, send), "Process data command with DDI 1 (0.01 L/ha resolution).")]

    def _key(self, v, send):
        d = bytes([0x00, 1 if v["st"] == "pressed" else 0]) + struct.pack("<HH", v["k"], 1000) + b"\x01\xff"
        if not send:
            return self.preview_can("vt", j1939_id(6, 0xE600, self.sa["vt"], self.sa["spr"]), d, ext=True,
                                    dissect=lambda b, o: self.isodis(b, o, j1939_id(6, 0xE600, self.sa["vt"], self.sa["spr"]), d))
        self.jsend("vt", 0xE600, d, self.sa["spr"], 6, "Soft key %d %s" % (v["k"], v["st"]), "cmd")
        return None

    def _rate(self, v, send):
        cid = j1939_id(6, 0xCB00, self.sa["tc"], self.sa["spr"])
        d = struct.pack("<HHi", 0x0013, 1, v["r"] * 100)
        if not send:
            return self.preview_can("tc", cid, d, ext=True, dissect=lambda b, o: self.isodis(b, o, cid, d))
        self.by["spr"].vars["Rate L/ha"] = v["r"]
        self.tc()
        return None
