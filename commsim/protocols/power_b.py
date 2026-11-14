"""Power and energy, part B: Modbus power meters, SunSpec Modbus, OCPP,
M-Bus and DLMS/COSEM."""
import math
import struct
from ..engine import Scenario, Bld, Frame, Tpl, P, Pdu
from ..bits import crcn
from .fam import serial_frame, IpNet
from .industrial_a import ModbusSerial, MbServer, mb_req, mb_dissect, mb_info, f32regs, regs_f32
from .webfam import http_req, http_rsp, ws_frame, jdump
from .power_a import utc


def u32regs(v):
    v = int(v) & 0xFFFFFFFF
    return v >> 16, v & 0xFFFF


def i64regs(v):
    v = int(v) & 0xFFFFFFFFFFFFFFFF
    return [(v >> s) & 0xFFFF for s in (48, 32, 16, 0)]


# ================================================= Modbus (power meters)
class ModbusPower(ModbusSerial):
    key, name, cat = "modbus_power", "Modbus (power meters)", "power"
    blurb = "Energy meters and power monitoring"
    rate = 19200
    medium = "Energy management system polling three meters on RS-485 (Modbus RTU 19200 8E1): main incomer, HVAC sub-meter, PV meter"
    faults = [("offbyone", "Integrator typed the manual's register numbers as addresses", "Main meter manual says register 3000; the protocol address is 2999. "
                                                                                          "Every float is now assembled from the wrong halves - plausible-looking garbage."),
              ("swap", "HVAC meter floats decoded with the wrong word order", "Values like 1.2e-41 or 3.4e+12 instead of 230 V."),
              ("ctpol", "CT on phase L2 of the HVAC meter fitted backwards", "Phase L2 power is negative; the total is only a third of the real load."),
              ("ctratio", "Main meter configured for 200/5 A CTs (fitted: 400/5)", "All currents, powers and energies read exactly half of the truth."),
              ("dupaddr", "PV meter accidentally set to address 2", "Two meters answer polls for address 2 at the same time: garbled replies, CRC errors."),
              ("no_term1", "Termination missing at the far end", "Reflections on the 19200 bit/s line corrupt some replies.")]
    spec = [("Standard", "Modbus RTU over RS-485 (Modbus over Serial Line V1.02); meter register maps are vendor-specific"),
            ("Main meter", "Holding registers, float32 (big-endian words); manual numbers are 1-based: manual 3000 = protocol address 2999. "
                           "3000 I1, 3002 I2, 3004 I3, 3028-3032 V L-N, 3060 P total kW, 3068 Q kvar, 3084 PF, 3110 Hz, 3204 energy INT64 Wh"),
            ("HVAC sub-meter", "Input registers (FC04), float32: 0x0000-0x0004 V L1-L3, 0x0006-0x000A I, 0x000C-0x0010 P per phase W, 0x0034 total W, 0x0048 import kWh"),
            ("PV meter", "Holding registers, scaled integers: 100 V x0.1, 101 I x0.01, 102 P (int16) x10^reg106 W, 103 PF x0.001, 104-105 export energy x0.01 kWh"),
            ("Pitfalls", "Off-by-one addressing, float word order, signed vs unsigned, scale factors, CT ratio and CT polarity")]
    frame = [["FC03 read of a float", ("Addr", 8), ("03", 8), ("Start 2999", 16), ("Qty 2", 16), ("CRC", 16)],
             ["Reply", ("Addr", 8), ("03", 8), ("Bytes 4", 8), ("Hi word", 16), ("Lo word", 16), ("CRC", 16)]]
    about = ("Almost every power meter speaks Modbus, but each one has its own register map. Values come as 32-bit floats split across two "
             "16-bit registers, as scaled integers with a fixed or separate scale factor, or as 64-bit energy counters - and the manual may number "
             "registers from 1 while the protocol counts from 0. Commissioning a metering system means getting all of that right, plus the CT "
             "ratio and the CT orientation on site.")
    guide = ["Select a reply from the main meter: two registers = one float. Check the value against the DEVICE panel.",
             "Inject the off-by-one fault and see how the same bytes give nonsense when split at the wrong register.",
             "Reverse the CT on L2: a negative phase power in the HVAC reply.",
             "COMPOSE a read of the 64-bit energy counter (manual 3204, 4 registers).",
             "Set two meters to the same address and watch the CRC errors."]

    def build(self):
        self.baud = 19200
        m = self.node("m", "ENERGY MANAGEMENT SYSTEM", "scada", 30, 40, "master", "polls every 100 ms", w=150)
        s1 = self.node("s1", "MAIN INCOMER METER", "meter", 230, 260, "slave 1", "400/5 A CTs", w=130)
        s2 = self.node("s2", "HVAC SUB-METER", "meter", 470, 260, "slave 2", "DIN rail", w=120)
        s3 = self.node("s3", "PV METER", "meter", 700, 260, "slave 3", "export", w=110)
        for n in (s1, s2, s3):
            n.at_top()
        self.trunk(180, 60, 850, [m, s1, s2, s3], "rs485", net="VDIFF", label="RS-485 2-wire, 19200 8E1", t0=True, t1=True)
        self.user = "m"
        n1 = {(3, 2999): "I1 A (float hi)", (3, 3000): "I1 A (float lo)", (3, 3001): "I2 A (hi)", (3, 3002): "I2 A (lo)", (3, 3003): "I3 A (hi)", (3, 3004): "I3 A (lo)",
              (3, 3027): "V1-N (hi)", (3, 3028): "V1-N (lo)", (3, 3029): "V2-N (hi)", (3, 3030): "V2-N (lo)", (3, 3031): "V3-N (hi)", (3, 3032): "V3-N (lo)",
              (3, 3059): "P total kW (hi)", (3, 3060): "P total kW (lo)", (3, 3083): "PF (hi)", (3, 3084): "PF (lo)", (3, 3109): "Hz (hi)", (3, 3110): "Hz (lo)",
              (3, 3203): "Energy Wh INT64 (word 1)", (3, 3204): "word 2", (3, 3205): "word 3", (3, 3206): "Energy Wh (word 4, least significant)"}
        n2 = {(4, 0): "V L1 (hi)", (4, 1): "V L1 (lo)", (4, 2): "V L2 (hi)", (4, 3): "V L2 (lo)", (4, 4): "V L3 (hi)", (4, 5): "V L3 (lo)", (4, 6): "I L1 (hi)",
              (4, 7): "I L1 (lo)", (4, 8): "I L2 (hi)", (4, 9): "I L2 (lo)", (4, 10): "I L3 (hi)", (4, 11): "I L3 (lo)", (4, 12): "P L1 W (hi)", (4, 13): "P L1 W (lo)",
              (4, 14): "P L2 W (hi)", (4, 15): "P L2 W (lo)", (4, 16): "P L3 W (hi)", (4, 17): "P L3 W (lo)", (4, 52): "P total W (hi)", (4, 53): "P total W (lo)",
              (4, 72): "Import kWh (hi)", (4, 73): "Import kWh (lo)"}
        n3 = {(3, 100): "V x0.1", (3, 101): "I x0.01", (3, 102): "P W (int16) x 10^SF", (3, 103): "PF x0.001", (3, 104): "Export kWh x0.01 (hi)",
              (3, 105): "Export kWh x0.01 (lo)", (3, 106): "Power scale factor (int16)"}
        self.srv = {1: MbServer(1, "MAIN METER", hr={a: 0 for a in list(range(2990, 3040)) + list(range(3056, 3070)) + list(range(3080, 3090)) + list(range(3106, 3116)) +
                                                     list(range(3200, 3212)) + [2000]}, ident=("COMM-SIM METERING", "PM-5560-SIM", "3.2"), names=n1),
                    2: MbServer(2, "HVAC METER", ir={a: 0 for a in range(0, 80)}, ident=("COMM-SIM METERING", "DIN-630-SIM", "1.8"), names=n2),
                    3: MbServer(3, "PV METER", hr={a: 0 for a in range(100, 110)}, ident=("COMM-SIM METERING", "PV-M1", "1.1"), names=n3)}
        self.srv[1].hr[2000] = 400
        self.e_main, self.e_hvac, self.e_pv = 1_523_400_000.0, 210_334.0, 48_210.0
        self.k = 0
        self.pending = None
        self.reqs = [(1, 3, 2999, 6), (1, 3, 3027, 6), (1, 3, 3059, 2), (1, 3, 3083, 2), (1, 3, 3203, 4), (2, 4, 0, 18), (2, 4, 52, 2), (3, 3, 100, 7)]
        m.vars.update({"Site import kW": "-", "Main I1 / V1": "-", "Main energy": "-", "HVAC kW (L1 L2 L3)": "-", "PV kW": "-", "Timeouts": 0, "CRC/LRC errors": 0, "Exceptions": 0})
        s1.vars.update({"Building load kW": 92.0})
        s1.ctl = [("Building load kW", "LOAD", 0.0, 250.0, 0, lambda v: "%.0f kW" % v)]
        s2.vars.update({"HVAC kW": 31.0})
        s2.ctl = [("HVAC kW", "HVAC", 0.0, 80.0, 0, lambda v: "%.1f kW" % v)]
        s3.vars.update({"Irradiance %": 70.0})
        s3.ctl = [("Irradiance %", "SUN", 0.0, 100.0, 0, lambda v: "%.0f %%" % v)]
        self.every(0.1, self.poll, 0.01)
        self.every(0.2, self.physics, 0.05)

    def physics(self):
        load = self.by["s1"].vars["Building load kW"]
        hv = self.by["s2"].vars["HVAC kW"] * (1 + 0.05 * math.sin(self.t / 3.0))
        pv = 60.0 * self.by["s3"].vars["Irradiance %"] / 100.0
        site = load + hv - pv
        k = 0.5 if self.fault["ctratio"] else 1.0
        v = [231.2 + float(self.rng.normal(0, 0.2)), 230.6 + float(self.rng.normal(0, 0.2)), 232.0 + float(self.rng.normal(0, 0.2))]
        ph = site * 1000 / 3
        cur = [ph / (v[i] * 0.96) for i in range(3)]
        self.e_main += site * 1000 * 0.2 / 3600 * k
        hr = self.srv[1].hr
        regs = {}
        for i, c in enumerate(cur):
            regs[2999 + 2 * i] = f32regs(c * k)
        regs[3005] = f32regs(sum(cur) / 3 * k)
        regs[3007] = f32regs(abs(cur[0] - cur[1]) * 0.1 * k)
        for i in range(3):
            regs[3027 + 2 * i] = f32regs(v[i])
        regs[3033] = f32regs(sum(v) / 3)
        regs[3059] = f32regs(site * k)
        regs[3067] = f32regs(site * 0.29 * k)
        regs[3083] = f32regs(0.96)
        regs[3109] = f32regs(50.0 + float(self.rng.normal(0, 0.01)))
        for a, (h, l) in regs.items():
            hr[a], hr[a + 1] = h, l
        for i, w in enumerate(i64regs(self.e_main)):
            hr[3203 + i] = w
        hw = hv * 1000 / 3
        pl = [hw, -hw if self.fault["ctpol"] else hw, hw]
        self.e_hvac += hv * 0.2 / 3600
        ir = self.srv[2].ir
        vals = [v[0], v[1], v[2], hw / v[0] / 0.9, hw / v[1] / 0.9, hw / v[2] / 0.9, pl[0], pl[1], pl[2]]
        for i, x in enumerate(vals):
            ir[2 * i], ir[2 * i + 1] = f32regs(x)
        ir[52], ir[53] = f32regs(sum(pl))
        ir[72], ir[73] = f32regs(self.e_hvac)
        self.e_pv += pv * 0.2 / 3600
        h3 = self.srv[3].hr
        p_w = -pv * 1000
        h3[100], h3[101] = int(v[0] * 10), int(pv * 1000 / 3 / v[0] * 100) & 0xFFFF
        h3[102] = int(p_w / 10) & 0xFFFF
        h3[103] = 990
        h3[104], h3[105] = u32regs(self.e_pv * 100)
        h3[106] = 1

    def poll(self):
        if not self.by["m"].on or self.pending is not None:
            return
        self.k = (self.k + 1) % len(self.reqs)
        unit, fc, a, q = self.reqs[self.k]
        if self.fault["offbyone"] and unit == 1:
            a += 1
        self.request(unit, mb_req(fc, a, q))

    def rx(self, fr):
        unit = fr.meta.get("unit")
        if fr.src == "m":
            srv = self.srv.get(unit)
            if srv is None or fr.err or not self.by.get("s%d" % unit, self.by["m"]).on:
                return
            if self.fault["dupaddr"] and unit == 3:
                return
            rsp = srv.handle(fr.meta["pdu"])
            err = None
            if self.fault["dupaddr"] and unit == 2:
                err = "Two meters answered at once: collision, CRC error"
            elif self.fault["no_term1"] and self.rng.random() < 0.25:
                err = "CRC mismatch: reflections from the unterminated end corrupted a bit"
            r = self.mkframe("s%d" % unit, "m", unit, rsp, fr.meta["pdu"], "resp" if not rsp[0] & 0x80 else "err", err)
            r.t = self.t + 0.004
            self.tx(r)
            return
        if fr.dst != "m":
            return
        m = self.by["m"]
        self.pending = None
        if fr.err:
            m.vars["CRC/LRC errors"] += 1
            return
        pdu, req = fr.meta["pdu"], fr.meta["req"]
        if pdu[0] & 0x80:
            m.vars["Exceptions"] += 1
            return
        if pdu[0] not in (3, 4):
            return
        regs = [struct.unpack(">H", pdu[2 + 2 * i:4 + 2 * i])[0] for i in range(pdu[1] // 2)]
        a0 = struct.unpack(">H", req[1:3])[0] - (1 if (self.fault["offbyone"] and unit == 1) else 0)
        f = lambda i, sw=False: regs_f32(regs[i + 1], regs[i]) if sw else regs_f32(regs[i], regs[i + 1])
        if unit == 1 and a0 == 2999:
            m.vars["Main I1 / V1"] = "%.4g A / %s" % (f(0), str(m.vars["Main I1 / V1"]).split(" / ")[-1])
        elif unit == 1 and a0 == 3027:
            m.vars["Main I1 / V1"] = "%s / %.4g V" % (str(m.vars["Main I1 / V1"]).split(" / ")[0], f(0))
        elif unit == 1 and a0 == 3059:
            m.vars["Site import kW"] = "%.4g kW" % f(0)
        elif unit == 1 and a0 == 3203:
            wh = (regs[0] << 48) | (regs[1] << 32) | (regs[2] << 16) | regs[3]
            m.vars["Main energy"] = "%.1f kWh" % (wh / 1000.0)
        elif unit == 2 and a0 == 0:
            sw = self.fault["swap"]
            m.vars["HVAC kW (L1 L2 L3)"] = " ".join("%.4g" % (f(12 + 2 * i, sw) / 1000) for i in range(3))
        elif unit == 3 and a0 == 100:
            p = struct.unpack(">h", struct.pack(">H", regs[2]))[0] * 10 ** struct.unpack(">h", struct.pack(">H", regs[6]))[0]
            m.vars["PV kW"] = "%.2f kW (export, sign -)" % (p / 1000.0)

    def tpls(self):
        return [Tpl("Read by manual register number", [P("u", "Meter", 1, opts=[1, 2, 3], fmt=lambda v: self.by["s%d" % v].label),
                                                       P("fc", "Function", 3, opts=[3, 4]), P("r", "Manual register (1-based)", 3060, 1, 65536), P("q", "Quantity", 2, 1, 125)],
                    lambda s, v, send: self._q(v["u"], mb_req(v["fc"], v["r"] - 1, v["q"]), send), "Subtracts 1 from the manual's number, as the protocol counts from 0."),
                Tpl("Read 64-bit energy (main)", [], lambda s, v, send: self._q(1, mb_req(3, 3203, 4), send), "Four registers, most significant word first, value in Wh."),
                Tpl("Write CT primary (main)", [P("v", "CT primary A", 400, 5, 10000)], lambda s, v, send: self._q(1, mb_req(6, 2000, 0, v["v"]), send),
                    "Configuration register 2000 (example): CT primary current."),
                Tpl("Read device identification", [P("u", "Meter", 1, opts=[1, 2, 3], fmt=lambda v: self.by["s%d" % v].label)],
                    lambda s, v, send: self._q(v["u"], mb_req(43), send), "FC43 / MEI 14: vendor, model, firmware.")]

    def on_fault(self, key, on):
        if key == "ctratio":
            self.srv[1].hr[2000] = 200 if on else 400

    def inspect(self, n):
        rows = list(n.vars.items())
        if n.id == "s1":
            rows += [("CT primary (reg 2000)", self.srv[1].hr[2000])]
        return rows


# ========================================================= SunSpec Modbus
def ss_str(s, n):
    b = s.encode().ljust(2 * n, b"\x00")[:2 * n]
    return [struct.unpack(">H", b[i:i + 2])[0] for i in range(0, 2 * n, 2)]


def s16(v):
    return int(v) & 0xFFFF


def sunspec_map(base, models):
    hr = {base: 0x5375, base + 1: 0x6E53}
    a = base + 2
    where = {}
    for mid, regs in models:
        hr[a], hr[a + 1] = mid, len(regs)
        where[mid] = a
        for i, r in enumerate(regs):
            hr[a + 2 + i] = r & 0xFFFF
        a += 2 + len(regs)
    hr[a], hr[a + 1] = 0xFFFF, 0
    where["end"] = a
    return hr, where


M103 = ["A", "AphA", "AphB", "AphC", "A_SF", "PPVphAB", "PPVphBC", "PPVphCA", "PhVphA", "PhVphB", "PhVphC", "V_SF", "W", "W_SF", "Hz", "Hz_SF", "VA", "VA_SF",
        "VAr", "VAr_SF", "PF", "PF_SF", "WH (hi)", "WH (lo)", "WH_SF", "DCA", "DCA_SF", "DCV", "DCV_SF", "DCW", "DCW_SF", "TmpCab", "TmpSnk", "TmpTrns", "TmpOt",
        "Tmp_SF", "St", "StVnd", "Evt1 (hi)", "Evt1 (lo)", "Evt2 (hi)", "Evt2 (lo)", "EvtVnd1 (hi)", "EvtVnd1 (lo)", "EvtVnd2 (hi)", "EvtVnd2 (lo)",
        "EvtVnd3 (hi)", "EvtVnd3 (lo)", "EvtVnd4 (hi)", "EvtVnd4 (lo)"]
M123 = ["Conn_WinTms", "Conn_RvrtTms", "Conn", "WMaxLimPct", "WMaxLimPct_WinTms", "WMaxLimPct_RvrtTms", "WMaxLimPct_RmpTms", "WMaxLim_Ena", "OutPFSet",
        "OutPFSet_WinTms", "OutPFSet_RvrtTms", "OutPFSet_RmpTms", "OutPFSet_Ena", "VArWMaxPct", "VArMaxPct", "VArAvalPct", "VArPct_WinTms", "VArPct_RvrtTms",
        "VArPct_RmpTms", "VArPct_Mod", "VArPct_Ena", "WMaxLimPct_SF", "OutPFSet_SF", "VArPct_SF"]
M203 = ["A", "AphA", "AphB", "AphC", "A_SF", "PhV", "PhVphA", "PhVphB", "PhVphC", "PPV", "PPVphAB", "PPVphBC", "PPVphCA", "V_SF", "Hz", "Hz_SF", "W", "WphA", "WphB",
        "WphC", "W_SF"]
ST103 = {1: "OFF", 2: "SLEEPING", 3: "STARTING", 4: "MPPT", 5: "THROTTLED", 6: "SHUTTING_DOWN", 7: "FAULT", 8: "STANDBY"}


def mbap(tid, unit, pdu, req=None, names=None):
    b = Bld("Modbus/TCP", "MBAP header + Modbus PDU.")
    b.u16("Transaction Identifier", tid, None, "Pairs the reply with the request.")
    b.u16("Protocol Identifier", 0, "0 (Modbus)", "")
    b.u16("Length", len(pdu) + 1, None, "Unit ID + PDU.")
    b.u8("Unit Identifier", unit, None, "")
    base = len(b.b)
    b.b += pdu
    mb_dissect(b, pdu, req, names or {}, 1, base)
    return b.done()


class SunSpec(IpNet):
    key, name, cat = "sunspec", "SunSpec Modbus", "power"
    blurb = "Solar inverters and energy storage"
    medium = "SunSpec over Modbus TCP: a site energy controller discovers a PV inverter and a grid meter by their SunSpec model chains and limits export"
    faults = [("sf", "Controller ignores scale factors", "Raw integers shown as values: 2345 A instead of 23.45 A - and the export control loop goes wild."),
              ("base", "Controller probes base address 40001 instead of 40000", "The 'SunS' marker is not found where it looks: discovery fails."),
              ("gf", "Inverter ground fault", "St = 7 FAULT, Evt1 bit 0 GROUND_FAULT, output 0 W."),
              ("meter", "Grid meter offline", "No export measurement: after 3 failed reads the controller fails safe and limits the inverter to 0 %.")]
    spec = [("Standard", "SunSpec Information Models (IEEE 1547.1 / 2030.5 aligned), Modbus TCP port 502 or RTU"),
            ("Discovery", "Read 'SunS' (0x53756E53) at base 40000, then walk model headers: ID, length, ..., end marker 0xFFFF"),
            ("Models", "1 common (manufacturer, model, serial), 101-103 inverter (1 / split / 3 phase), 120-126 settings and controls, 203 3-phase meter, 7xx DER models"),
            ("Scale factors", "Integer points with a separate sunssf register: value = raw x 10^SF; 'not implemented' = 0x8000 / 0xFFFF"),
            ("Control", "Model 123: WMaxLimPct + WMaxLim_Ena (power limit), Conn (connect / disconnect), OutPFSet")]
    frame = [["Model header", ("ID", 16), ("L (registers)", 16), ("Points ...", "L x 16")], ["Base", ("'Su'", 16), ("'nS'", 16), ("Model 1 ...", "n x 16")]]
    about = ("SunSpec gives every solar inverter, battery and meter the same Modbus map, whatever the brand. A controller reads the 'SunS' "
             "marker, then follows a chain of models - each with an ID and length - so it can find, say, the 3-phase inverter model 103 "
             "without knowing the vendor. Values are integers with scale-factor registers, and control points such as the active power "
             "limit live in standard places too.")
    guide = ["Follow discovery: 'SunS' marker, model 1 header, common model (read the strings), model 103 header ...",
             "Select a model 103 reply: find W and W_SF, compute the power.",
             "Reduce the irradiance or raise the export: watch the controller write WMaxLimPct and WMaxLim_Ena (model 123).",
             "Inject 'ignore scale factors' and compare the controller's values."]

    def setup(self):
        hosts = [("ems", "SITE ENERGY CONTROLLER", "plc", 40, 40, "192.168.1.10", "00:1e:c0:00:01:10", "Modbus client"),
                 ("inv", "PV INVERTER 50 kW", "inverter", 700, 40, "192.168.1.20", "00:1e:c0:00:01:20", "SunSpec 1, 103, 123"),
                 ("mtr", "GRID METER", "meter", 700, 290, "192.168.1.30", "00:1e:c0:00:01:30", "SunSpec 1, 203")]
        self.star(hosts)
        load = self.node("load", "SITE LOAD", "box", 40, 290, "", "consumption", w=110)
        load.extra["can"] = False
        self.user = "ems"
        common = lambda md, sn: ss_str("COMM-SIM ENERGY", 16) + ss_str(md, 16) + ss_str("", 8) + ss_str("2.4.1", 8) + ss_str(sn, 16) + [1, 0x8000]
        self.inv_hr, self.inv_at = sunspec_map(40000, [(1, common("CS-INV-50K", "INV50-0042117")), (103, [0] * 50), (123, [0] * 24)])
        self.mtr_hr, self.mtr_at = sunspec_map(40000, [(1, common("CS-MTR-3P", "MTR-0008812")), (203, [0] * 105)])
        self.inv = MbServer(1, "INV", hr=self.inv_hr)
        self.mtr = MbServer(1, "MTR", hr=self.mtr_hr)
        self.names = {"inv": self._names(self.inv_at, {103: M103, 123: M123}), "mtr": self._names(self.mtr_at, {203: M203})}
        c123 = self.inv_at[123] + 2
        self.inv.hr[c123 + 2] = 1
        self.inv.hr[c123 + 3] = 100
        self.limit = 100.0
        self.pv_out = 0.0
        self.tid = 0
        self.conns = {}
        self.disc = {"inv": None, "mtr": None}
        self.miss = 0
        self.by["ems"].vars.update({"Discovery": "-", "PV W": "-", "Grid W (import +)": "-", "Limit sent": "-", "Export limit": "0 W (zero export)"})
        self.by["inv"].vars.update({"Irradiance %": 85.0, "State": "MPPT", "Limit": "100 %"})
        self.by["inv"].ctl = [("Irradiance %", "SUN", 0.0, 100.0, 0, lambda v: "%.0f %%" % v)]
        self.by["load"].vars.update({"Load kW": 32.0})
        self.by["load"].ctl = [("Load kW", "LOAD", 0.0, 80.0, 0, lambda v: "%.0f kW" % v)]
        self.every(0.25, self.physics, 0.1)
        self.at(0.05, self.connect)
        self.every(1.0, self.cycle, 1.5)

    @staticmethod
    def _names(at, models):
        out = {(3, 40000): "SunS marker 'Su'", (3, 40001): "SunS marker 'nS'"}
        for mid, a in at.items():
            if mid == "end":
                out[(3, a)] = "End marker 0xFFFF"
                continue
            out[(3, a)] = "Model %d header: ID" % mid
            out[(3, a + 1)] = "Model %d header: L" % mid
            for i, nm in enumerate(models.get(mid, [])):
                out[(3, a + 2 + i)] = "%d.%s" % (mid, nm)
        return out

    def physics(self):
        inv = self.by["inv"]
        avail = 50000 * inv.vars["Irradiance %"] / 100.0
        c123 = self.inv_at[123] + 2
        hr = self.inv.hr
        ena = hr[c123 + 7] == 1
        lim = hr[c123 + 3] if ena else 100
        target = 0.0 if (self.fault["gf"] or hr[c123 + 2] == 0) else min(avail, 500.0 * lim)
        self.pv_out += (target - self.pv_out) * 0.35
        w = self.pv_out
        st = 7 if self.fault["gf"] else (5 if (ena and 500.0 * lim < avail) else (4 if w > 100 else 2))
        inv.vars.update({"State": ST103[st], "Limit": "%d %%%s" % (lim, "" if ena else " (disabled)")})
        b = self.inv_at[103] + 2
        v = 230.0 + float(self.rng.normal(0, 0.3))
        amps = w / (3 * v)
        vals = [int(amps * 100), int(amps * 100), int(amps * 100), int(amps * 100), s16(-2), 3990, 3990, 3990, int(v * 10), int(v * 10), int(v * 10), s16(-1),
                int(w / 10), 1, 5000, s16(-2), int(w / 10), 1, 0, 1, 1000, s16(-1)]
        wh = int(getattr(self, "wh", 81_234_000))
        self.wh = wh + w * 0.25 / 3600
        vals += [wh >> 16 & 0xFFFF, wh & 0xFFFF, 0, int(w / 0.97 / 650 * 100), s16(-2), 6500, s16(-1), int(w / 0.97 / 10), 1, 412, 0x8000, 0x8000, 0x8000, s16(-1),
                 st, 0, 0, 1 if self.fault["gf"] else 0] + [0] * 10
        for i, x in enumerate(vals):
            hr[b + i] = s16(x)
        load = self.by["load"].vars["Load kW"] * 1000
        grid = load - w
        mb = self.mtr_at[203] + 2
        mv = [int(abs(grid) / (3 * v) * 10), 0, 0, 0, s16(-1), int(v * 10), int(v * 10), int(v * 10), int(v * 10), int(v * 1.732 * 10), 0, 0, 0, s16(-1), 5000,
              s16(-2), s16(grid / 10), s16(grid / 30), s16(grid / 30), s16(grid / 30), 1]
        for i, x in enumerate(mv):
            self.mtr.hr[mb + i] = s16(x)

    def connect(self):
        for k in ("inv", "mtr"):
            c = self.tcp("ems", k, 50510 + len(self.conns), 502, "Modbus/TCP")
            self.conns[k] = c
            c.connect(on_open=lambda k=k: self.at(self.t + 0.01, self.discover, k, "marker"))

    def ask(self, k, a, q, then=None, info=None, fc=3, vals=None):
        c = self.conns.get(k)
        if not c or not c.open:
            return None
        self.tid = (self.tid + 1) & 0xFFFF
        tid = self.tid
        pdu = mb_req(fc, a, q, vals)
        names = self.names[k]
        fr = c.send("ems", mbap(tid, 1, pdu, None, names), info or ("Query TID %d: %s" % (tid, mb_info(pdu))), "Modbus/TCP", "cmd", auto_ack=False)
        if k == "mtr" and self.fault["meter"]:
            self.at(self.t + 1.0, self._miss)
            return fr
        srv = self.inv if k == "inv" else self.mtr

        def reply():
            rsp = srv.handle(pdu)
            c.send(k, mbap(tid, 1, rsp, pdu, names), "Response TID %d: %s" % (tid, mb_info(rsp, pdu)), "Modbus/TCP", "err" if rsp[0] & 0x80 else "resp")
            if then and not rsp[0] & 0x80:
                regs = [struct.unpack(">H", rsp[2 + 2 * i:4 + 2 * i])[0] for i in range(rsp[1] // 2)] if rsp[0] in (3, 4) else []
                self.at(self.t + 0.001, then, regs)
        self.at(self.t + 0.002, reply)
        return fr

    def _miss(self):
        self.miss += 1
        if self.miss == 3:
            self.log("Controller: grid meter lost - fail-safe: inverter limited to 0 %")
            self.write_limit(0)

    def discover(self, k, step, a=None):
        base = 40001 if self.fault["base"] else 40000
        d = self.by["ems"].vars
        if step == "marker":
            def got(regs):
                if regs[:2] == [0x5375, 0x6E53]:
                    d["Discovery"] = "%s: SunS found at %d" % (k, base)
                    self.discover(k, "hdr", base + 2)
                else:
                    d["Discovery"] = "%s: no SunS marker at %d (read %04X %04X)" % (k, base, regs[0], regs[1])
                    self.log("Controller: SunSpec marker not found at %d - check the base address (40000 / 0 / 50000)" % base)
            self.ask(k, base, 2, got, "Discovery: read SunSpec marker at %d" % base)
        elif step == "hdr":
            def got(regs):
                mid, ln = regs
                if mid == 0xFFFF:
                    d["Discovery"] = "%s: done (end marker)" % k
                    self.disc[k] = True
                    return
                d["Discovery"] = "%s: model %d (L = %d) at %d" % (k, mid, ln, a)
                if mid == 1:
                    self.ask(k, a + 2, ln, lambda r: self.discover(k, "hdr", a + 2 + ln), "Discovery: read common model 1 (%d registers)" % ln)
                else:
                    self.discover(k, "hdr", a + 2 + ln)
            self.ask(k, a, 2, got, "Discovery: read model header at %d" % a)

    def cycle(self):
        if self.disc["inv"]:
            b = self.inv_at[103] + 2
            self.ask("inv", b, 50, self.got_inv, "Poll model 103 (3-phase inverter), 50 registers")
        if self.disc["mtr"]:
            b = self.mtr_at[203] + 2
            self.ask("mtr", b, 21, self.got_mtr, "Poll model 203 (meter) points A..W_SF, 21 registers")

    def sf(self, raw, sf, signed=True):
        r = struct.unpack(">h", struct.pack(">H", raw))[0] if signed else raw
        s = struct.unpack(">h", struct.pack(">H", sf))[0]
        return float(r) if self.fault["sf"] else r * 10.0 ** s

    def got_inv(self, regs):
        w = self.sf(regs[12], regs[13])
        st = regs[36]
        self.by["ems"].vars["PV W"] = "%.0f W (St %d %s)" % (w, st, ST103.get(st, "?"))
        self.pv_w = w

    def got_mtr(self, regs):
        self.miss = 0
        grid = self.sf(regs[16], regs[20])
        self.by["ems"].vars["Grid W (import +)"] = "%.0f W" % grid
        pv = getattr(self, "pv_w", 0.0)
        c123 = self.inv_at[123] + 2
        cur = self.limit
        if grid < -200:
            new = max(0.0, (pv + grid - 300) / 500.0)
        elif grid > 1500 and cur < 100:
            new = min(100.0, cur + 5)
        else:
            return
        if abs(new - cur) >= 1:
            self.write_limit(new)

    def write_limit(self, pct, send=True):
        c123 = self.inv_at[123] + 2
        if not send:
            pdu = mb_req(16, c123 + 3, 0, [int(pct), 0, 0, 0, 1])
            return Frame(self.t, 0.0001, "ems", "inv", "Modbus/TCP", "preview", pdu=mbap(self.tid + 1, 1, pdu, None, self.names["inv"]))
        self.limit = pct
        self.by["ems"].vars["Limit sent"] = "WMaxLimPct = %d %%" % pct
        self.ask("inv", c123 + 3, 5, None, "Write model 123 WMaxLimPct = %d %% .. WMaxLim_Ena = 1 (FC16, 5 registers)" % pct, fc=16, vals=[int(pct), 0, 0, 0, 1])
        return None

    def tpls(self):
        return [Tpl("Read a model", [P("k", "Device", "inv", opts=["inv", "mtr"], fmt=lambda v: self.by[v].label),
                                     P("m", "Model", 1, opts=[1, 103, 123, 203])], lambda s, v, send: self._rd(v, send), "Reads the whole model body after its header."),
                Tpl("Set power limit", [P("p", "WMaxLimPct %", 50, 0, 100)], lambda s, v, send: self.write_limit(v["p"], send),
                    "Model 123: WMaxLimPct and WMaxLim_Ena in one FC16 write."),
                Tpl("Disconnect / connect inverter", [P("c", "Conn", "disconnect", opts=["disconnect", "connect"])], lambda s, v, send: self._conn(v["c"] == "connect", send),
                    "Model 123 Conn = 0 / 1.")]

    def _rd(self, v, send):
        at = self.inv_at if v["k"] == "inv" else self.mtr_at
        if v["m"] not in at:
            return Frame(self.t, 0.0001, "ems", v["k"], "Modbus/TCP", "preview", pdu=mbap(0, 1, bytes([0x83, 0x02]), mb_req(3, 0, 1)))
        hr = (self.inv if v["k"] == "inv" else self.mtr).hr
        a = at[v["m"]]
        ln = min(hr[a + 1], 125)
        if not send:
            return Frame(self.t, 0.0001, "ems", v["k"], "Modbus/TCP", "preview", pdu=mbap(self.tid + 1, 1, mb_req(3, a + 2, ln), None, self.names[v["k"]]))
        self.ask(v["k"], a + 2, ln, None, "Read model %d (%d registers at %d)" % (v["m"], ln, a + 2))
        return None

    def _conn(self, on, send):
        c123 = self.inv_at[123] + 2
        if not send:
            return Frame(self.t, 0.0001, "ems", "inv", "Modbus/TCP", "preview", pdu=mbap(self.tid + 1, 1, mb_req(6, c123 + 2, 0, int(on)), None, self.names["inv"]))
        self.ask("inv", c123 + 2, 1, None, "Write model 123 Conn = %d (%s)" % (on, "connect" if on else "disconnect"), fc=6, vals=int(on))
        return None

    def on_fault(self, key, on):
        if key == "base" and not on:
            self.at(self.t + 0.1, self.discover, "inv", "marker")
            self.at(self.t + 0.3, self.discover, "mtr", "marker")
        if key == "meter" and not on:
            self.miss = 0


# ==================================================================== OCPP
def ocpp_pdu(msg, masked, title):
    p = ws_frame(jdump(msg), masked=masked, title=title)
    rows = [[0, "OCPP-J message (JSON array)", None, 0, "[2, id, action, payload] = CALL; [3, id, payload] = CALLRESULT; [4, id, code, text, details] = CALLERROR."]]
    kind = {2: "CALL", 3: "CALLRESULT", 4: "CALLERROR"}[msg[0]]
    rows.append([1, "MessageTypeId: %d (%s)" % (msg[0], kind), None, 0, ""])
    rows.append([1, "UniqueId: \"%s\"" % msg[1], None, 0, "Pairs the result with the call."])
    if msg[0] == 2:
        rows.append([1, "Action: %s" % msg[2], None, 0, ""])
        body = msg[3]
    elif msg[0] == 3:
        body = msg[2]
    else:
        rows.append([1, "ErrorCode: %s" % msg[2], None, 0, ""])
        body = msg[4]
    for k, v in body.items():
        rows.append([2, "%s: %s" % (k, jdump(v)[:120]), None, 0, ""])
    p.rows += rows
    return p


class OCPP(IpNet):
    key, name, cat = "ocpp", "OCPP", "power"
    blurb = "Electric vehicle charging stations"
    medium = "OCPP 1.6J: an AC charging station keeps a WebSocket open to the charging station management system (CSMS) in the cloud; JSON CALL / CALLRESULT messages"
    faults = [("card", "Driver presents an unknown RFID card", "Authorize returns idTagInfo.status = Invalid: no charging session."),
              ("offline", "Backend connection lost", "The station keeps charging with its local authorization, queues transaction messages and sends them after reconnecting."),
              ("boot", "Station not registered in the CSMS", "BootNotification is answered with Rejected: the station retries after 'interval' and may not send anything else."),
              ("gf", "Ground fault in the EV supply", "StatusNotification Faulted / GroundFailure; the running transaction is stopped.")]
    spec = [("Standard", "Open Charge Point Protocol 1.6 (OCPP-J, JSON over WebSocket) - OCPP 2.0.1 adds device model, security, ISO 15118; Open Charge Alliance"),
            ("Transport", "WebSocket (RFC 6455) sub-protocol 'ocpp1.6'; ws:// or wss:// with basic auth or client certificates (security profiles 1-3)"),
            ("Messages", "CALL [2, id, action, payload], CALLRESULT [3, id, payload], CALLERROR [4, id, code, description, details]"),
            ("Station -> CSMS", "BootNotification, Heartbeat, StatusNotification, Authorize, StartTransaction, MeterValues, StopTransaction"),
            ("CSMS -> station", "RemoteStart / RemoteStopTransaction, SetChargingProfile (smart charging), Reset, ChangeAvailability, TriggerMessage"),
            ("Rules", "One outstanding CALL per direction; idTag authorization, transactionId issued by the CSMS")]
    frame = [["CALL", ("[2,", 16), ("\"uniqueId\",", "n x 8"), ("\"Action\",", "n x 8"), ("{payload}]", "n x 8")]]
    about = ("OCPP connects charging stations to the operator's back office. The station opens a WebSocket to the central system and announces "
             "itself with a BootNotification; from then on both sides send small JSON calls. A charging session is an Authorize of the RFID "
             "tag, a StartTransaction that returns a transaction ID, periodic MeterValues and a StopTransaction - and the back office can "
             "limit power at any time with a charging profile.")
    guide = ["Follow the WebSocket upgrade (HTTP 101) and the BootNotification / Accepted with the heartbeat interval.",
             "Watch the session start when the EV plugs in: Preparing, Authorize, StartTransaction (transactionId), Charging.",
             "COMPOSE a SetChargingProfile limiting the current to 10 A and watch the power drop in MeterValues.",
             "Drop the backend connection mid-session and watch the queued messages arrive after reconnecting."]

    def setup(self):
        hosts = [("cs", "AC CHARGING STATION", "evse", 40, 290, "192.168.10.20", "00:24:a5:22:00:17", "CP-001, 22 kW"),
                 ("csms", "CSMS (CLOUD BACKEND)", "csms", 700, 40, "34.90.12.80", "00:50:56:30:00:80", "wss endpoint")]
        self.star(hosts, sw=("sw", "SITE ROUTER / 4G", 380, 160))
        ev = self.node("ev", "ELECTRIC VEHICLE", "battery", 200, 300, "", "Type 2 cable", w=120)
        ev.extra["can"] = False
        self.seg([(158, 316), (200, 316)], "wire", label="CP / PE / L1-L3", c0="screw", c1="screw")
        self.user = "csms"
        self.mid = 1000
        self.c = None
        self.ws = False
        self.pending = {}
        self.outq = []
        self.tx_id = None
        self.limit_a = 32.0
        self.wh = 1_523_400
        self.soc = 34.0
        self.state = "Available"
        self.booted = False
        self.plugged = False
        self.by["cs"].vars.update({"Connector 1": "Available", "Transaction": "-", "Power": "0 kW", "Energy register": "%.1f kWh" % (self.wh / 1000.0)})
        self.by["csms"].vars.update({"Station": "offline", "Sessions": 0, "Last message": "-"})
        self.by["ev"].vars.update({"SoC": "34 %", "Max current": "32 A"})
        self.at(0.05, self.connect)
        self.at(4.0, self.plug_in)
        self.every(0.5, self.physics, 0.5)
        self.every(10.0, self.meter_values, 12.0)

    # ------------------------------------------------------- transport
    def connect(self):
        if self.fault["offline"]:
            self.at(self.t + 5.0, self.connect)
            return
        self.c = self.tcp("cs", "csms", 49800 + int(self.t) % 100, 9000, "WebSocket")
        self.c.connect(on_open=self.upgrade)

    def upgrade(self):
        c = self.c
        c.send("cs", http_req("GET", "/ocpp/CP-001", [("Host", "csms.example.net:9000"), ("Upgrade", "websocket"), ("Connection", "Upgrade"),
                                                      ("Sec-WebSocket-Key", "x3JJHMbDL1EzLkh9GBhXDw=="), ("Sec-WebSocket-Version", "13"),
                                                      ("Sec-WebSocket-Protocol", "ocpp1.6"), ("Authorization", "Basic Q1AtMDAxOnNlY3JldA==")]),
               "HTTP GET /ocpp/CP-001 Upgrade: websocket, Sec-WebSocket-Protocol: ocpp1.6", "HTTP", "cmd")

        def rsp():
            c.send("csms", http_rsp(101, [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Sec-WebSocket-Accept", "HSmrc0sMlYUkAGmm5OPpG2HaGWk="),
                                          ("Sec-WebSocket-Protocol", "ocpp1.6")]), "HTTP/1.1 101 Switching Protocols (ocpp1.6)", "HTTP", "resp")
            self.ws = True
            self.by["csms"].vars["Station"] = "connected"
            self.at(self.t + 0.05, self.boot)
        self.at(self.t + 0.02, rsp)

    def call(self, action, payload, then=None, send=True):
        self.mid += 1
        uid = str(self.mid)
        msg = [2, uid, action, payload]
        if not send:
            return Frame(self.t, 0.0001, "cs", "csms", "OCPP", "preview", pdu=ocpp_pdu(msg, True, "WebSocket: OCPP CALL %s" % action))
        if not (self.ws and self.c and self.c.open):
            if action in ("StopTransaction", "MeterValues", "StartTransaction"):
                self.outq.append((action, payload, then))
                self.by["cs"].vars["Queued"] = len(self.outq)
            return None
        self.c.send("cs", ocpp_pdu(msg, True, "WebSocket: OCPP CALL %s" % action), ("CALL %s %s" % (action, self._sum(action, payload))).strip(), "OCPP", "cmd")
        self.at(self.t + 0.03, self.csms_handle, uid, action, payload, then)
        return None

    @staticmethod
    def _sum(action, p):
        if action == "StatusNotification":
            return "connector %d %s%s" % (p["connectorId"], p["status"], (" (%s)" % p["errorCode"]) if p["errorCode"] != "NoError" else "")
        if action == "Authorize":
            return "idTag %s" % p["idTag"]
        if action == "StartTransaction":
            return "connector %d idTag %s meterStart %d Wh" % (p["connectorId"], p["idTag"], p["meterStart"])
        if action == "StopTransaction":
            return "transaction %d meterStop %d Wh reason %s" % (p["transactionId"], p["meterStop"], p.get("reason", "Local"))
        if action == "MeterValues":
            sv = p["meterValue"][0]["sampledValue"]
            return "transaction %s: %s Wh, %s W" % (p.get("transactionId"), sv[0]["value"], sv[1]["value"])
        return ""

    def result(self, uid, payload, info, kind="resp"):
        if not (self.ws and self.c and self.c.open):
            return
        self.c.send("csms", ocpp_pdu([3, uid, payload], False, "WebSocket: OCPP CALLRESULT"), "CALLRESULT %s %s" % (uid, info), "OCPP", kind)
        self.by["csms"].vars["Last message"] = info

    # -------------------------------------------------------- CSMS side
    def csms_handle(self, uid, action, p, then):
        now = utc(self.t).strftime("%Y-%m-%dT%H:%M:%SZ")
        out = {}
        if action == "BootNotification":
            out = {"status": "Rejected" if self.fault["boot"] else "Accepted", "currentTime": now, "interval": 30 if self.fault["boot"] else 60}
            info = "BootNotification: %s, interval %d s" % (out["status"], out["interval"])
        elif action == "Heartbeat":
            out, info = {"currentTime": now}, "Heartbeat: currentTime"
        elif action == "StatusNotification":
            info = "StatusNotification: {}"
        elif action == "Authorize":
            st = "Invalid" if self.fault["card"] else "Accepted"
            out, info = {"idTagInfo": {"status": st, "expiryDate": "2027-12-31T23:59:59Z"}}, "Authorize: idTagInfo %s" % st
        elif action == "StartTransaction":
            self.by["csms"].vars["Sessions"] += 1
            out, info = {"transactionId": 5871 + self.by["csms"].vars["Sessions"], "idTagInfo": {"status": "Accepted"}}, "StartTransaction: transactionId %d" % (5871 + self.by["csms"].vars["Sessions"])
        elif action == "StopTransaction":
            out, info = {"idTagInfo": {"status": "Accepted"}}, "StopTransaction: accepted"
        elif action == "MeterValues":
            info = "MeterValues: {}"
        else:
            info = action
        self.result(uid, out, info, "ack" if not out else "resp")
        if then:
            self.at(self.t + 0.03, then, out)

    def csms_call(self, action, payload, info, on_res=None, send=True):
        uid = "c%05d" % int(self.rng.integers(0, 99999))
        msg = [2, uid, action, payload]
        p = ocpp_pdu(msg, False, "WebSocket: OCPP CALL %s (from the CSMS)" % action)
        if not send:
            return Frame(self.t, 0.0001, "csms", "cs", "OCPP", "preview", pdu=p)
        if not (self.ws and self.c and self.c.open):
            return None
        self.c.send("csms", p, "CALL %s %s" % (action, info), "OCPP", "cmd")
        self.at(self.t + 0.03, self.cs_handle, uid, action, payload)
        return None

    # ------------------------------------------------------ station side
    def boot(self):
        def done(r):
            if r.get("status") == "Accepted":
                self.booted = True
                self.by["csms"].vars["Station"] = "Accepted (BootNotification)"
                self.status(0, "Available")
                self.at(self.t + 0.1, self.status, 1, self.state)
                self.at(self.t + 1.0, self.flush)
                self.at(self.t + r.get("interval", 60), self.heartbeat)
            else:
                self.by["csms"].vars["Station"] = "Rejected: retry in %d s" % r.get("interval", 30)
                self.at(self.t + r.get("interval", 30), self.boot)
        self.call("BootNotification", {"chargePointVendor": "CommSim", "chargePointModel": "CS-AC22", "chargePointSerialNumber": "CS22-00117",
                                       "firmwareVersion": "1.4.2", "meterType": "MID 3-phase"}, done)

    def heartbeat(self):
        if self.booted and self.ws:
            self.call("Heartbeat", {}, lambda r: self.at(self.t + 60, self.heartbeat))

    def status(self, conn, st, err="NoError"):
        if conn == 1:
            self.state = st
            self.by["cs"].vars["Connector 1"] = st + ("" if err == "NoError" else " (%s)" % err)
        if self.booted:
            self.call("StatusNotification", {"connectorId": conn, "errorCode": err, "status": st, "timestamp": utc(self.t).strftime("%Y-%m-%dT%H:%M:%SZ")})

    def flush(self):
        q, self.outq = self.outq, []
        self.by["cs"].vars.pop("Queued", None)
        for i, (a, p, then) in enumerate(q):
            self.at(self.t + 0.2 * i, self.call, a, p, then)

    def plug_in(self):
        if self.state != "Available":
            return
        self.plugged = True
        self.by["ev"].sub = "plugged in"
        self.status(1, "Preparing")
        self.at(self.t + 1.5, self.authorize, "04A2B3C4D5")

    def authorize(self, tag):
        def done(r):
            if r["idTagInfo"]["status"] != "Accepted":
                self.log("Station: card %s rejected (%s)" % (tag, r["idTagInfo"]["status"]))
                self.by["cs"].vars["Transaction"] = "card rejected"
                return
            self.start(tag)
        self.call("Authorize", {"idTag": tag}, done)

    def start(self, tag):
        def done(r):
            self.tx_id = r.get("transactionId")
            self.by["cs"].vars["Transaction"] = "%d (%s)" % (self.tx_id, tag)
            self.status(1, "Charging")
        self.tx_id = -1
        self.call("StartTransaction", {"connectorId": 1, "idTag": tag, "meterStart": int(self.wh), "timestamp": utc(self.t).strftime("%Y-%m-%dT%H:%M:%SZ")}, done)

    def stop(self, reason="Local"):
        if self.tx_id is None:
            return
        tid = self.tx_id
        self.tx_id = None
        self.by["cs"].vars["Transaction"] = "-"
        self.call("StopTransaction", {"transactionId": tid, "meterStop": int(self.wh), "timestamp": utc(self.t).strftime("%Y-%m-%dT%H:%M:%SZ"), "reason": reason})
        self.at(self.t + 0.2, self.status, 1, "Finishing")

    def power_w(self):
        if self.tx_id is None or self.state != "Charging" or self.fault["gf"]:
            return 0.0
        amps = min(self.limit_a, 32.0) if self.soc < 90 else min(self.limit_a, 10.0)
        return 3 * 230.0 * amps

    def physics(self):
        w = self.power_w()
        self.wh += w * 0.5 / 3600
        self.soc = min(100.0, self.soc + w * 0.5 / 3600 / 77000.0 * 100)
        self.by["cs"].vars["Power"] = "%.1f kW" % (w / 1000.0)
        self.by["cs"].vars["Energy register"] = "%.1f kWh" % (self.wh / 1000.0)
        self.by["ev"].vars["SoC"] = "%.1f %%" % self.soc

    def meter_values(self):
        if self.tx_id is None or self.tx_id == -1:
            return
        w = self.power_w()
        a = w / 690.0
        self.call("MeterValues", {"connectorId": 1, "transactionId": self.tx_id, "meterValue": [{"timestamp": utc(self.t).strftime("%Y-%m-%dT%H:%M:%SZ"), "sampledValue": [
            {"value": "%d" % self.wh, "measurand": "Energy.Active.Import.Register", "unit": "Wh"},
            {"value": "%d" % w, "measurand": "Power.Active.Import", "unit": "W"},
            {"value": "%.1f" % a, "measurand": "Current.Import", "phase": "L1", "unit": "A"},
            {"value": "%.0f" % self.soc, "measurand": "SoC", "unit": "Percent"}]}]})

    def cs_handle(self, uid, action, p):
        if action == "SetChargingProfile":
            lim = p["csChargingProfiles"]["chargingSchedule"]["chargingSchedulePeriod"][0]["limit"]
            self.limit_a = lim
            self.by["ev"].vars["Max current"] = "%.0f A (profile)" % lim
            self.c.send("cs", ocpp_pdu([3, uid, {"status": "Accepted"}], True, "WebSocket: OCPP CALLRESULT"), "CALLRESULT %s SetChargingProfile: Accepted" % uid, "OCPP", "resp")
        elif action == "RemoteStopTransaction":
            ok = self.tx_id is not None and p["transactionId"] == self.tx_id
            self.c.send("cs", ocpp_pdu([3, uid, {"status": "Accepted" if ok else "Rejected"}], True, "WebSocket: OCPP CALLRESULT"),
                        "CALLRESULT %s RemoteStopTransaction: %s" % (uid, "Accepted" if ok else "Rejected"), "OCPP", "resp")
            if ok:
                self.at(self.t + 0.2, self.stop, "Remote")
        elif action == "RemoteStartTransaction":
            ok = self.tx_id is None and self.plugged
            self.c.send("cs", ocpp_pdu([3, uid, {"status": "Accepted" if ok else "Rejected"}], True, "WebSocket: OCPP CALLRESULT"),
                        "CALLRESULT %s RemoteStartTransaction: %s" % (uid, "Accepted" if ok else "Rejected"), "OCPP", "resp")
            if ok:
                self.at(self.t + 0.2, self.start, p["idTag"])
        elif action == "TriggerMessage":
            self.c.send("cs", ocpp_pdu([3, uid, {"status": "Accepted"}], True, "WebSocket: OCPP CALLRESULT"), "CALLRESULT %s TriggerMessage: Accepted" % uid, "OCPP", "resp")
            self.at(self.t + 0.1, self.meter_values if p["requestedMessage"] == "MeterValues" else (lambda: self.status(1, self.state)))
        elif action == "Reset":
            self.c.send("cs", ocpp_pdu([3, uid, {"status": "Accepted"}], True, "WebSocket: OCPP CALLRESULT"), "CALLRESULT %s Reset: Accepted" % uid, "OCPP", "resp")
            self.at(self.t + 0.3, self.reboot)

    def reboot(self):
        self.stop("SoftReset")
        if self.c and self.c.open:
            self.c.close("cs")
        self.ws = False
        self.booted = False
        self.by["csms"].vars["Station"] = "offline (rebooting)"
        self.at(self.t + 3.0, self.connect)

    def on_fault(self, key, on):
        if key == "offline":
            if on and self.c and self.c.open:
                self.c.reset("cs")
                self.ws = False
                self.booted = False
                self.by["csms"].vars["Station"] = "offline"
                self.log("Station: WebSocket lost - continues the session locally and queues messages")
            elif not on:
                self.at(self.t + 0.5, self.connect)
        if key == "gf" and on:
            self.status(1, "Faulted", "GroundFailure")
            self.at(self.t + 0.1, self.stop, "Other")
        if key == "gf" and not on and self.plugged:
            self.at(self.t + 0.5, self.status, 1, "Preparing")
        if key == "card" and not on and self.tx_id is None and self.plugged:
            self.at(self.t + 0.5, self.authorize, "04A2B3C4D5")
        if key == "boot" and not on and not self.booted:
            self.at(self.t + 0.5, self.boot)

    def tpls(self):
        return [Tpl("SetChargingProfile (current limit)", [P("a", "Limit (A)", 10.0, 6.0, 32.0, 1.0)], lambda s, v, send: self._prof(v["a"], send),
                    "TxProfile on connector 1 with one schedule period: the EV current drops to the limit."),
                Tpl("RemoteStopTransaction", [], lambda s, v, send: self.csms_call("RemoteStopTransaction", {"transactionId": self.tx_id or 0},
                                                                                 "transaction %s" % self.tx_id, send=send), "The CSMS ends the session; the station sends StopTransaction."),
                Tpl("RemoteStartTransaction", [P("tag", "idTag", "APP-USER-77")], lambda s, v, send: self.csms_call("RemoteStartTransaction", {"connectorId": 1, "idTag": v["tag"]},
                                                                                                                   "idTag %s" % v["tag"], send=send), "Start from the app (needs the EV plugged in and no session)."),
                Tpl("TriggerMessage", [P("m", "Message", "MeterValues", opts=["MeterValues", "StatusNotification"])],
                    lambda s, v, send: self.csms_call("TriggerMessage", {"requestedMessage": v["m"], "connectorId": 1}, v["m"], send=send), "Ask the station to send a message now."),
                Tpl("Reset (soft)", [], lambda s, v, send: self.csms_call("Reset", {"type": "Soft"}, "Soft", send=send), "Station stops the session, reboots and boots again.")]

    def _prof(self, a, send):
        prof = {"connectorId": 1, "csChargingProfiles": {"chargingProfileId": 12, "stackLevel": 1, "chargingProfilePurpose": "TxProfile", "chargingProfileKind": "Absolute",
                                                         "chargingSchedule": {"chargingRateUnit": "A", "chargingSchedulePeriod": [{"startPeriod": 0, "limit": float(a)}]}}}
        return self.csms_call("SetChargingProfile", prof, "limit %.0f A" % a, send=send)


# ========================================================== M-Bus (wired)
def mbus_man(code):
    v = ((ord(code[0]) - 64) << 10) | ((ord(code[1]) - 64) << 5) | (ord(code[2]) - 64)
    return struct.pack("<H", v)


def bcd_le(v, nbytes):
    s = "%0*d" % (2 * nbytes, int(v))
    return bytes(int(s[i:i + 2], 16) for i in range(0, 2 * nbytes, 2))[::-1]


MBUS_MED = {0x02: "electricity", 0x04: "heat (outlet)", 0x07: "water"}


class MBus(Scenario):
    key, name, cat = "mbus", "M-Bus", "power"
    blurb = "Utility metering (heat, water, gas, electricity)"
    phy, rate = "mbus", 2400
    medium = "Wired M-Bus (EN 13757-2/-3): a level converter powers the 2-wire bus (36 V) and polls water, heat and electricity meters at 2400 bit/s"
    nets = [("V", "Bus voltage: master sends by modulating 36 / 24 V"), ("I", "Bus current: meters answer by drawing +11..20 mA")]
    lines = ["M", "S"]
    faults = [("short", "Short circuit on the bus", "The level converter detects overcurrent and switches the bus off: no meter can be read."),
              ("dup", "Two meters with primary address 2", "Both answer at once: the current pulses add up, the master sees garbage. Use secondary addressing."),
              ("dead", "Electricity meter not responding", "Timeouts on every request for address 3."),
              ("baud", "Heat meter left at 300 bit/s", "It cannot decode 2400 bit/s requests and never answers.")]
    spec = [("Standard", "EN 13757-2 (physical and link layer), EN 13757-3 (application layer), EN 13757-7 (security); Wireless M-Bus in EN 13757-4"),
            ("Physical", "2 wires, any polarity and topology; master -> meters: voltage 36 V (mark) / 24 V (space); meters -> master: current 1.5 mA / +11-20 mA; meters may be bus-powered"),
            ("Link", "2400 bit/s typical (300-9600), 8E1; single char E5h, short frame 10h C A CS 16h, long frame 68h L L 68h C A CI data CS 16h"),
            ("Addressing", "Primary 1-250 (253 = selected by secondary address, 254 / 255 broadcast); secondary = 8-digit ID + manufacturer + version + medium"),
            ("Data", "Variable data structure (CI 72h): fixed header + records of DIF, VIF (unit / scale), value (binary or BCD)")]
    frame = [["Long frame", ("68h", 8), ("L", 8), ("L", 8), ("68h", 8), ("C", 8), ("A", 8), ("CI", 8), ("Data", "n x 8"), ("CS", 8), ("16h", 8)],
             ["Record", ("DIF", 8), ("[DIFE]", 8), ("VIF", 8), ("[VIFE]", 8), ("Value", "n x 8")]]
    about = ("M-Bus is the meter-reading bus in many apartment buildings: one pair of wires links the heat, water and electricity meters to a "
             "data logger, which also powers them. The master talks by modulating the bus voltage; meters answer by modulating the current "
             "they draw. Each reply carries the meter's identity and a list of records whose DIF and VIF codes say what the value is and in "
             "which unit.")
    guide = ["SCOPE: the master's voltage pulses (36 / 24 V) and the meters' current pulses on the I probe.",
             "Select an RSP_UD from the water meter: ID, manufacturer, medium, then each DIF / VIF record.",
             "Watch the FCB toggle in successive REQ_UD2 to the same meter.",
             "Give two meters the same address and read one by secondary address (COMPOSE)."]

    def build(self):
        m = self.node("m", "M-BUS LEVEL CONVERTER", "gw", 30, 40, "master", "36 V, 2400 bit/s", w=150)
        mt = [("w", "WATER METER", "meter", 230, 260, "addr 1", "ID 12345678"), ("h", "HEAT METER", "meter", 470, 260, "addr 2", "ID 23456789"),
              ("e", "ELECTRICITY METER", "meter", 700, 260, "addr 3", "ID 34567890")]
        ns = [self.node(*x) for x in mt]
        for n in ns:
            n.at_top()
        self.trunk(180, 60, 850, [m] + ns, "tsp", net="V", label="M-Bus 2-wire (J-Y(St)Y 2x2x0.8)", c="screw")
        self.user = "m"
        self.meters = {1: dict(id=12345678, man="CSM", ver=0x10, med=0x07, nid="w", acc=0, fcb=None, vol=1234.567, flow=0.0),
                       2: dict(id=23456789, man="CSM", ver=0x21, med=0x04, nid="h", acc=0, fcb=None, kwh=48210, m3=812.33, tf=68, tr=44),
                       3: dict(id=34567890, man="CSM", ver=0x05, med=0x02, nid="e", acc=0, fcb=None, wh10=1523400, p=2300)}
        self.fcb = {1: 0, 2: 0, 3: 0}
        self.k = 0
        self.busy = False
        m.vars.update({"Bus": "36 V, 4.5 mA", "Water m3": "-", "Heat kWh": "-", "Electricity kWh": "-", "Timeouts": 0})
        ns[0].vars.update({"Flow l/h": 420.0})
        ns[0].ctl = [("Flow l/h", "FLOW", 0.0, 2500.0, 0, lambda v: "%.0f l/h" % v)]
        self.every(1.0, self.cycle, 0.5)
        self.every(0.5, self.physics, 0.25)
        self.at(0.1, self.nke, 254)

    def physics(self):
        w = self.meters[1]
        w["flow"] = self.by["w"].vars["Flow l/h"]
        w["vol"] += w["flow"] * 0.5 / 3600 / 1000
        h = self.meters[2]
        h["kwh"] += 0.002
        e = self.meters[3]
        e["p"] = int(2300 + 200 * math.sin(self.t / 4))
        e["wh10"] += e["p"] * 0.5 / 3600 / 10
        self.by["m"].vars["Bus"] = "0 V - OVERLOAD, bus switched off" if self.fault["short"] else "36 V, 4.5 mA (3 meters x 1.5 mA)"

    def short(self, c, a, title):
        cs = (c + a) & 0xFF
        b = Bld("M-Bus short frame: %s" % title, "Start 10h, C, A, checksum, 16h.")
        b.u8("Start", 0x10, "10h", "")
        b.u8("C field", c, self._ctxt(c), "Function and frame count bit.")
        b.u8("A field (primary address)", a, {254: "254 (broadcast, all reply)", 255: "255 (broadcast, no reply)", 253: "253 (meter selected by secondary address)"}.get(a, str(a)), "")
        b.u8("Checksum", cs, "0x%02X [correct]" % cs, "Sum of C and A modulo 256.")
        b.u8("Stop", 0x16, "16h", "")
        return b.done()

    @staticmethod
    def _ctxt(c):
        names = {0x40: "SND_NKE (initialise)", 0x53: "SND_UD (send user data)", 0x73: "SND_UD (FCB 1)", 0x5B: "REQ_UD2 (request class 2 data)",
                 0x7B: "REQ_UD2 (FCB 1)", 0x08: "RSP_UD (respond user data)"}
        return "0x%02X %s%s" % (c, names.get(c, "?"), (", FCB %d" % (c >> 5 & 1)) if c & 0x10 and c & 0x40 else "")

    def long(self, c, a, ci, recs, title):
        b = Bld("M-Bus long frame: %s" % title, "68h L L 68h, C, A, CI, data, checksum, 16h.")
        data = bytes([c, a, ci]) + b"".join(r[1] for r in recs)
        cs = sum(data) & 0xFF
        b.u8("Start", 0x68, "68h", "")
        b.u8("L field", len(data), str(len(data)), "Bytes from C to the end of the data.")
        b.u8("L field (repeated)", len(data), str(len(data)), "")
        b.u8("Start (repeated)", 0x68, "68h", "")
        b.u8("C field", c, self._ctxt(c), "")
        b.u8("A field", a, str(a), "")
        b.u8("CI field", ci, {0x72: "72h variable data structure (long header)", 0x52: "52h select slave (secondary address)", 0x51: "51h data send",
                              0x50: "50h application reset"}.get(ci, "%02Xh" % ci), "Control information: what the data part contains.")
        for lab, raw, txt, d in recs:
            b.raw(lab, raw, txt, d)
        b.u8("Checksum", cs, "0x%02X [correct]" % cs, "Arithmetic sum from C to the last data byte, modulo 256.")
        b.u8("Stop", 0x16, "16h", "")
        return b.done()

    def hdr_recs(self, mt):
        return [("Identification number", bcd_le(mt["id"], 4), "%08d (BCD, LSB first)" % mt["id"], "Secondary address part 1: serial number."),
                ("Manufacturer", mbus_man(mt["man"]), "%s (3 letters packed in 15 bits)" % mt["man"], "FLAG association code."),
                ("Version", bytes([mt["ver"]]), "0x%02X" % mt["ver"], ""),
                ("Medium (device type)", bytes([mt["med"]]), "0x%02X %s" % (mt["med"], MBUS_MED[mt["med"]]), ""),
                ("Access number", bytes([mt["acc"] & 255]), str(mt["acc"] & 255), "Counts the meter's replies."),
                ("Status", b"\x00", "0x00 no error", "Application busy, error, power low, permanent / temporary error bits."),
                ("Signature", b"\x00\x00", "0000 (no encryption)", "Encryption mode (EN 13757-7) when used.")]

    def data_recs(self, a):
        mt = self.meters[a]
        d = utc(self.t)
        typef = struct.pack("<I", d.minute | (d.hour << 8) | (d.day << 16) | ((d.year % 100 & 7) << 21) | (d.month << 24) | ((d.year % 100 >> 3) << 28))
        tr = [("Record: date/time", bytes([0x04, 0x6D]) + typef, d.strftime("%Y-%m-%d %H:%M (type F)"), "DIF 04h 32-bit, VIF 6Dh date and time.")]
        if a == 1:
            return [("Record: volume", bytes([0x0C, 0x13]) + bcd_le(int(mt["vol"] * 1000), 4), "%.3f m3" % mt["vol"], "DIF 0Ch 8-digit BCD, VIF 13h volume in litres (10^-3 m3)."),
                    ("Record: volume flow", bytes([0x0B, 0x3B]) + bcd_le(int(mt["flow"]), 3), "%d l/h" % mt["flow"], "DIF 0Bh 6-digit BCD, VIF 3Bh volume flow l/h.")] + tr + \
                   [("Record: error flags", bytes([0x02, 0xFD, 0x17, 0x00, 0x00]), "0000 none", "DIF 02h 16-bit, VIF FDh + VIFE 17h error flags.")]
        if a == 2:
            return [("Record: energy", bytes([0x0C, 0x06]) + bcd_le(int(mt["kwh"]), 4), "%d kWh" % mt["kwh"], "DIF 0Ch 8-digit BCD, VIF 06h energy kWh."),
                    ("Record: volume", bytes([0x0C, 0x14]) + bcd_le(int(mt["m3"] * 100), 4), "%.2f m3" % mt["m3"], "VIF 14h volume 10^-2 m3."),
                    ("Record: flow temperature", bytes([0x0A, 0x5B]) + bcd_le(mt["tf"], 2), "%d degC" % mt["tf"], "DIF 0Ah 4-digit BCD, VIF 5Bh flow temperature degC."),
                    ("Record: return temperature", bytes([0x0A, 0x5F]) + bcd_le(mt["tr"], 2), "%d degC" % mt["tr"], "VIF 5Fh return temperature degC.")] + tr
        return [("Record: energy", bytes([0x0C, 0x04]) + bcd_le(int(mt["wh10"]), 4), "%.2f kWh" % (mt["wh10"] / 100.0), "DIF 0Ch 8-digit BCD, VIF 04h energy in 10 Wh."),
                ("Record: power", bytes([0x0B, 0x2B]) + bcd_le(mt["p"], 3), "%d W" % mt["p"], "DIF 0Bh 6-digit BCD, VIF 2Bh power W.")] + tr

    def send(self, src, dst, pdu, info, kind, err=None, line="M"):
        fr = serial_frame(self, src, dst, "M-Bus", info, pdu, 2400, 8, "E", 1, line=line, kind=kind, err=err)
        self.tx(fr, ifs=0.012)
        return fr

    # master -------------------------------------------------------------
    def cycle(self):
        if self.busy or not self.by["m"].on:
            return
        self.k = self.k % 3 + 1
        self.req(self.k)

    def nke(self, a, send=True):
        p = self.short(0x40, a, "SND_NKE")
        if not send:
            return Frame(self.t, 0.02, "m", None, "M-Bus", "preview", pdu=p)
        if self.fault["short"]:
            return None
        self.send("m", None if a >= 254 else self.meters.get(a, {}).get("nid"), p, "SND_NKE to %s: initialise (reset FCB)" % ("all (254)" if a == 254 else "address %d" % a), "ctl")
        for k in self.meters:
            if a in (254, 255, k):
                self.meters[k]["fcb"] = None
                self.fcb[k] = 0
        if a != 254:
            self.at(self.t + 0.06, self._e5, a)
        return None

    def _e5(self, a):
        mt = self.meters.get(a)
        if not mt or self.fault["short"]:
            return
        p = Pdu(b"\xE5", [[0, "M-Bus single character", 0, 1, ""], [1, "E5h: ACK", 0, 1, "Acknowledges SND_NKE / SND_UD."]])
        self.send(mt["nid"], "m", p, "E5h ACK from address %d" % a, "ack", line="S")

    def req(self, a, send=True, addr=None):
        addr = a if addr is None else addr
        self.fcb[a] ^= 1
        c = 0x5B | (self.fcb[a] << 5)
        p = self.short(c, addr, "REQ_UD2")
        if not send:
            return Frame(self.t, 0.02, "m", None, "M-Bus", "preview", pdu=p)
        if self.fault["short"]:
            return None
        nid = self.meters[a]["nid"]
        fr = self.send("m", nid, p, "REQ_UD2 -> address %d (FCB %d)" % (addr, self.fcb[a]), "cmd")
        self.busy = True
        tok = object()
        self.tok = tok
        self.at(fr.t + fr.dur + 0.4, self._to, tok, a)
        self.at(fr.t + fr.dur + 0.05, self.meter_rsp, a, tok)
        return fr

    def _to(self, tok, a):
        if self.tok is tok:
            self.busy = False
            self.by["m"].vars["Timeouts"] += 1
            self.log("Master: no answer from address %d" % a)

    def meter_rsp(self, a, tok):
        mt = self.meters[a]
        if not self.by[mt["nid"]].on or (a == 3 and self.fault["dead"]) or (a == 2 and self.fault["baud"]):
            return
        mt["acc"] += 1
        recs = [(l, r, t, d) for l, r, t, d in self.hdr_recs(mt)] + [(l, r, t, d) for l, r, t, d in self.data_recs(a)]
        p = self.long(0x08, a, 0x72, recs, "RSP_UD from %s meter" % MBUS_MED[mt["med"]])
        err = None
        if self.fault["dup"] and a == 2:
            err = "Two meters answered: overlapping current pulses, parity / checksum errors"
        self.send(mt["nid"], "m", p, "RSP_UD address %d: %s meter ID %08d, %s" % (a, MBUS_MED[mt["med"]], mt["id"], self._val(a)), "resp", err, line="S")
        self.tok = None
        self.busy = False
        if not err:
            v = self.by["m"].vars
            if a == 1:
                v["Water m3"] = "%.3f" % mt["vol"]
            elif a == 2:
                v["Heat kWh"] = "%d" % mt["kwh"]
            else:
                v["Electricity kWh"] = "%.2f" % (mt["wh10"] / 100.0)

    def _val(self, a):
        mt = self.meters[a]
        if a == 1:
            return "%.3f m3" % mt["vol"]
        if a == 2:
            return "%d kWh" % mt["kwh"]
        return "%.2f kWh" % (mt["wh10"] / 100.0)

    def select(self, a, send=True):
        mt = self.meters[a]
        recs = [("Identification (select)", bcd_le(mt["id"], 4), "%08d" % mt["id"], "Wildcards (F) allowed per digit."),
                ("Manufacturer", mbus_man(mt["man"]), mt["man"], ""), ("Version", bytes([mt["ver"]]), "0x%02X" % mt["ver"], ""),
                ("Medium", bytes([mt["med"]]), MBUS_MED[mt["med"]], "")]
        p = self.long(0x53, 253, 0x52, recs, "SND_UD select by secondary address")
        if not send:
            return Frame(self.t, 0.03, "m", None, "M-Bus", "preview", pdu=p)
        self.send("m", mt["nid"], p, "SND_UD select secondary address %08d (A = 253)" % mt["id"], "ctl")
        self.at(self.t + 0.12, self._e5, a)
        self.at(self.t + 0.25, self.req, a, True, 253)
        return None

    def on_fault(self, key, on):
        if key == "short" and on:
            self.log("Level converter: bus current > 100 mA - bus switched off")

    def tpls(self):
        mt = lambda v: "%d (%s)" % (v, MBUS_MED[self.meters[v]["med"]])
        return [Tpl("REQ_UD2 (read meter)", [P("a", "Primary address", 1, opts=[1, 2, 3], fmt=mt)], lambda s, v, send: self.req(v["a"], send), "Request class 2 data; FCB toggles."),
                Tpl("Select by secondary address", [P("a", "Meter", 2, opts=[1, 2, 3], fmt=mt)], lambda s, v, send: self.select(v["a"], send),
                    "SND_UD CI 52h with ID / manufacturer / version / medium, then REQ_UD2 to address 253."),
                Tpl("SND_NKE (initialise)", [P("a", "Address", 254, opts=[1, 2, 3, 254])], lambda s, v, send: self.nke(v["a"], send), "Resets the link layer (FCB) of a meter or all.")]


# ============================================================ DLMS / COSEM
OBIS = {"1.0.1.8.0.255": ("Active energy import (+A) total", 3, 30), "1.0.2.8.0.255": ("Active energy export (-A) total", 3, 30),
        "1.0.1.7.0.255": ("Active power import (+P)", 3, 27), "1.0.32.7.0.255": ("Voltage L1", 3, 35), "1.0.31.7.0.255": ("Current L1", 3, 33),
        "0.0.1.0.0.255": ("Clock", 8, None), "0.0.96.1.0.255": ("Meter serial number", 1, None), "0.0.96.3.10.255": ("Disconnect control", 70, None)}
UNITS = {27: "W", 30: "Wh", 33: "A", 35: "V"}


def obis_b(s):
    return bytes(int(x) for x in s.split("."))


def hdlc_frame(ctrl, dst, src, info=b"", seg=False, title="HDLC"):
    n = 2 + len(dst) + len(src) + 1 + (2 + len(info) if info else 0) + 2
    fmt = 0xA000 | (0x0800 if seg else 0) | n
    hdr = struct.pack(">H", fmt) + dst + src + bytes([ctrl])
    b = Bld("IEC 62056-46 HDLC frame: %s" % title, "Frame format type 3: flag, format, destination, source, control, HCS, information, FCS, flag.")
    b.u8("Flag", 0x7E, "7Eh", "")
    b.u16("Frame format", fmt, "type 3 (Ah), segmentation %d, length %d" % (seg, n), "Length counts everything between the flags.")
    b.raw("Destination address", dst, " ".join("%02X" % x for x in dst), "HDLC addresses end with bit 0 = 1. Server: upper (logical device) + lower (physical) address.")
    b.raw("Source address", src, " ".join("%02X" % x for x in src), "Client SAP shifted left, bit 0 = 1.")
    cn = {0x93: "SNRM (set normal response mode)", 0x73: "UA (unnumbered ack)", 0x53: "DISC (disconnect)", 0x1F: "DM (disconnected mode)"}
    if ctrl in cn:
        ct = cn[ctrl]
    elif ctrl & 1 == 0:
        ct = "I-frame N(R) %d, P/F %d, N(S) %d" % (ctrl >> 5, ctrl >> 4 & 1, ctrl >> 1 & 7)
    else:
        ct = "RR N(R) %d, P/F %d" % (ctrl >> 5, ctrl >> 4 & 1)
    b.u8("Control", ctrl, "0x%02X %s" % (ctrl, ct), "")
    if info:
        hcs = crcn("CRC-16/X-25", hdr)
        b.u16("HCS", hcs, "0x%04X [correct]" % hcs, "Header check sequence, CRC-16 (X.25), LSB first.", little=True)
        b.raw("Information", info, None, "")
        fcs = crcn("CRC-16/X-25", hdr + struct.pack("<H", hcs) + info)
    else:
        fcs = crcn("CRC-16/X-25", hdr)
    b.u16("FCS", fcs, "0x%04X [correct]" % fcs, "Frame check sequence over everything between the flags.", little=True)
    b.u8("Flag", 0x7E, "7Eh", "")
    return b.done()


def dlms_rows(p, start, rows):
    """Append APDU dissection rows (offsets relative to the information field start)."""
    for d, txt, off, n, desc in rows:
        p.rows.append([d, txt, None if off is None else start + off, n, desc])
    return p


class DLMS(Scenario):
    key, name, cat = "dlms", "DLMS/COSEM", "power"
    blurb = "Smart electricity meters"
    phy, rate = "optport", 9600
    medium = "DLMS/COSEM over HDLC through the optical port (IEC 62056-21 mode E): a handheld reads a smart meter's registers and clock"
    nets = [("IR LIGHT", "Optical probe: infrared light (space = light on)")]
    lines = ["O"]
    faults = [("pwd", "Wrong low-level-security password", "The meter answers the AARQ with an AARE: rejected-permanent, authentication-failure."),
              ("sun", "Sunlight on the optical probe", "Stray infrared corrupts some frames: the FCS fails, the client repeats its request."),
              ("obis", "Client asks for an object the meter does not have", "GET.response carries data-access-result object-undefined (4)."),
              ("addr", "Client uses the wrong server physical address", "The meter ignores frames that are not addressed to it: no UA, timeouts.")]
    spec = [("Standards", "IEC 62056 series / DLMS UA Blue Book (COSEM objects), Green Book (communication); IEC 62056-21 optical port, -46 HDLC, -47 / -4-7 TCP wrapper"),
            ("Model", "COSEM interface classes (1 Data, 3 Register, 7 Profile generic, 8 Clock, 70 Disconnect control ...) identified by OBIS codes A.B.C.D.E.F"),
            ("Services", "Association (AARQ / AARE), GET, SET, ACTION, data notification; block transfer for large data"),
            ("Security", "No security (public client), LLS password, HLS (GMAC / ECDSA) with suite 0-2 ciphering"),
            ("HDLC", "Type 3 frames, client / server addresses, SNRM / UA, I-frames with N(S) / N(R), LLC E6 E6 00 / E6 E7 00, CRC-16 HCS / FCS")]
    frame = [["HDLC frame", ("7E", 8), ("Format + length", 16), ("Dest", "1-4 B"), ("Src", "1-4 B"), ("Ctrl", 8), ("HCS", 16), ("LLC + APDU", "n x 8"), ("FCS", 16), ("7E", 8)],
             ["GET.request", ("C0 01", 16), ("Invoke id", 8), ("Class id", 16), ("OBIS", 48), ("Attribute", 8), ("Access sel.", 8)]]
    about = ("DLMS/COSEM is the language of most smart electricity meters. Everything in the meter is an object of a standard class, named by "
             "an OBIS code - 1.0.1.8.0.255 is total imported active energy - and a client reads attributes with GET, writes with SET and "
             "triggers actions such as the disconnect relay with ACTION. Before that, the client opens an association with AARQ, where the "
             "password or keys are checked.")
    guide = ["Watch the IEC 62056-21 sign-on at 300 bit/s, then the switch to HDLC at 9600.",
             "Follow SNRM / UA (link parameters), then AARQ / AARE (association, password).",
             "Select a GET.request: class ID 3, OBIS 1.0.1.8.0.255, attribute 2. Then the response value and the scaler_unit (attribute 3).",
             "COMPOSE an ACTION on the disconnect control (class 70) and see the relay state change."]

    def build(self):
        hh = self.node("hh", "HANDHELD (DLMS CLIENT)", "laptop", 40, 150, "client 32 (LLS)", "reading software", w=150).at_right()
        pr = self.node("probe", "OPTICAL PROBE", "sensor", 300, 160, "", "IEC 62056-21", w=110)
        mt = self.node("mtr", "SMART METER", "meter", 600, 150, "server 1 / 17", "3-phase, LN referencing", w=140).at_left()
        pr.extra["can"] = False
        self.seg([hh.port, (300, 176)], "usb", label="USB", c0="usba")
        self.seg([(410, 176), mt.port], "pof", net="IR LIGHT", label="infrared", c1="jack")
        self.user = "hh"
        self.srv_addr = bytes([0x02, 0x23])
        self.cli = bytes([0x41])
        self.ns = self.nr = 0
        self.inv = 0
        self.assoc = False
        self.relay = True
        self.e_imp, self.e_exp = 15_234_870, 812_440
        self.baud = 300
        self.busy = False
        hh.vars.update({"Association": "-", "+A energy": "-", "Power": "-", "Clock": "-"})
        mt.vars.update({"Relay": "connected", "Load W": 2400.0})
        mt.ctl = [("Load W", "LOAD", 0.0, 12000.0, 0, lambda v: "%.0f W" % v)]
        self.queue = []
        self.at(0.1, self.signon)
        self.every(0.5, self.physics, 0.3)

    def physics(self):
        w = self.by["mtr"].vars["Load W"] if self.relay else 0.0
        self.e_imp += w * 0.5 / 3600
        self.by["mtr"].vars["Relay"] = "connected" if self.relay else "DISCONNECTED"

    def link(self, src, dst, p, info, kind, baud, bits=8, par="N"):
        err = "FCS error (stray light)" if (self.fault["sun"] and baud > 300 and self.rng.random() < 0.25) else None
        fr = serial_frame(self, src, dst, "DLMS" if baud > 300 else "IEC 62056-21", info, p, baud, bits, par, 1, line="O", kind=kind, err=err)
        self.tx(fr, ifs=0.02)
        return fr

    def signon(self):
        b = Bld("IEC 62056-21 sign-on (300 bit/s, 7E1)", "Request message: / ? ! CR LF")
        b.text("Request", "/?!\r\n", "Any meter: send your identification.")
        self.link("hh", "mtr", b.done(), "Sign-on request /?!", "ctl", 300, 7, "E")
        b2 = Bld("IEC 62056-21 identification", "/ XXX Z \\W Ident CR LF")
        b2.text("Identification", "/CSM5\\2CS3PH-DLMS\r\n", "Manufacturer CSM, max baud char '5' (9600), '\\2' = mode E (HDLC) capable.")
        self.at(self.t + 0.35, lambda: self.link("mtr", "hh", b2.done(), "Identification /CSM5\\2CS3PH-DLMS (mode E)", "resp", 300, 7, "E"))
        b3 = Bld("IEC 62056-21 acknowledgement / option select", "ACK V Z Y CR LF")
        b3.raw("ACK", b"\x06", "06h", "")
        b3.text("Options", "252\r\n", "V = '2' HDLC protocol, Z = '5' 9600 bit/s, Y = '2' binary mode")
        self.at(self.t + 1.4, lambda: self.link("hh", "mtr", b3.done(), "ACK 2 5 2: switch to HDLC at 9600 bit/s", "ctl", 300, 7, "E"))
        self.at(self.t + 1.9, self.snrm)

    def hframe(self, src, ctrl, info=b"", title="", info_rows=()):
        if src == "hh":
            dst, sa = (bytes([0x02, 0x25]) if self.fault["addr"] else self.srv_addr), self.cli
        else:
            dst, sa = self.cli, self.srv_addr
        p = hdlc_frame(ctrl, dst, sa, info, title=title)
        if info:
            dlms_rows(p, 1 + 2 + len(dst) + len(sa) + 1 + 2, info_rows)
        return p

    def snrm(self):
        par = bytes.fromhex("818012050180060180070400000001080400000001")
        p = self.hframe("hh", 0x93, par, "SNRM", [[0, "HDLC parameter negotiation", 0, len(par), "Max information length tx / rx 128, window size 1"]])
        self.link("hh", "mtr", p, "SNRM: set normal response mode (max info 128, window 1)", "ctl", 9600)
        if self.fault["addr"]:
            self.at(self.t + 2.0, lambda: self.log("Client: no UA from the meter (server address 1/18 does not exist) - check the physical address"))
            return
        self.ns = self.nr = 0
        self.at(self.t + 0.08, lambda: self.link("mtr", "hh", self.hframe("mtr", 0x73, par, "UA", [[0, "Negotiated HDLC parameters", 0, len(par), ""]]),
                                                 "UA: link established", "resp", 9600))
        self.at(self.t + 0.2, self.aarq)

    def iframe(self, src, apdu, title, rows, info, kind):
        llc = b"\xE6\xE6\x00" if src == "hh" else b"\xE6\xE7\x00"
        if src == "hh":
            ctrl = (self.nr << 5) | 0x10 | (self.ns << 1)
            self.ns = (self.ns + 1) & 7
        else:
            ctrl = (self.ns << 5) | 0x10 | (self.nr << 1)
            self.nr = (self.nr + 1) & 7
        allrows = [[0, "LLC header", 0, 3, "E6 E6 00 from client, E6 E7 00 from server."]] + [[d, t, None if o is None else o + 3, n, de] for d, t, o, n, de in rows]
        p = self.hframe(src, ctrl, llc + apdu, "I-frame", allrows)
        return self.link(src, "mtr" if src == "hh" else "hh", p, info, kind, 9600)

    def aarq(self):
        pwd = b"99999999" if self.fault["pwd"] else b"12345678"
        user = bytes.fromhex("BE10040E01000000065F1F0400007E1F04B0")
        body = bytes.fromhex("A109060760857405080101") + bytes.fromhex("8A0207808B0760857405080201") + bytes([0xAC, 2 + len(pwd), 0x80, len(pwd)]) + pwd + user
        apdu = bytes([0x60, len(body)]) + body
        rows = [[0, "COSEM APDU: AARQ (association request)", 0, len(apdu), "ACSE: open an application association."],
                [1, "application-context-name: 2.16.756.5.8.1.1 (LN referencing, no ciphering)", 2, 11, ""],
                [1, "sender-acse-requirements: authentication", 13, 4, ""],
                [1, "mechanism-name: 2.16.756.5.8.2.1 (low level security)", 17, 9, ""],
                [1, "calling-authentication-value: password \"%s\"" % pwd.decode(), 26, 4 + len(pwd), "LLS: the password travels in clear text."],
                [1, "user-information: xDLMS InitiateRequest (DLMS version 6, conformance 00 7E 1F, max PDU 1200)", 30 + len(pwd), len(user), ""]]
        self.iframe("hh", apdu, "AARQ", rows, "AARQ: LN referencing, LLS password", "ctl")
        if self.fault["pwd"]:
            are = bytes.fromhex("611FA109060760857405080101A203020101A305A10302010D") + bytes.fromhex("BE06040408000E0B")[:0]
            rows2 = [[0, "COSEM APDU: AARE (association response)", 0, len(are), ""], [1, "result: 1 rejected-permanent", 13, 5, ""],
                     [1, "result-source-diagnostic: acse-service-user 13 (authentication-failure)", 18, 7, ""]]
            self.at(self.t + 0.25, lambda: self.iframe("mtr", are, "AARE", rows2, "AARE: REJECTED - authentication failure", "err"))
            self.by["hh"].vars["Association"] = "REJECTED (password)"
            self.at(self.t + 0.6, self.disc)
            return
        are = bytes.fromhex("6129A109060760857405080101A203020100A305A103020100BE10040E0800065F1F040000501F01F40007")
        rows2 = [[0, "COSEM APDU: AARE (association response)", 0, len(are), ""], [1, "result: 0 accepted", 13, 5, ""],
                 [1, "result-source-diagnostic: null", 18, 7, ""],
                 [1, "user-information: xDLMS InitiateResponse (version 6, conformance 00 50 1F, max PDU 500, VAA 0007)", 25, 18, ""]]
        self.at(self.t + 0.25, lambda: self.iframe("mtr", are, "AARE", rows2, "AARE: association accepted", "resp"))
        self.at(self.t + 0.5, self._assoc)

    def _assoc(self):
        self.assoc = True
        self.by["hh"].vars["Association"] = "LLS, LN referencing"
        for obis, attr in (("0.0.1.0.0.255", 2), ("1.0.1.8.0.255", 2), ("1.0.1.8.0.255", 3), ("1.0.2.8.0.255", 2), ("1.0.32.7.0.255", 2), ("1.0.1.7.0.255", 2)):
            self.queue.append(("get", obis, attr))
        self.every(0.45, self.pump, 0.1)
        self.every(6.0, lambda: self.queue.extend([("get", "1.0.1.7.0.255", 2), ("get", "1.0.1.8.0.255", 2)]), 6.0)

    def pump(self):
        if not self.assoc or self.busy or not self.queue:
            return
        op = self.queue.pop(0)
        if op[0] == "get":
            self.get(op[1], op[2])
        elif op[0] == "act":
            self.action(op[1])

    def value(self, obis, attr):
        """-> (encoded data bytes, text) or None."""
        if obis not in OBIS:
            return None
        name, cls, unit = OBIS[obis]
        if cls == 8:
            d = utc(self.t)
            dt = struct.pack(">HBBBBBBBhB", d.year, d.month, d.day, d.isoweekday(), d.hour, d.minute, d.second, 0, -60, 0x00)
            return bytes([0x09, 12]) + dt, d.strftime("%Y-%m-%d %H:%M:%S") + " (octet-string date-time, deviation -60 min)"
        if attr == 3:
            sc = {30: 0, 27: 0, 35: -1, 33: -2}[unit]
            return bytes([0x02, 0x02, 0x0F, sc & 0xFF, 0x16, unit]), "scaler %d, unit %d (%s)" % (sc, unit, UNITS[unit])
        if obis == "1.0.1.8.0.255":
            return bytes([0x06]) + struct.pack(">I", int(self.e_imp)), "%d Wh (double-long-unsigned)" % int(self.e_imp)
        if obis == "1.0.2.8.0.255":
            return bytes([0x06]) + struct.pack(">I", int(self.e_exp)), "%d Wh" % int(self.e_exp)
        if obis == "1.0.1.7.0.255":
            w = int(self.by["mtr"].vars["Load W"] if self.relay else 0)
            return bytes([0x06]) + struct.pack(">I", w), "%d W" % w
        if obis == "1.0.32.7.0.255":
            v = int(2312 + self.rng.normal(0, 3))
            return bytes([0x12]) + struct.pack(">H", v), "%d (x 10^-1 V = %.1f V, long-unsigned)" % (v, v / 10.0)
        return bytes([0x16, 1 if self.relay else 0]), "enum %d" % (1 if self.relay else 0)

    def get(self, obis, attr, send=True):
        name, cls, unit = OBIS.get(obis, ("unknown object", 1, None))
        self.inv = (self.inv + 1) & 0x0F
        apdu = bytes([0xC0, 0x01, 0xC0 | self.inv]) + struct.pack(">H", cls) + obis_b(obis) + bytes([attr, 0x00])
        rows = [[0, "COSEM APDU: GET.request-normal", 0, len(apdu), ""], [1, "Invoke-id-and-priority: 0x%02X (id %d, high priority, confirmed)" % (0xC0 | self.inv, self.inv), 2, 1, ""],
                [1, "Class id: %d" % cls, 3, 2, {1: "Data", 3: "Register", 8: "Clock", 70: "Disconnect control"}.get(cls, "")],
                [1, "Instance id (OBIS): %s %s" % (obis, name), 5, 6, "A.B.C.D.E.F: medium, channel, quantity, processing, tariff, billing period."],
                [1, "Attribute id: %d (%s)" % (attr, {2: "value", 3: "scaler_unit", 1: "logical_name"}.get(attr, "")), 11, 1, ""], [1, "Access selection: none", 12, 1, ""]]
        if not send:
            return Frame(self.t, 0.05, "hh", "mtr", "DLMS", "preview", pdu=self.hframe("hh", 0x10, b"\xE6\xE6\x00" + apdu, "I-frame", [[0, "LLC", 0, 3, ""]] +
                                                                                   [[d, t, o + 3, n, de] for d, t, o, n, de in rows]))
        self.busy = True
        fr = self.iframe("hh", apdu, "GET", rows, "GET.request %s attr %d (%s)" % (obis, attr, name), "cmd")
        if fr.err:
            self.at(fr.t + fr.dur + 0.5, self.get, obis, attr)
            return None
        v = None if (self.fault["obis"] and obis == "1.0.31.7.0.255") else self.value(obis, attr)
        inv = self.inv

        def rsp():
            self.busy = False
            if v is None:
                r = bytes([0xC4, 0x01, 0xC0 | inv, 0x01, 0x04])
                self.iframe("mtr", r, "GET.response", [[0, "COSEM APDU: GET.response-normal", 0, 5, ""], [1, "Result: data-access-result 4 (object-undefined)", 3, 2, ""]],
                            "GET.response %s: data-access-result object-undefined" % obis, "err")
                return
            data, txt = v
            r = bytes([0xC4, 0x01, 0xC0 | inv, 0x00]) + data
            rf = self.iframe("mtr", r, "GET.response", [[0, "COSEM APDU: GET.response-normal", 0, len(r), ""], [1, "Invoke-id-and-priority: id %d" % inv, 2, 1, ""],
                                                         [1, "Result: data", 3, 1, ""], [1, "Data: %s" % txt, 4, len(data), "A-XDR: type tag, then the value."]],
                             "GET.response %s attr %d: %s" % (obis, attr, txt), "resp")
            hv = self.by["hh"].vars
            if obis == "1.0.1.8.0.255" and attr == 2:
                hv["+A energy"] = "%.3f kWh" % (int(self.e_imp) / 1000.0)
            elif obis == "1.0.1.7.0.255":
                hv["Power"] = txt
            elif obis == "0.0.1.0.0.255":
                hv["Clock"] = txt.split(" (")[0]
            if rf.err:
                self.queue.insert(0, ("get", obis, attr))
        self.at(fr.t + fr.dur + 0.06, rsp)
        return None

    def action(self, method, send=True):
        self.inv = (self.inv + 1) & 0x0F
        apdu = bytes([0xC3, 0x01, 0xC0 | self.inv]) + struct.pack(">H", 70) + obis_b("0.0.96.3.10.255") + bytes([method, 0x01, 0x0F, 0x00])
        rows = [[0, "COSEM APDU: ACTION.request-normal", 0, len(apdu), ""], [1, "Class id 70 (Disconnect control)", 3, 2, ""],
                [1, "Instance id: 0.0.96.3.10.255", 5, 6, ""], [1, "Method id: %d (%s)" % (method, {1: "remote_disconnect", 2: "remote_reconnect"}[method]), 11, 1, ""],
                [1, "Method parameters: integer 0", 12, 3, ""]]
        if not send:
            return Frame(self.t, 0.05, "hh", "mtr", "DLMS", "preview", pdu=self.hframe("hh", 0x10, b"\xE6\xE6\x00" + apdu, "I-frame", [[0, "LLC", 0, 3, ""]] +
                                                                                   [[d, t, o + 3, n, de] for d, t, o, n, de in rows]))
        if not self.assoc:
            return None
        self.busy = True
        fr = self.iframe("hh", apdu, "ACTION", rows, "ACTION.request class 70 0.0.96.3.10.255 method %d (%s)" % (method, "remote_disconnect" if method == 1 else "remote_reconnect"), "cmd")
        inv = self.inv

        def rsp():
            self.busy = False
            self.relay = method == 2
            r = bytes([0xC7, 0x01, 0xC0 | inv, 0x00, 0x00])
            self.iframe("mtr", r, "ACTION.response", [[0, "COSEM APDU: ACTION.response-normal", 0, 5, ""], [1, "Result: 0 success", 3, 1, ""], [1, "Return parameters: none", 4, 1, ""]],
                        "ACTION.response: success - relay %s" % ("connected" if self.relay else "disconnected"), "resp")
        self.at(fr.t + fr.dur + 0.3, rsp)
        return None

    def disc(self, send=True):
        p = self.hframe("hh", 0x53, title="DISC")
        if not send:
            return Frame(self.t, 0.02, "hh", "mtr", "DLMS", "preview", pdu=p)
        self.assoc = False
        self.link("hh", "mtr", p, "DISC: disconnect the HDLC link", "ctl", 9600)
        self.at(self.t + 0.08, lambda: self.link("mtr", "hh", self.hframe("mtr", 0x73, title="UA"), "UA: disconnected", "ack", 9600))
        self.by["hh"].vars["Association"] = self.by["hh"].vars["Association"] if "REJ" in str(self.by["hh"].vars["Association"]) else "released"
        return None

    def on_fault(self, key, on):
        if key in ("pwd", "addr") and not on and not self.assoc:
            self.at(self.t + 0.5, self.snrm)

    def tpls(self):
        return [Tpl("GET attribute", [P("o", "Object (OBIS)", "1.0.1.8.0.255", opts=list(OBIS)[:6], fmt=lambda v: "%s %s" % (v, OBIS[v][0])), P("a", "Attribute", 2, opts=[1, 2, 3])],
                    lambda s, v, send: self._q(("get", v["o"], v["a"]), lambda: self.get(v["o"], v["a"], False), send), "Attribute 2 = value, 3 = scaler_unit (registers)."),
                Tpl("ACTION disconnect control", [P("m", "Method", 1, opts=[1, 2], fmt=lambda v: {1: "1 remote_disconnect", 2: "2 remote_reconnect"}[v])],
                    lambda s, v, send: self._q(("act", v["m"]), lambda: self.action(v["m"], False), send), "Opens or closes the meter's supply relay."),
                Tpl("Release (DISC)", [], lambda s, v, send: self.disc(send), "Ends the HDLC link (the association is released with it).")]

    def _q(self, op, pv, send):
        if not send:
            return pv()
        self.queue.append(op)
        return None
