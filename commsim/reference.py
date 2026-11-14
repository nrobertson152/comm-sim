"""REFERENCE tab: protocol matrix with OSI stacks, the OSI model, connector
pin-outs, line codes, a CRC calculator and a glossary."""
import math
import pygame
from . import ui, fx, bits
from .ui import C, text, Button, TextField
from .refdata import OSI, OSI_NOTE, stack, CONNECTORS, LINECODES, GLOSSARY

PAGES = ["PROTOCOLS", "OSI MODEL", "CONNECTORS", "LINE CODES", "CRC CALCULATOR", "GLOSSARY"]
TIPS = {"PROTOCOLS": "Every protocol in the simulator: physical layer, bit rate and what it uses at each OSI layer.",
        "OSI MODEL": "The seven OSI layers and which simulated protocols live on each.",
        "CONNECTORS": "Pin-outs of the common connectors: RS-232, CAN, PROFIBUS, RJ45, OBD-II, M12 ...",
        "LINE CODES": "How bits become signals: NRZ, NRZI, Manchester, bipolar RZ, MLT-3, FSK - drawn from your own bit pattern.",
        "CRC CALCULATOR": "Every CRC used by the simulated protocols, with their parameters, check values and a live calculator.",
        "GLOSSARY": "Short definitions of the terms used in the labs and the guides."}
PHY_NAME = {"rs232": "RS-232", "rs422": "RS-422 differential", "rs423": "RS-423", "rs485": "RS-485 differential", "can": "CAN differential",
            "eth10": "10 Mbit/s Ethernet", "eth100": "100BASE-TX", "eth1000": "1000BASE-T", "t1": "100BASE-T1", "fiber": "Optical fibre",
            "pof": "Plastic optical fibre", "ttl": "TTL logic", "spi": "SPI (4-wire)", "i2c": "I2C open drain", "onewire": "1-Wire",
            "usb": "USB D+/D-", "lvds": "LVDS", "gpib": "IEEE-488 parallel", "rf": "Radio", "manch": "Manchester bus", "ffpa": "MBP 31.25 kbit/s",
            "iolink": "IO-Link C/Q", "asi": "AS-i APM", "hart": "FSK on 4-20 mA", "lin": "LIN single wire", "flexray": "FlexRay differential",
            "kline": "K-line", "vpw": "J1850 VPW", "sent": "SENT pulses", "psi5": "PSI5 current loop", "seatalk": "SeaTalk 3-wire",
            "a429": "ARINC 429 bipolar RZ", "a429ls": "ARINC 429 low speed", "a717": "Harvard bi-phase", "m1553": "1553 Manchester",
            "spw": "LVDS data-strobe", "cml": "CML serial", "knx": "KNX TP1", "dali": "DALI 2-wire", "mbus": "M-Bus 2-wire",
            "optport": "Optical port (IR)", "dc24": "24 V DC", "pwm": "PWM", "audio": "Audio", "pcm": "PCM"}
CAT_COL = {"PHYSICAL": (130, 200, 255), "INDUSTRIAL": (255, 178, 46), "AUTOMOTIVE": (255, 120, 90), "MARINE": (90, 215, 255),
           "AEROSPACE": (200, 160, 255), "POWER/BLDG": (255, 236, 90), "NETWORKING": (70, 255, 120)}
TOPY = 92
BODY = pygame.Rect(0, TOPY, ui.W, ui.BOT - TOPY)


RATE_TXT = {"wirelesshart": "250 kbit/s", "adsb": "1 Mbit/s", "modes": "1 / 4 Mbit/s", "acars": "2.4 kbit/s", "cpdlc": "31.5 kbit/s",
            "ccsds": "kbit/s - Mbit/s", "zigbee": "250 kbit/s", "thread": "250 kbit/s", "ble": "1 Mbit/s", "wifi": "1-600 Mbit/s",
            "lorawan": "0.3-5.5 kbit/s", "zwave": "9.6-100 kbit/s", "ieee802154": "250 kbit/s", "ais": "9.6 kbit/s"}


def fmt_rate(r):
    r = float(r)
    if r >= 1e9:
        return "%g Gbit/s" % (r / 1e9)
    if r >= 1e6:
        return "%g Mbit/s" % (r / 1e6)
    if r >= 1e3:
        return "%g kbit/s" % round(r / 1e3, 1)
    return "%d bit/s" % r


def wave(code, bitsl):
    """Points (x in bit times, y in -1..1) of a line code for a bit list."""
    pts = []
    n = len(bitsl)
    if code == "fsk":
        ph = 0.0
        for i, b in enumerate(bitsl):
            f = 1.0 if b else 2200.0 / 1200.0
            for k in range(40):
                pts.append((i + k / 40.0, 0.85 * math.sin(ph)))
                ph += 2 * math.pi * f / 40.0
        pts.append((n, 0.85 * math.sin(ph)))
        return pts, False
    seg = []                                       # (t0, t1, level)
    lev = -1
    idx = 0
    pol = 1
    cyc = [0, 1, 0, -1]
    for i, b in enumerate(bitsl):
        if code == "nrz":
            seg.append((i, i + 1, 1 if b else -1))
        elif code == "nrzi":
            if not b:
                lev = -lev
            seg.append((i, i + 1, lev))
        elif code == "man":
            seg += [(i, i + .5, -1 if b else 1), (i + .5, i + 1, 1 if b else -1)]
        elif code == "man2":
            seg += [(i, i + .5, 1 if b else -1), (i + .5, i + 1, -1 if b else 1)]
        elif code == "dman":
            if not b:
                lev = -lev
            seg.append((i, i + .5, lev))
            lev = -lev
            seg.append((i + .5, i + 1, lev))
        elif code == "bpm":
            lev = -lev
            if b:
                seg.append((i, i + .5, lev))
                lev = -lev
                seg.append((i + .5, i + 1, lev))
            else:
                seg.append((i, i + 1, lev))
        elif code == "rz":
            seg += [(i, i + .5, 1 if b else -1), (i + .5, i + 1, 0)]
        elif code == "ami":
            if b:
                seg += [(i, i + .5, pol), (i + .5, i + 1, 0)]
                pol = -pol
            else:
                seg.append((i, i + 1, 0))
        elif code == "mlt3":
            if b:
                idx = (idx + 1) % 4
            seg.append((i, i + 1, cyc[idx]))
    for t0, t1, y in seg:
        if pts and pts[-1][1] != y:
            pts.append((t0, y))
        elif not pts:
            pts.append((t0, y))
        pts.append((t1, y))
    return pts, True


class Reference:
    def __init__(self, app):
        self.app = app
        self.page = 0
        self.tabs = [Button((16 + i * 182, 54, 176, 30), p, TIPS[p], size=11, color="cyan", on_click=lambda b, i=i: self.set_page(i))
                     for i, p in enumerate(PAGES)]
        self.keys = [(c[0], cls) for c in app.cats for cls in c[3]]
        seen = set()
        self.rows_all = []
        for cat, cls in self.keys:
            if (cat, cls.key) in seen:
                continue
            seen.add((cat, cls.key))
            self.rows_all.append((cat, cls))
        self.sel_key = self.rows_all[0][1].key
        self.sel_cat = self.rows_all[0][0]
        self.scroll = {p: 0 for p in PAGES}
        self.f_proto = TextField((24, 128, 300, 26), "", "Filter the list: protocol name, category or physical layer.", size=12,
                                 placeholder="FILTER (e.g. CAN, 485, radio)")
        self.f_gloss = TextField((24, 128, 360, 26), "", "Filter the glossary.", size=12, placeholder="SEARCH TERMS")
        self.f_bits = TextField((180, 128, 260, 26), "0100110101", "Bit pattern to encode (0 and 1, up to 24 bits).", size=12, maxlen=24)
        self.f_crc = TextField((180, 128, 420, 26), "123456789", "Data to run through every CRC.", size=12, maxlen=80)
        self.b_hex = Button((610, 128, 70, 26), "HEX", "Interpret the input as hexadecimal bytes (e.g. 01 03 00 00 00 0A).", toggle=True, size=10)
        self.b_open = Button((0, 0, 190, 34), "OPEN ON BENCH", "Load this protocol on its category's bench.", color="green", size=11,
                             on_click=lambda b: self.app.open(self.sel_key, self.sel_cat))
        self.b_rand = Button((450, 128, 90, 26), "RANDOM", "A random 16-bit pattern.", size=10, on_click=lambda b: self._rand())
        self.osi_sel = 7
        self.con_sel = 0
        self.lab_btns = []
        self.chips = []
        self.rows = []
        self.crows = []
        self._rng = 12345

    # ---------------------------------------------------------------- input
    def set_page(self, i):
        self.page = i
        ui.FOCUS[0] = None
        ui.sfx("detent", 0.6)

    def _rand(self):
        self._rng = (self._rng * 1103515245 + 12345) & 0x7FFFFFFF
        self.f_bits.value = "".join("1" if (self._rng >> k) & 1 else "0" for k in range(16))

    def widgets(self):
        p = PAGES[self.page]
        w = list(self.tabs)
        if p == "PROTOCOLS":
            w += [self.f_proto, self.b_open] + self.lab_btns
        elif p == "LINE CODES":
            w += [self.f_bits, self.b_rand]
        elif p == "CRC CALCULATOR":
            w += [self.f_crc, self.b_hex]
        elif p == "GLOSSARY":
            w += [self.f_gloss]
        return w

    def enter(self):
        pass

    def handle(self, ev):
        for w in self.widgets():
            if w.visible and w.handle(ev):
                return True
        p = PAGES[self.page]
        if ev.type == pygame.MOUSEWHEEL:
            self.scroll[p] = max(0, self.scroll[p] - ev.y * 3)
            return True
        if ev.type == pygame.MOUSEBUTTONDOWN and ev.button == 1:
            for rr, v in self.rows:
                if rr.collidepoint(ev.pos):
                    if p == "PROTOCOLS":
                        self.sel_cat, self.sel_key = v
                    elif p == "OSI MODEL":
                        self.osi_sel = v
                    elif p == "CONNECTORS":
                        self.con_sel = v
                    ui.sfx("detent", 0.5)
                    return True
            for rr, (cat, key) in self.chips:
                if rr.collidepoint(ev.pos):
                    self.sel_cat, self.sel_key = cat, key
                    self.page = 0
                    ui.sfx("detent", 0.5)
                    return True
        return False

    def update(self, dt):
        pass

    def tip_at(self, p):
        for w in self.widgets():
            if w.visible and w.hit(p) and w.tip:
                return w.tip
        for rr, (cat, key) in self.chips:
            if rr.collidepoint(p):
                return "%s - click to see its stack in PROTOCOLS." % self.app.by_key[key].name
        return TIPS[PAGES[self.page]]

    def draw_status(self, s, r):
        pass

    # ----------------------------------------------------------------- draw
    def draw(self, s):
        ui.panel(s, (0, ui.TOP, ui.W, ui.BOT - ui.TOP), "REFERENCE")
        for i, b in enumerate(self.tabs):
            b.on = i == self.page
            b.draw(s)
        self.rows, self.chips = [], []
        getattr(self, "_p_" + PAGES[self.page].split()[0].lower())(s)

    # ------------------------------------------------------------ PROTOCOLS
    def _p_protocols(self, s):
        left = pygame.Rect(14, TOPY + 2, 760, BODY.h - 10)
        right = pygame.Rect(786, TOPY + 2, ui.W - 800, BODY.h - 10)
        self.f_proto.draw(s)
        flt = self.f_proto.value.lower().strip()
        rows = [(cat, cls) for cat, cls in self.rows_all
                if not flt or flt in (cat + " " + cls.name + " " + cls.key + " " + PHY_NAME.get(cls.phy, cls.phy) + " " + cls.blurb).lower()]
        text(s, "%d PROTOCOLS" % len(rows), (340, 134), 11, C["dim"], bold=True)
        cols = [("CATEGORY", 24), ("PROTOCOL", 140), ("PHYSICAL LAYER", 360), ("BIT RATE", 560), ("OSI LAYERS", 672)]
        y0 = 166
        for nm, x in cols:
            ui.legend(s, nm, (x, y0), 10, align="l")
        pygame.draw.line(s, (80, 86, 96), (20, y0 + 16), (left.right - 10, y0 + 16), 1)
        lh = 21
        vis = (left.bottom - y0 - 26) // lh
        sc = self.scroll["PROTOCOLS"] = min(self.scroll["PROTOCOLS"], max(0, len(rows) - vis))
        y = y0 + 22
        for cat, cls in rows[sc:sc + vis]:
            rr = pygame.Rect(18, y - 2, left.w - 24, lh - 1)
            sel = cls.key == self.sel_key and cat == self.sel_cat
            if sel:
                pygame.draw.rect(s, (60, 52, 26), rr, border_radius=3)
            elif rr.collidepoint(ui.MOUSE):
                pygame.draw.rect(s, (36, 40, 46), rr, border_radius=3)
            self.rows.append((rr, (cat, cls.key)))
            text(s, cat, (24, y), 10, CAT_COL.get(cat, C["text"]), bold=True)
            text(s, ui.clip_text(cls.name, 12, 210, mono=False, bold=sel), (140, y - 1), 12, C["white"] if sel else C["text"], bold=sel, mono=False)
            text(s, ui.clip_text(PHY_NAME.get(cls.phy, cls.phy), 11, 190), (360, y), 11, (170, 178, 188))
            text(s, RATE_TXT.get(cls.key) or fmt_rate(cls.rate), (560, y), 11, (170, 178, 188))
            st = stack(cls.key)
            for k in range(1, 8):
                x = 672 + (k - 1) * 12
                pygame.draw.rect(s, CAT_COL.get(cat, C["amber"]) if k in st else (44, 48, 54), (x, y + 2, 10, 11), border_radius=2)
            y += lh
        ui.scrollbar(s, (left.right - 8, y0 + 20, 6, vis * lh), sc, vis, max(1, len(rows)))
        self._proto_detail(s, right)

    def _proto_detail(self, s, r):
        cls = self.app.by_key[self.sel_key]
        cat = self.sel_cat
        fx.draw_well(s, r, (16, 18, 21), (30, 32, 36))
        x, w = r.x + 18, r.w - 36
        y = r.y + 12
        text(s, cls.name, (x, y), 22, C["amber"], bold=True, mono=False)
        y += 32
        text(s, "%s   -   %s" % (cat, cls.blurb), (x, y), 12, CAT_COL.get(cat, C["cyan"]), bold=True, mono=False)
        y += 22
        y = ui.text_block(s, "Simulated: " + cls.medium, (x, y, w, 60), 12, (176, 184, 194), lh=17, mono=False) + 8
        ui.legend(s, "PROTOCOL STACK", (x, y), 10, align="l")
        y += 18
        st = stack(cls.key)
        for num, name, pdu, _desc, _dev in OSI:
            used = num in st
            rr = pygame.Rect(x, y, w, 30)
            pygame.draw.rect(s, (34, 38, 30) if used else (22, 24, 27), rr, border_radius=4)
            pygame.draw.rect(s, CAT_COL.get(cat, C["amber"]) if used else (50, 54, 60), (x, y, 5, 30), border_radius=2)
            text(s, "%d" % num, (x + 16, y + 7), 13, C["white"] if used else (90, 96, 104), bold=True)
            text(s, name, (x + 36, y + 9), 9, C["white"] if used else (90, 96, 104), bold=True)
            body = st.get(num, "-")
            lines = ui.wrap(body, 11, w - 150, mono=False)
            yy = y + (9 if len(lines) == 1 else 2)
            for ln in lines[:2]:
                text(s, ln, (x + 140, yy), 11, (210, 214, 220) if used else (80, 86, 94), mono=False)
                yy += 13
            y += 33
        y += 6
        ui.legend(s, "KEY FACTS", (x, y), 10, align="l")
        y += 18
        bottom = r.bottom - 54
        for k, v in cls.spec:
            lines = ui.wrap(v, 11, w - 130, mono=False)
            if y + 14 * len(lines) > bottom:
                text(s, "... more in the SPEC panel on the bench", (x, y), 10, C["dim"])
                break
            text(s, k, (x, y), 10, C["cyan"], bold=True)
            for ln in lines:
                text(s, ln, (x + 128, y - 1), 11, C["text"], mono=False)
                y += 14
            y += 3
        self.b_open.rect.topleft = (x, r.bottom - 44)
        self.b_open.draw(s)
        labs = [(i, l) for i, l in enumerate(self.app.labs.labs) if l["key"] == cls.key]
        self.lab_btns = []
        bx = x + 200
        for i, l in labs[:2]:
            b = Button((bx, r.bottom - 44, 196, 34), "LAB: " + ui.clip_text(l["title"].split(":")[0], 10, 150, bold=True), "Open the lab '%s'." % l["title"], size=10,
                       on_click=lambda b, i=i: self._goto_lab(i))
            self.lab_btns.append(b)
            b.draw(s)
            bx += 202

    def _goto_lab(self, i):
        self.app.labs.sel = i
        self.app.set_mode(self.app.modes.index("LABS"))

    # ------------------------------------------------------------ OSI MODEL
    def _p_osi(self, s):
        x0, w = 24, 860
        y = TOPY + 14
        h = 92
        for num, name, pdu, desc, dev in OSI:
            rr = pygame.Rect(x0, y, w, h - 6)
            sel = num == self.osi_sel
            hue = (40 + num * 4, 46 + num * 2, 58 - num * 2)
            pygame.draw.rect(s, (70, 60, 28) if sel else hue, rr, border_radius=6)
            pygame.draw.rect(s, C["amber"] if sel else (70, 76, 86), rr, 1, border_radius=6)
            self.rows.append((rr, num))
            text(s, str(num), (x0 + 30, y + 40), 34, C["amber"] if sel else (150, 156, 166), bold=True, align="m")
            text(s, name, (x0 + 66, y + 8), 16, C["white"], bold=True)
            text(s, "PDU: " + pdu, (x0 + w - 14, y + 10), 11, C["cyan"], bold=True, align="r")
            ui.text_block(s, desc, (x0 + 66, y + 32, w - 90, 34), 12, (190, 196, 204), lh=16, mono=False)
            text(s, "Devices: " + dev, (x0 + 66, y + 66), 10, (130, 138, 150))
            y += h
        # right: protocols at the selected layer
        r = pygame.Rect(900, TOPY + 14, ui.W - 924, BODY.h - 30)
        fx.draw_well(s, r, (16, 18, 21), (30, 32, 36))
        name = [o[1] for o in OSI if o[0] == self.osi_sel][0]
        text(s, "LAYER %d  %s" % (self.osi_sel, name), (r.x + 16, r.y + 12), 16, C["amber"], bold=True)
        text(s, "Simulated protocols that use this layer (click one):", (r.x + 16, r.y + 38), 11, C["dim"], mono=False)
        y = r.y + 60
        cats = {}
        for cat, cls in self.rows_all:
            if self.osi_sel in stack(cls.key):
                cats.setdefault(cat, []).append(cls)
        for cat, lst in cats.items():
            if y > r.bottom - 150:
                break
            text(s, cat, (r.x + 16, y), 10, CAT_COL.get(cat, C["text"]), bold=True)
            y += 16
            x = r.x + 16
            for cls in lst:
                tw = ui.font(10, True, True).size(cls.name)[0] + 14
                if x + tw > r.right - 12:
                    x = r.x + 16
                    y += 22
                cr = pygame.Rect(x, y, tw, 19)
                hov = cr.collidepoint(ui.MOUSE)
                pygame.draw.rect(s, (52, 56, 64) if hov else (32, 36, 42), cr, border_radius=9)
                pygame.draw.rect(s, CAT_COL.get(cat, C["text"]), cr, 1, border_radius=9)
                text(s, cls.name, cr.center, 10, C["white"], bold=True, align="m")
                self.chips.append((cr, (cat, cls.key)))
                x += tw + 6
            y += 28
        ui.text_block(s, OSI_NOTE, (r.x + 16, r.bottom - 132, r.w - 32, 60), 11, (150, 158, 168), lh=15, mono=False)
        self._encap(s, pygame.Rect(r.x + 16, r.bottom - 64, r.w - 32, 50))

    def _encap(self, s, r):
        parts = [("ETH", 14, (90, 140, 255)), ("IP", 20, (70, 255, 120)), ("TCP", 20, (255, 178, 46)), ("HTTP data", 60, (230, 230, 230)), ("FCS", 4, (90, 140, 255))]
        tot = sum(p[1] for p in parts)
        x = r.x
        text(s, "Encapsulation: each layer wraps the one above", (r.x, r.y - 2), 10, C["dim"])
        for nm, n, col in parts:
            ww = max(34, int((r.w) * n / tot))
            rr = pygame.Rect(x, r.y + 14, ww - 3, 26)
            pygame.draw.rect(s, (col[0] // 4, col[1] // 4, col[2] // 4), rr, border_radius=3)
            pygame.draw.rect(s, col, rr, 1, border_radius=3)
            text(s, nm, rr.center, 10, col, bold=True, align="m")
            x += ww
            if x > r.right:
                break

    # ----------------------------------------------------------- CONNECTORS
    def _p_connectors(self, s):
        y = TOPY + 14
        for i, c in enumerate(CONNECTORS):
            rr = pygame.Rect(18, y, 330, 38)
            sel = i == self.con_sel
            pygame.draw.rect(s, (60, 52, 26) if sel else ((36, 40, 46) if rr.collidepoint(ui.MOUSE) else (24, 27, 31)), rr, border_radius=4)
            if sel:
                pygame.draw.rect(s, C["amber"], rr, 1, border_radius=4)
            text(s, c["name"], (rr.x + 10, rr.y + 4), 12, C["white"] if sel else C["text"], bold=sel, mono=False)
            text(s, ui.clip_text(c["use"], 10, rr.w - 20, mono=False), (rr.x + 10, rr.y + 21), 10, (130, 138, 150), mono=False)
            self.rows.append((rr, i))
            y += 42
        c = CONNECTORS[self.con_sel]
        r = pygame.Rect(364, TOPY + 14, ui.W - 388, BODY.h - 30)
        fx.draw_well(s, r, (16, 18, 21), (30, 32, 36))
        text(s, c["name"], (r.x + 20, r.y + 14), 22, C["amber"], bold=True, mono=False)
        text(s, c["use"], (r.x + 20, r.y + 46), 12, C["cyan"], bold=True, mono=False)
        draw_r = pygame.Rect(r.x + 20, r.y + 84, 560, 400)
        pygame.draw.rect(s, (10, 12, 14), draw_r, border_radius=6)
        hl = self._hover_pin(c, r)
        draw_connector(s, c, draw_r, hl)
        text(s, c["view"], (draw_r.centerx, draw_r.bottom + 8), 11, C["dim"], align="c", mono=False)
        # pin table
        tx = draw_r.right + 30
        ty = r.y + 86
        ui.legend(s, "PIN", (tx, ty), 10, align="l")
        ui.legend(s, "SIGNAL", (tx + 70, ty), 10, align="l")
        ui.legend(s, "NOTES", (tx + 200, ty), 10, align="l")
        ty += 20
        self._pin_rows = []
        for pin, sig, note in c["pins"]:
            rr = pygame.Rect(tx - 6, ty - 3, r.right - tx - 14, 24)
            on = hl == pin
            if on or rr.collidepoint(ui.MOUSE):
                pygame.draw.rect(s, (60, 52, 26), rr, border_radius=3)
            self._pin_rows.append((rr, pin))
            text(s, pin, (tx, ty), 12, C["amber"], bold=True)
            text(s, sig, (tx + 70, ty), 12, C["white"], bold=True)
            text(s, ui.clip_text(note, 11, r.right - tx - 230, mono=False), (tx + 200, ty + 1), 11, (170, 178, 188), mono=False)
            ty += 26
        ui.text_block(s, c["note"], (r.x + 20, r.bottom - 120, r.w - 40, 100), 13, (190, 196, 204), lh=19, mono=False)

    def _hover_pin(self, c, r):
        for rr, pin in getattr(self, "_pin_rows", []):
            if rr.collidepoint(ui.MOUSE):
                return pin
        return None

    # ----------------------------------------------------------- LINE CODES
    def _p_line(self, s):
        text(s, "BIT PATTERN", (24, 134), 11, C["amber"], bold=True)
        self.f_bits.draw(s)
        self.b_rand.draw(s)
        bl = [1 if ch == "1" else 0 for ch in self.f_bits.value if ch in "01"][:24] or [0]
        text(s, "%d bits" % len(bl), (552, 134), 11, C["dim"])
        y = 168
        x0, x1 = 420, ui.W - 30
        bw = (x1 - x0) / len(bl)
        for i, b in enumerate(bl):
            text(s, str(b), (int(x0 + (i + .5) * bw), y), 12, C["amber"], bold=True, align="c")
        y += 20
        rh = (ui.BOT - 16 - y) // len(LINECODES)
        for code, name, rule, use in LINECODES:
            rr = pygame.Rect(18, y, ui.W - 36, rh - 4)
            pygame.draw.rect(s, (22, 25, 29), rr, border_radius=4)
            text(s, name, (28, y + 3), 13, C["white"], bold=True, mono=False)
            yy = ui.text_block(s, rule, (28, y + 20, 380, 26), 10, (170, 178, 188), lh=12, mono=False)
            ui.text_block(s, use, (28, yy + 1, 380, y + rh - 6 - yy), 10, C["cyan"], lh=12, mono=False)
            wr = pygame.Rect(x0, y + 6, x1 - x0, rh - 16)
            pygame.draw.rect(s, (8, 12, 10), wr)
            for i in range(len(bl) + 1):
                xx = int(x0 + i * bw)
                pygame.draw.line(s, (36, 44, 40), (xx, wr.y), (xx, wr.bottom), 1)
                if i < len(bl):
                    pygame.draw.line(s, (24, 30, 27), (int(xx + bw / 2), wr.y), (int(xx + bw / 2), wr.bottom), 1)
            pygame.draw.line(s, (40, 56, 48), (x0, wr.centery), (x1, wr.centery), 1)
            pts, _ = wave(code, bl)
            pp = [(int(x0 + t * bw), int(wr.centery - v * (wr.h / 2 - 5))) for t, v in pts]
            if len(pp) > 1:
                pygame.draw.lines(s, (90, 255, 140), False, pp, 2)
            y += rh

    # ----------------------------------------------------------------- CRC
    def _p_crc(self, s):
        text(s, "INPUT DATA", (24, 134), 11, C["amber"], bold=True)
        self.f_crc.draw(s)
        self.b_hex.draw(s)
        data, err = self._crc_data()
        text(s, err or ("%d bytes" % len(data)), (692, 134), 11, C["red"] if err else C["dim"])
        cols = [("ALGORITHM", 24), ("WIDTH", 236), ("POLY", 296), ("INIT", 386), ("REFIN", 476), ("REFOUT", 530), ("XOROUT", 594),
                ("CHECK '123456789'", 684), ("YOUR DATA", 860), ("USED BY", 960)]
        y = 168
        for nm, x in cols:
            ui.legend(s, nm, (x, y), 10, align="l")
        pygame.draw.line(s, (80, 86, 96), (20, y + 16), (ui.W - 20, y + 16), 1)
        y += 22
        for name, p in bits.CRCS.items():
            w, poly, init, ri, ro, xo, chk, use = p
            hexw = (w + 3) // 4
            f = "0x%%0%dX" % hexw
            try:
                mine = bits.crcn(name, b"123456789")
            except Exception:
                mine = None
            ok = chk is None or mine == chk
            text(s, name, (24, y), 11, C["white"], bold=True)
            text(s, str(w), (236, y), 11, C["text"])
            text(s, f % poly, (296, y), 11, C["text"])
            text(s, f % init, (386, y), 11, C["text"])
            text(s, "yes" if ri else "no", (476, y), 11, C["text"])
            text(s, "yes" if ro else "no", (530, y), 11, C["text"])
            text(s, f % xo, (594, y), 11, C["text"])
            text(s, (f % mine) if mine is not None else "-", (684, y), 11, C["green"] if ok else C["red"], bold=True)
            if chk is not None:
                text(s, "OK" if ok else "!", (684 + 12 + 9 * (hexw + 2), y), 10, C["green"] if ok else C["red"], bold=True)
            try:
                v = bits.crcn(name, data) if not err else None
            except Exception:
                v = None
            text(s, (f % v) if v is not None else "-", (860, y), 11, C["amber"], bold=True)
            text(s, ui.clip_text(use, 11, ui.W - 990, mono=False), (960, y), 11, (170, 178, 188), mono=False)
            y += 23
        y += 10
        ui.text_block(s, "Parameters follow the Rocksoft / 'catalogue of CRC algorithms' model: WIDTH bits, generator POLY (normal form, "
                         "top bit implied), register preset INIT, REFIN = bytes enter LSB first, REFOUT = result reflected, XOROUT applied "
                         "at the end. CHECK is the CRC of the nine ASCII characters '123456789' - the standard way to verify an "
                         "implementation. The CAN CRCs are computed over the bit stream; here they are applied to bytes for comparison.",
                      (24, y, ui.W - 48, 80), 12, (170, 178, 188), lh=17, mono=False)

    def _crc_data(self):
        v = self.f_crc.value
        if self.b_hex.on:
            h = v.replace(" ", "").replace("0x", "").replace(",", "")
            if len(h) % 2 or any(c not in "0123456789abcdefABCDEF" for c in h):
                return b"", "not valid hex"
            return bytes.fromhex(h), None
        return v.encode("latin-1", "replace"), None

    # ------------------------------------------------------------ GLOSSARY
    def _p_glossary(self, s):
        self.f_gloss.draw(s)
        flt = self.f_gloss.value.lower().strip()
        items = [(t, d) for t, d in GLOSSARY if not flt or flt in t.lower() or flt in d.lower()]
        text(s, "%d TERMS" % len(items), (400, 134), 11, C["dim"], bold=True)
        colw = (ui.W - 72) // 2
        cols = [24, 24 + colw + 24]
        top = 170
        bot = ui.BOT - 14
        # lay out in two columns, scrolling by item
        sc = self.scroll["GLOSSARY"] = min(self.scroll["GLOSSARY"], max(0, len(items) - 1))
        ci, y = 0, top
        for t, d in items[sc:]:
            lines = ui.wrap(d, 12, colw - 170, mono=False)
            h = max(1, len(lines)) * 16 + 10
            if y + h > bot:
                ci += 1
                y = top
                if ci > 1:
                    break
            x = cols[ci]
            text(s, t, (x, y), 12, C["amber"], bold=True, mono=False)
            yy = y
            for ln in lines:
                text(s, ln, (x + 170, yy), 12, (200, 206, 214), mono=False)
                yy += 16
            pygame.draw.line(s, (40, 44, 50), (x, y + h - 5), (x + colw, y + h - 5), 1)
            y += h
        if sc or len(items) > 0:
            ui.scrollbar(s, (ui.W - 18, top, 6, bot - top), sc, 30, max(30, len(items)))


# ------------------------------------------------------------- connector art
def _pin(s, pos, label, hl, r=13, col=(200, 170, 90)):
    on = hl is not None and label == hl
    pygame.draw.circle(s, (20, 18, 12), (pos[0] + 2, pos[1] + 2), r)
    pygame.draw.circle(s, (255, 210, 90) if on else col, pos, r)
    pygame.draw.circle(s, (250, 230, 170), (pos[0] - r // 3, pos[1] - r // 3), max(2, r // 4))
    text(s, label, (pos[0], pos[1] + r + 12), 11, C["amber"] if on else C["white"], bold=True, align="m")


def draw_connector(s, c, r, hl):
    k = c["kind"]
    cx, cy = r.center
    female = "Female" in c["view"]
    shell = (120, 124, 130)
    if k in ("dsub9", "dsub25"):
        n_top = 5 if k == "dsub9" else 13
        n_bot = 4 if k == "dsub9" else 12
        pitch = 74 if k == "dsub9" else 36
        wt = n_top * pitch + 40
        wb = wt - 2 * pitch
        pts = [(cx - wt // 2, cy - 70), (cx + wt // 2, cy - 70), (cx + wb // 2, cy + 70), (cx - wb // 2, cy + 70)]
        pygame.draw.polygon(s, (60, 62, 66), [(p[0] + (12 if p[0] > cx else -12), p[1] + (12 if p[1] > cy else -12)) for p in pts])
        pygame.draw.polygon(s, shell, [(p[0] + (12 if p[0] > cx else -12), p[1] + (12 if p[1] > cy else -12)) for p in pts], 3)
        pygame.draw.polygon(s, (28, 30, 34), pts)
        pygame.draw.polygon(s, (90, 94, 100), pts, 2)
        rad = 13 if k == "dsub9" else 9
        for i in range(n_top):
            n = i + 1
            x = cx - (n_top - 1) * pitch // 2 + i * pitch
            if female:
                x = 2 * cx - x
            _pin(s, (x, cy - 28), str(n), hl, rad)
        for i in range(n_bot):
            n = n_top + i + 1
            x = cx - (n_bot - 1) * pitch // 2 + i * pitch
            if female:
                x = 2 * cx - x
            _pin(s, (x, cy + 22), str(n), hl, rad)
    elif k == "rj45":
        body = pygame.Rect(cx - 150, cy - 120, 300, 230)
        pygame.draw.rect(s, (190, 200, 210), body, border_radius=10)
        pygame.draw.rect(s, (230, 236, 240), body, 2, border_radius=10)
        pygame.draw.rect(s, (150, 160, 170), (cx - 60, cy + 110, 120, 60), border_radius=6)
        for i in range(8):
            x = cx - 105 + i * 30
            pygame.draw.rect(s, (220, 180, 70), (x - 6, cy - 110, 12, 70), border_radius=2)
            on = hl == str(i + 1)
            if on:
                pygame.draw.rect(s, (255, 230, 120), (x - 8, cy - 112, 16, 74), 2, border_radius=2)
            text(s, str(i + 1), (x, cy - 24), 14, C["amber"] if on else (30, 34, 40), bold=True, align="m")
        cols = {"1": (240, 160, 60), "2": (240, 140, 30), "3": (110, 220, 110), "4": (80, 120, 255), "5": (150, 180, 255), "6": (60, 200, 60),
                "7": (200, 150, 110), "8": (140, 90, 50)}
        if "Ethernet" in c["name"]:
            for i in range(8):
                x = cx - 105 + i * 30
                col = cols[str(i + 1)]
                pygame.draw.rect(s, col, (x - 9, cy + 6, 18, 90), border_radius=4)
                if i in (0, 2, 4, 6):
                    for yy in range(cy + 12, cy + 92, 14):
                        pygame.draw.line(s, (245, 245, 245), (x - 8, yy), (x + 8, yy + 6), 4)
        text(s, "cable", (cx, cy + 180), 10, C["dim"], align="c")
    elif k == "obd16":
        wt, wb = 470, 400
        pts = [(cx - wt // 2, cy - 90), (cx + wt // 2, cy - 90), (cx + wb // 2, cy + 90), (cx - wb // 2, cy + 90)]
        pygame.draw.polygon(s, (24, 26, 30), pts)
        pygame.draw.polygon(s, (90, 94, 100), pts, 3)
        used = {p[0] for p in c["pins"]}
        for row in range(2):
            for i in range(8):
                n = row * 8 + i + 1
                x = cx - 3.5 * 50 + i * 50
                _pin(s, (int(x), cy - 40 + row * 70), str(n), hl, 11, (200, 170, 90) if str(n) in used else (90, 90, 90))
        pygame.draw.rect(s, (90, 94, 100), (cx - 30, cy - 104, 60, 14), border_radius=3)
    elif k == "m12a5":
        pygame.draw.circle(s, (70, 74, 80), (cx, cy), 150)
        pygame.draw.circle(s, (150, 156, 164), (cx, cy), 150, 4)
        pygame.draw.circle(s, (26, 28, 32), (cx, cy), 118)
        pygame.draw.rect(s, (150, 156, 164), (cx - 12, cy - 132, 24, 22), border_radius=4)
        rr = 66
        pos = {"1": (cx + rr * 0.72, cy - rr * 0.72), "2": (cx - rr * 0.72, cy - rr * 0.72), "3": (cx - rr * 0.72, cy + rr * 0.72),
               "4": (cx + rr * 0.72, cy + rr * 0.72), "5": (cx, cy)}
        for pin, _sig, _n in c["pins"]:
            p = pos.get(pin)
            if p:
                _pin(s, (int(p[0]), int(p[1])), pin, hl, 14)
        text(s, "key", (cx, cy - 152), 10, C["dim"], align="c")
    elif k == "to92":
        body = pygame.Rect(cx - 70, cy - 150, 140, 130)
        pygame.draw.rect(s, (30, 30, 32), body, border_top_left_radius=70, border_top_right_radius=70)
        pygame.draw.rect(s, (90, 90, 96), body, 2, border_top_left_radius=70, border_top_right_radius=70)
        text(s, "DS18B20", (cx, cy - 80), 13, (200, 200, 200), bold=True, align="m")
        for i in range(3):
            x = cx - 45 + i * 45
            pygame.draw.line(s, (200, 200, 205), (x, cy - 20), (x, cy + 110), 5)
            on = hl == str(i + 1)
            text(s, str(i + 1), (x, cy + 128), 14, C["amber"] if on else C["white"], bold=True, align="m")
            text(s, c["pins"][i][1], (x, cy + 148), 11, C["amber"] if on else C["text"], bold=True, align="m")
    elif k == "twinax":
        pygame.draw.circle(s, (34, 34, 38), (cx, cy), 140)                 # jacket
        pygame.draw.circle(s, (170, 150, 110), (cx, cy), 124)              # braided shield
        for a in range(0, 360, 12):
            x = cx + int(118 * math.cos(math.radians(a)))
            y = cy + int(118 * math.sin(math.radians(a)))
            pygame.draw.circle(s, (120, 104, 72), (x, y), 4)
        pygame.draw.circle(s, (225, 225, 230), (cx, cy), 108)              # dielectric
        for dx, ins, lab, pin in ((-48, (90, 130, 230), "Data +", "wire 1"), (48, (235, 235, 235), "Data -", "wire 2")):
            on = hl == pin
            pygame.draw.circle(s, ins, (cx + dx, cy), 36)
            pygame.draw.circle(s, (255, 210, 90) if on else (110, 110, 116), (cx + dx, cy), 36, 3)
            pygame.draw.circle(s, (200, 120, 70), (cx + dx, cy), 16)
            text(s, lab, (cx + dx, cy + 54), 12, C["amber"] if on else (30, 34, 40), bold=True, align="m")
        text(s, "Shield (braid)", (cx, cy - 158), 12, C["amber"] if hl == "braid" else C["white"], bold=True, align="m")
    elif k == "flat":
        pts = [(cx - 160, cy - 40), (cx + 160, cy - 40), (cx + 160, cy + 20), (cx + 120, cy + 50), (cx - 120, cy + 50), (cx - 160, cy + 20)]
        pygame.draw.polygon(s, (230, 200, 40), pts)
        pygame.draw.polygon(s, (120, 100, 20), pts, 2)
        for x, col, lab in ((cx - 70, (150, 90, 40), "AS-i +"), (cx + 70, (60, 90, 200), "AS-i -")):
            pygame.draw.circle(s, col, (x, cy), 24)
            pygame.draw.circle(s, (200, 180, 120), (x, cy), 10)
            text(s, lab, (x, cy + 72), 12, C["white"], bold=True, align="m")
    else:                                            # schematic pin grid
        pins = c["pins"]
        n = len(pins)
        ncol = 3 if n <= 9 else 4
        if k == "schem24":
            ncol = 4
        nrow = (n + ncol - 1) // ncol
        for i, (pin, sig, _note) in enumerate(pins):
            col, row = i % ncol, i // ncol
            x = cx - (ncol - 1) * 70 + col * 140
            y = cy - (nrow - 1) * 40 + row * 80 - 10
            _pin(s, (x, y), pin, hl, 12)
            text(s, sig, (x, y + 38), 10, C["text"], align="m")
        text(s, "schematic - not the physical pin layout", (cx, r.y + 12), 10, C["dim"], align="c")
