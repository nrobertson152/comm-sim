"""Physical layer: what an oscilloscope probe sees on each net.

A frame's Wire holds ideal logic levels per line. Each physical model below
maps lines to electrical levels for every probe point (net), then the
cable / transceiver is applied:

* single-pole RC edges with separate rise and fall time constants (open-
  drain pull-ups, CAN recessive edges, slew-limited RS-232 / LIN drivers);
* reflections: a damped ring added at every edge when terminations are
  missing or a stub is long (frequency from the cable length);
* differential and common-mode noise (common-mode cancels in the
  difference, exactly as on a real twisted pair), ground offset,
  attenuation and polarity reversal.
"""
import math
import numpy as np

_rng = np.random.default_rng(11)


def L(line, mp, up=5e-9, dn=None, unit="V"):
    return ("lvl", line, mp, up, dn if dn is not None else up, unit)


def D(p, n, unit="V"):
    return ("diff", p, n, unit)


def A(line, k=1.0, off=0.0, unit="V"):
    return ("ana", line, k, off, unit)


def S(parts, unit="V"):
    return ("sum", parts, unit)


def K(v, unit="V"):
    return ("const", v, unit)


TTL3 = {1: 3.3, 0: 0.0}
TTL5 = {1: 5.0, 0: 0.0}
GPIB = {1: 0.35, 0: 3.4}            # negative logic: asserted (true) = low


def _rs485(line="D", hi=3.55, lo=1.05, tau=12e-9):
    # TIA-485: mark (logic 1) -> A below B.  Lines: D = data, DE = driver enable
    return {"A": ("lvl", line, {1: lo, 0: hi, 2: 2.3, 3: 2.5}, tau, tau, "V"),
            "B": ("lvl", line, {1: hi, 0: lo, 2: 2.6, 3: 2.5}, tau, tau, "V"),
            "VDIFF": D("B", "A")}


MODELS = {
    "ttl": {"TX": L("TX", TTL3, 4e-9), "RX": L("RX", TTL3, 4e-9), "GND": K(0.0)},
    "rs232": {"TXD": L("TX", {1: -8.6, 0: 8.6}, 0.35e-6), "RXD": L("RX", {1: -8.6, 0: 8.6}, 0.35e-6),
              "RTS": L("RTS", {1: 8.6, 0: -8.6}, 0.35e-6), "CTS": L("CTS", {1: 8.6, 0: -8.6}, 0.35e-6),
              "DTR": L("DTR", {1: 8.6, 0: -8.6}, 0.35e-6), "DSR": L("DSR", {1: 8.6, 0: -8.6}, 0.35e-6),
              "GND": K(0.0)},
    "rs422": {"A": L("D", {1: 1.05, 0: 3.55}, 10e-9), "B": L("D", {1: 3.55, 0: 1.05}, 10e-9), "VDIFF": D("B", "A"),
              "RA": L("R", {1: 1.05, 0: 3.55}, 10e-9), "RB": L("R", {1: 3.55, 0: 1.05}, 10e-9), "RDIFF": D("RB", "RA")},
    "rs423": {"SD": L("D", {1: -5.2, 0: 5.2}, 1.2e-6), "SG": K(0.0), "RD": L("R", {1: -5.2, 0: 5.2}, 1.2e-6)},
    "rs485": _rs485(),
    "can": {"CANH": L("B", {0: 3.5, 1: 2.5}, 60e-9, 25e-9), "CANL": L("B", {0: 1.5, 1: 2.5}, 60e-9, 25e-9),
            "VDIFF": D("CANH", "CANL"), "RXD": L("B", TTL5, 5e-9), "TXD": L("T", TTL5, 3e-9)},
    "lin": {"LIN": L("B", {1: 12.0, 0: 0.9}, 3.5e-6, 2.2e-6), "VBAT": K(12.0)},
    "kline": {"K": L("B", {1: 12.0, 0: 0.8}, 1.8e-6, 0.8e-6), "L": L("L", {1: 12.0, 0: 0.8}, 1.8e-6, 0.8e-6)},
    "onewire": {"DQ": L("DQ", {1: 3.3, 0: 0.05}, 1.4e-6, 30e-9)},
    "i2c": {"SCL": L("SCL", {1: 3.3, 0: 0.05}, 0.35e-6, 10e-9), "SDA": L("SDA", {1: 3.3, 0: 0.05}, 0.35e-6, 10e-9)},
    "spi": {"SCLK": L("SCLK", TTL3, 2e-9), "MOSI": L("MOSI", TTL3, 2e-9), "MISO": L("MISO", TTL3, 2e-9),
            "CS0": L("CS0", TTL3, 2e-9), "CS1": L("CS1", TTL3, 2e-9)},
    "usb": {"D+": L("DP", {1: 3.0, 0: 0.05}, 5e-9), "D-": L("DM", {1: 3.0, 0: 0.05}, 5e-9), "VDIFF": D("D+", "D-")},
    "lvds": {"P": L("D", {1: 1.375, 0: 1.025}, 120e-12), "N": L("D", {1: 1.025, 0: 1.375}, 120e-12), "VDIFF": D("P", "N"),
             "CLKP": L("C", {1: 1.375, 0: 1.025}, 120e-12), "CLKN": L("C", {1: 1.025, 0: 1.375}, 120e-12), "CLK": D("CLKP", "CLKN")},
    "a429": {"A": L("W", {1: 5.0, 0: 0.0, -1: -5.0}, 0.42e-6), "B": L("W", {1: -5.0, 0: 0.0, -1: 5.0}, 0.42e-6), "VDIFF": D("A", "B")},
    "a429ls": {"A": L("W", {1: 5.0, 0: 0.0, -1: -5.0}, 3.0e-6), "B": L("W", {1: -5.0, 0: 0.0, -1: 5.0}, 3.0e-6), "VDIFF": D("A", "B")},
    "m1553": {"BUS A": L("A", {1: 3.0, 0: -3.0, 2: 0.0}, 60e-9), "BUS B": L("Bb", {1: 3.0, 0: -3.0, 2: 0.0}, 60e-9)},
    "manch": {"BUS": L("M", {1: 1.6, 0: -1.6, 2: 0.0}, 40e-9)},
    "eth10": {"TD": L("TD", {1: 2.4, 0: -2.4, 2: 0.0}, 9e-9), "RD": L("RD", {1: 2.4, 0: -2.4, 2: 0.0}, 9e-9)},
    "eth100": {"TX": L("M", {1: 1.0, 0: 0.0, -1: -1.0}, 1.4e-9)},
    "eth1000": {"PAIR A": L("PA", {2: 1.0, 1: 0.5, 0: 0.0, -1: -0.5, -2: -1.0}, 1.3e-9),
                "PAIR B": L("PB", {2: 1.0, 1: 0.5, 0: 0.0, -1: -0.5, -2: -1.0}, 1.3e-9)},
    "t1": {"TRX": L("M", {1: 1.1, 0: 0.0, -1: -1.1}, 2.5e-9)},
    "fiber": {"OPTICAL": L("O", {1: 0.50, 0: 0.06}, 70e-12, unit="mW"), "ELEC": L("O", {1: 0.4, 0: -0.4}, 60e-12)},
    "pof": {"OPTICAL": L("O", {1: 0.30, 0: 0.02}, 2e-9, unit="mW")},
    "optport": {"IR LIGHT": L("O", {1: 0.01, 0: 0.40}, 1.5e-6, unit="mW")},
    "hart": {"LOOP": A("LOOP", 1.0, 0.0, "mA"), "VR250": A("LOOP", 0.25, 0.0, "V")},
    "mbus": {"V": L("M", {1: 36.0, 0: 24.0}, 25e-6), "I": L("S", {1: 1.5, 0: 16.5}, 12e-6, unit="mA")},
    "knx": {"BUS": L("K", {0: 29.0, 1: 22.0, 2: 31.5}, 2e-6)},
    "dali": {"DA": L("B", {1: 16.0, 0: 0.6}, 18e-6, 6e-6)},
    "ffpa": {"BUS AC": L("M", {1: 0.45, 0: -0.45, 2: 0.0}, 0.8e-6), "BUS DC": S([(L("M", {1: 0.45, 0: -0.45, 2: 0.0}, 0.8e-6), 1.0), (K(19.0), 1.0)])},
    "asi": {"AS-i +/-": A("ASI", 1.0, 0.0)},
    "sent": {"SIG": L("S", {1: 4.9, 0: 0.2}, 1.6e-6, 0.4e-6)},
    "psi5": {"I": L("I", {1: 32.0, 0: 6.0}, 0.6e-6, unit="mA"), "V": L("V", {1: 10.0, 0: 6.5}, 2e-6)},
    "vpw": {"BUS": L("B", {1: 7.0, 0: 0.0}, 4e-6)},
    "pwm": {"BUS+": L("B", {1: 5.0, 0: 0.0}, 0.6e-6), "BUS-": L("B", {1: 0.0, 0: 5.0}, 0.6e-6), "VDIFF": D("BUS+", "BUS-")},
    "flexray": {"BP": L("F", {1: 3.0, 0: 2.0, 2: 2.5}, 5e-9), "BM": L("F", {1: 2.0, 0: 3.0, 2: 2.5}, 5e-9), "VDIFF": D("BP", "BM"),
                "BP-B": L("G", {1: 3.0, 0: 2.0, 2: 2.5}, 5e-9), "BM-B": L("G", {1: 2.0, 0: 3.0, 2: 2.5}, 5e-9), "VDIFF B": D("BP-B", "BM-B")},
    "spw": {"D": L("D", {1: 0.35, 0: -0.35}, 0.25e-9), "S": L("S", {1: 0.35, 0: -0.35}, 0.25e-9)},
    "cml": {"LANE": L("D", {1: 0.40, 0: -0.40}, 30e-12)},
    "gpib": dict([(n, L(n, GPIB, 25e-9)) for n in ("DIO1", "DIO2", "DIO3", "DIO4", "DIO5", "DIO6", "DIO7", "DIO8",
                                                    "DAV", "NRFD", "NDAC", "ATN", "EOI", "IFC", "SRQ", "REN")]),
    "a717": {"HBP": L("H", {1: 5.0, 0: -5.0}, 4e-6)},
    "seatalk": {"DATA": L("B", {1: 12.0, 0: 0.4}, 6e-6, 2e-6), "+12V": K(12.0)},
    "iolink": {"C/Q": L("B", {1: 0.6, 0: 23.5}, 0.9e-6), "L+": K(24.0)},
    "rf": {"ENV": A("ENV"), "FREQ": A("FREQ", 1.0, 0.0, "kHz"), "I": A("I"), "Q": A("Q")},
    "audio": {"AUDIO": A("AUDIO")},
    "pcm": {"BB": L("D", {1: 1.0, 0: -1.0}, 30e-9)},
    "dc24": {"OUT": L("D", {1: 24.0, 0: 0.0}, 3e-6)},
}

UNIT_DEFAULT = "V"


def nets_of(model):
    return list(MODELS.get(model, {}).keys())


def unit_of(model, net):
    sp = MODELS.get(model, {}).get(net)
    if sp is None:
        return UNIT_DEFAULT
    return sp[-1] if isinstance(sp[-1], str) else UNIT_DEFAULT


def rc_levels(tl, vl, ts, tau_up, tau_dn, v0=None):
    """Exact single-pole RC response to a piecewise-constant target."""
    out = np.empty_like(ts)
    tl = np.asarray(tl, dtype=np.float64)
    vl = np.asarray(vl, dtype=np.float64)
    if len(tl) == 0:
        out[:] = 0.0
        return out
    cur = vl[0] if v0 is None else v0
    edges = list(tl) + [1e30]
    idx = np.searchsorted(ts, tl)
    idx = np.append(idx, len(ts))
    # samples before the first edge sit at the first level
    out[:idx[0]] = vl[0]
    for i in range(len(tl)):
        a, b = idx[i], idx[i + 1]
        tgt = vl[i]
        tau = tau_up if tgt > cur else tau_dn
        if tau <= 0:
            tau = 1e-15
        if b > a:
            dt = ts[a:b] - tl[i]
            out[a:b] = tgt + (cur - tgt) * np.exp(-dt / tau)
        # value reached at the next edge
        dte = edges[i + 1] - tl[i]
        cur = tgt + (cur - tgt) * math.exp(-min(dte / tau, 700.0)) if dte < 1e29 else tgt
    return out


def ring(y, ts, amp, f, decay):
    """Add a damped oscillation after every edge (reflection / LC ringing)."""
    if amp <= 0 or len(ts) < 4:
        return y
    dt = ts[1] - ts[0]
    if dt <= 0:
        return y
    n = int(min(len(ts), max(8, 5 * decay / dt)))
    k = np.arange(n) * dt
    h = amp * np.exp(-k / decay) * np.sin(2 * math.pi * f * k)
    dy = np.diff(y, prepend=y[0])
    return y + np.convolve(dy, h)[:len(y)] * 1.0


def trace(model, wire, net, ts, cond=None, _cm=None):
    """Volts (or mA / mW) on `net` at relative times ts for this frame."""
    cond = cond or {}
    m = MODELS.get(model, {})
    sp = m.get(net)
    if sp is None:
        sp = ("lvl", net, {1: 1.0, 0: 0.0}, 5e-9, 5e-9, "V") if net in wire.L else ("const", 0.0, "V")
    kind = sp[0]
    if kind == "diff":
        cm = _rng.normal(0, 1, len(ts)) * cond.get("cm", 0.0)
        p = trace(model, wire, sp[1], ts, cond, cm)
        n = trace(model, wire, sp[2], ts, cond, cm)
        return p - n
    if kind == "const":
        y = np.full(len(ts), float(sp[1]))
    elif kind == "sum":
        y = np.zeros(len(ts))
        for part, k in sp[1]:
            if part[0] == "lvl":
                tl, vl = wire.L.get(part[1], ([0.0], [1]))
                lv = [part[2].get(v, part[2].get(1, 0.0)) for v in vl]
                y += k * rc_levels(tl, lv, ts, part[3], part[4])
            elif part[0] == "const":
                y += k * part[1]
            elif part[0] == "ana" and part[1] in wire.ana:
                y += k * (wire.ana[part[1]](ts) * part[2] + part[3])
    elif kind == "ana":
        f = wire.ana.get(sp[1])
        y = f(ts) * sp[2] + sp[3] if f else np.zeros(len(ts))
    else:
        line, mp, up, dn = sp[1], sp[2], sp[3], sp[4]
        tl, vl = wire.L.get(line, ([0.0], [1]))
        if not tl:
            tl, vl = [0.0], [1]
        lv = [mp.get(v, mp.get(1, 0.0)) for v in vl]
        r = cond.get("rise", 1.0)
        su = cond.get("slow_up", 1.0)
        sd = cond.get("slow_dn", 1.0)
        y = rc_levels(tl, lv, ts, up * r * su, dn * r * sd)
        if cond.get("float_idle") is not None:
            pass
    if kind in ("lvl", "sum", "ana"):
        if cond.get("refl", 0) > 0 and kind == "lvl":
            y = ring(y, ts, cond["refl"], cond.get("ringf", 4.0 / max(wire.bit, 1e-9)), cond.get("ringd", 0.6 * max(wire.bit, 1e-9)))
        y = y * cond.get("atten", 1.0)
        if cond.get("inv"):
            y = -y
        y = y + cond.get("off", 0.0)
        if cond.get("noise", 0.0) > 0:
            y = y + _rng.normal(0, cond["noise"], len(ts))
        if _cm is not None:
            y = y + _cm
    return y


def fsk(times, bits_t, f_mark, f_space, amp=1.0, f_idle=None):
    """Phase-continuous FSK: returns callable(ts) for a Wire.ana line.
    bits_t: (edge times, bit values)."""
    tl = np.asarray(bits_t[0], dtype=np.float64)
    vl = np.asarray(bits_t[1], dtype=np.float64)

    def f(ts):
        idx = np.clip(np.searchsorted(tl, ts, side="right") - 1, 0, len(vl) - 1)
        fr = np.where(vl[idx] > 0.5, f_mark, f_space)
        if f_idle is not None:
            fr = np.where(vl[idx] < 0, f_idle, fr)
        if len(ts) < 2:
            return np.zeros(len(ts))
        dt = np.diff(ts, prepend=ts[0])
        ph = np.cumsum(2 * math.pi * fr * dt)
        on = (ts >= tl[0]) & (ts <= times)
        return amp * np.sin(ph) * on
    return f
