"""2.5D look: pre-rendered, lit hardware sprites and CRT glass effects.

No 3D engine. Every piece of equipment is described as a small height map
(how far each pixel stands proud of the panel) plus a material, and is lit
ONCE with a fixed lamp above-left of the console (Lambert + Blinn specular).
The results are cached as ordinary 2D sprites. Knobs are rendered per
rotation angle so the flutes and pointer turn while the highlights stay put,
which is what makes them read as solid objects.

CRT faces are drawn live by the stations and then passed through a cheap
phosphor bloom, scan-line / vignette mask and a glass reflection.
"""
import math
import numpy as np
import pygame

_L = np.array([-0.44, -0.62, 0.65])
_L /= np.linalg.norm(_L)
_H = _L + np.array([0, 0, 1.0])
_H /= np.linalg.norm(_H)
_rng = np.random.default_rng(1986)
_cache = {}


# ------------------------------------------------------------------ basics
def grid(w, h):
    x, y = np.mgrid[0:w, 0:h]
    return x.astype(np.float64), y.astype(np.float64)


def sstep(t):
    t = np.clip(t, 0, 1)
    return t * t * (3 - 2 * t)


def shade(h, albedo, spec=0.25, gloss=20.0, amb=0.45):
    """Light a height map (indexed [x, y]). Flat areas come out as albedo."""
    gx, gy = np.gradient(h)
    inv = 1.0 / np.sqrt(gx * gx + gy * gy + 1.0)
    nx, ny, nz = -gx * inv, -gy * inv, inv
    d = np.clip(nx * _L[0] + ny * _L[1] + nz * _L[2], 0, None) / _L[2]
    s = np.clip(nx * _H[0] + ny * _H[1] + nz * _H[2], 0, 1) ** gloss - _H[2] ** gloss
    lit = amb + (1 - amb) * d
    alb = np.asarray(albedo, dtype=np.float64)
    if alb.ndim == 1:
        alb = alb[None, None, :]
    return np.clip(alb * lit[..., None] + (255.0 * spec) * np.clip(s, 0, None)[..., None], 0, 255)


def surf(rgb, alpha=None):
    w, h = rgb.shape[:2]
    if alpha is None:
        s = pygame.Surface((w, h))
        pygame.surfarray.blit_array(s, np.clip(rgb, 0, 255).astype(np.uint8))
        return s
    s = pygame.Surface((w, h), pygame.SRCALPHA)
    a = pygame.surfarray.pixels3d(s)
    a[:] = np.clip(rgb, 0, 255).astype(np.uint8)
    del a
    a = pygame.surfarray.pixels_alpha(s)
    a[:] = np.clip(alpha, 0, 255).astype(np.uint8)
    del a
    return s


def _fast(s, alpha=False):
    try:
        return s.convert_alpha() if alpha else s.convert()
    except pygame.error:
        return s


def down(s, f):
    return pygame.transform.smoothscale(s, (max(1, s.get_width() // f), max(1, s.get_height() // f)))


def noise(w, h, cell):
    """Smooth value noise in 0..1."""
    sw, sh = max(2, w // cell + 2), max(2, h // cell + 2)
    a = (_rng.random((sw, sh)) * 255).astype(np.uint8)
    s = pygame.Surface((sw, sh))
    pygame.surfarray.blit_array(s, np.dstack([a, a, a]))
    s = pygame.transform.smoothscale(s, (w, h))
    return pygame.surfarray.array3d(s)[:, :, 0] / 255.0


def rrect_sd(x, y, w, h, rad):
    """Signed distance to a rounded rectangle filling (0,0,w,h); <0 inside."""
    qx = np.abs(x - (w - 1) / 2.0) - (w / 2.0 - rad)
    qy = np.abs(y - (h - 1) / 2.0) - (h / 2.0 - rad)
    return np.hypot(np.maximum(qx, 0), np.maximum(qy, 0)) + np.minimum(np.maximum(qx, qy), 0) - rad


def light_at(x, y):
    """Room lighting: one hooded lamp above the middle of the console."""
    f = 1.10 - 0.30 * ((x - 800.0) / 800.0) ** 2 - 0.34 * np.clip((y - 180.0) / 720.0, 0, None) ** 1.6
    return np.clip(f, 0.45, 1.15)


# ------------------------------------------------------------ panel plates
def screw(i=0):
    k = ("screw", i % 4)
    if k not in _cache:
        S, r = 4, 5
        n = (2 * r + 2) * S
        x, y = grid(n, n)
        cx = (n - 1) / 2.0
        dx, dy = x - cx, y - cx
        rho = np.hypot(dx, dy) / (r * S)
        ang = [0.5, 2.1, 1.2, 2.8][i % 4]
        v = np.abs(dx * math.sin(ang) - dy * math.cos(ang)) / (r * S)
        hgt = np.where(rho < 1, 2.6 * S * np.sqrt(np.clip(1 - rho * rho, 0, 1)) * 0.55, 0)
        hgt -= np.where((v < 0.16) & (rho < 0.92), 1.6 * S * sstep((0.16 - v) / 0.1), 0)
        rgb = shade(hgt, (118, 120, 124), spec=0.9, gloss=28, amb=0.3)
        al = 255 * sstep((1.02 - rho) / 0.06)
        _cache[k] = _fast(down(surf(rgb, al), S), True)
    return _cache[k]


def plate(rect, base=(50, 54, 57), screws=True, grain=1.0):
    """Wrinkle-painted steel panel, lit for its position on the console."""
    r = pygame.Rect(rect)
    k = ("plate", r.x, r.y, r.w, r.h, base, screws)
    if k not in _cache:
        w, h = r.w, r.h
        x, y = grid(w, h)
        d = np.minimum(np.minimum(x, w - 1 - x), np.minimum(y, h - 1 - y))
        hgt = np.minimum(d, 3.0) * 0.9 + (_rng.random((w, h)) * 0.42 + noise(w, h, 3) * 1.1) * grain
        alb = np.asarray(base, dtype=np.float64)[None, None, :] * (0.88 + 0.24 * noise(w, h, 56))[..., None]
        rgb = shade(hgt, alb, spec=0.16, gloss=7, amb=0.52)
        rgb *= light_at(r.x + x, r.y + y)[..., None]
        rgb[d < 1] *= 0.35
        s = surf(rgb)
        if screws and w > 120 and h > 80:
            for i, (px, py) in enumerate(((9, 9), (w - 10, 9), (9, h - 10), (w - 10, h - 10))):
                sc = screw(i + r.x // 7)
                s.blit(sc, (px - sc.get_width() // 2, py - sc.get_height() // 2))
        _cache[k] = _fast(s)
    return _cache[k]


def strip(rect, base=(40, 42, 46)):
    """Brushed-metal rail (header / footer of the console)."""
    r = pygame.Rect(rect)
    k = ("strip", r.x, r.y, r.w, r.h, base)
    if k not in _cache:
        w, h = r.w, r.h
        x, y = grid(w, h)
        rows = _rng.random(h) * 0.5 + 0.75
        streak = rows[None, :] * (0.9 + 0.2 * noise(w, h, 90)) * (0.94 + 0.12 * _rng.random((w, h)))
        d = np.minimum(y, h - 1 - y)
        rgb = shade(np.minimum(d, 2.0), np.asarray(base)[None, None, :] * streak[..., None], spec=0.3, gloss=10)
        rgb *= light_at(r.x + x, r.y + y * 0 + 120)[..., None]
        _cache[k] = _fast(surf(rgb))
    return _cache[k]


# ----------------------------------------------------- recessed displays
M = 7          # width of the bezel wall around a recessed display


def well(w, h, tint=(0, 0, 0), rad=6):
    """Bezel of a display set back into the panel: four alpha strips."""
    k = ("well", w, h, tint, rad)
    if k not in _cache:
        W, H = w + 2 * M, h + 2 * M
        x, y = grid(W, H)
        e = rrect_sd(x - M, y - M, w, h, rad)                 # >0 outside the glass
        t = np.clip(e / (M - 2.0), 0, 1)
        hgt = np.where(e <= 0, -7.0, -7.0 * (1 - t))
        hgt = hgt + np.where(e > M - 2.5, 1.6 * np.sin(np.clip((e - (M - 2.5)) / 2.5, 0, 1) * math.pi), 0)
        alb = np.array([34, 36, 39.0])[None, None, :] * (0.9 + 0.2 * _rng.random((W, H)))[..., None]
        rgb = shade(hgt, alb, spec=0.5, gloss=14, amb=0.35)
        glow = (1 - t) * (e > 0)
        rgb += np.asarray(tint, dtype=np.float64)[None, None, :] * (0.16 * glow)[..., None]
        al = 255 * sstep((M + 0.5 - e) / 1.2) * (e > -0.8)
        full = surf(rgb, al)
        c = M + rad
        parts = [((0, 0), (0, 0, W, c)), ((0, H - c), (0, H - c, W, c)),
                 ((0, c), (0, c, c, H - 2 * c)), ((W - c, c), (W - c, c, c, H - 2 * c))]
        _cache[k] = [(off, _fast(full.subsurface(pygame.Rect(src)).copy(), True)) for off, src in parts if src[2] > 0 and src[3] > 0]
    return _cache[k]


def draw_well(s, rect, bg=(4, 9, 8), tint=(0, 0, 0)):
    r = pygame.Rect(rect)
    s.fill(bg, r)
    for (ox, oy), part in well(r.w, r.h, tint):
        s.blit(part, (r.x - M + ox, r.y - M + oy))


def glass(w, h, kind):
    """(multiply mask, additive reflection) for a display face."""
    k = ("glass", w, h, kind)
    if k not in _cache:
        x, y = grid(w, h)
        e = -rrect_sd(x, y, w, h, 7)                          # depth inside the glass
        m = np.ones((w, h))
        m *= 0.50 + 0.50 * sstep(e / 9.0)                     # wall shadow all round
        m *= 0.72 + 0.28 * sstep(np.minimum(x, y * 1.4) / 26.0)   # deeper under the top-left lip
        if kind == "crt":
            m *= 1.0 - 0.13 * (y.astype(int) % 3 == 2)        # scan lines
            u, v = (x - w / 2) / (w / 2), (y - h / 2) / (h / 2)
            m *= 1.0 - 0.30 * np.clip(u * u * v * v * 1.6 + 0.12 * (u * u + v * v), 0, 1)
        m[e < 0] = 0.06
        mult = surf(np.dstack([m, m, m]) * 255)
        band = np.exp(-((x * 0.55 + y - 0.32 * (w * 0.55 + h)) / (0.10 * (w + h))) ** 2)
        band2 = np.exp(-((x * 0.55 + y - 0.47 * (w * 0.55 + h)) / (0.03 * (w + h))) ** 2)
        top = np.exp(-y / (h * 0.16 + 6.0)) * (0.6 + 0.4 * np.exp(-((x - w * 0.3) / (w * 0.45)) ** 2))
        a = (band * 7.0 + band2 * 4.0 + top * (9.0 if kind == "crt" else 6.0)) * (e > 1)
        add = surf(np.dstack([a * 0.92, a, a * 1.06]))
        _cache[k] = (_fast(mult), _fast(add))
    return _cache[k]


def bloom(s, rect, gain=150):
    """Phosphor glow: add a blurred copy of the region to itself."""
    r = pygame.Rect(rect).clip(s.get_rect())
    if r.w < 16 or r.h < 16:
        return
    sub = s.subsurface(r)
    sm = pygame.transform.smoothscale(sub, (max(2, r.w // 4), max(2, r.h // 4)))
    s2 = pygame.transform.smoothscale(sm, (max(2, r.w // 10), max(2, r.h // 10)))
    sm.blit(pygame.transform.smoothscale(s2, sm.get_size()), (0, 0), special_flags=pygame.BLEND_RGB_ADD)
    sm.fill((gain, gain, gain), special_flags=pygame.BLEND_RGB_MULT)
    sub.blit(pygame.transform.smoothscale(sm, r.size), (0, 0), special_flags=pygame.BLEND_RGB_ADD)


def finish_glass(s, rect, kind, gain=150):
    r = pygame.Rect(rect)
    if gain:
        bloom(s, r, gain)
    mult, add = glass(r.w, r.h, kind)
    s.blit(mult, r, special_flags=pygame.BLEND_RGB_MULT)
    s.blit(add, r, special_flags=pygame.BLEND_RGB_ADD)


def round_glass(R):
    """(multiply, add) pair for a circular CRT face of radius R."""
    k = ("rglass", R)
    if k not in _cache:
        n = 2 * R + 1
        x, y = grid(n, n)
        dx, dy = (x - R) / R, (y - R) / R
        rho = np.hypot(dx, dy)
        m = (0.42 + 0.58 * sstep((1 - rho) / 0.07)) * (1.0 - 0.22 * rho ** 3)
        m *= 0.80 + 0.20 * sstep((1 - np.hypot(dx - 0.05, dy - 0.07)) / 0.16)
        m[rho > 1] = 1.0
        hi = np.exp(-(((dx + 0.42) / 0.42) ** 2 + ((dy + 0.50) / 0.20) ** 2)) * 15.0
        hi += np.exp(-(((dx - 0.30) / 0.5) ** 2 + ((dy - 0.74) / 0.07) ** 2)) * 4.0
        hi += 5.0 * np.clip(1 - np.abs(rho - 0.965) / 0.03, 0, 1) * np.clip(-(dx + dy) * 0.7, 0, 1)
        hi *= rho < 0.995
        _cache[k] = (_fast(surf(np.dstack([m, m, m]) * 255)), _fast(surf(np.dstack([hi * 0.9, hi, hi * 1.05]))))
    return _cache[k]


# ------------------------------------------------------------------ knobs
def knob_shadow(r):
    k = ("kshadow", r)
    if k not in _cache:
        n = 2 * r + 30
        x, y = grid(n, n)
        rho = np.hypot(x - n / 2.0 + 4, y - n / 2.0 + 7 - 12) / r
        al = 190 * sstep((1.22 - np.hypot(x - n / 2.0 - 3, y - n / 2.0 - 5) / r) / 0.42)
        _cache[k] = _fast(surf(np.zeros((n, n, 3)), al), True)
        del rho
    return _cache[k]


def knob(r, angle, style="fluted"):
    """Top view of a control knob of radius r turned to `angle` degrees."""
    q = round(angle / 3.0) * 3 % 360 if style != "bar" else round(angle) % 360
    k = ("knob", r, q, style)
    if k in _cache:
        return _cache[k]
    S = 3
    R = r * S
    n = 2 * (r + 3) * S
    x, y = grid(n, n)
    c = (n - 1) / 2.0
    dx, dy = x - c, y - c
    rho = np.hypot(dx, dy) / R
    a = math.radians(q)
    u = (dx * math.sin(a) - dy * math.cos(a)) / R              # along the pointer
    v = (dx * math.cos(a) + dy * math.sin(a)) / R              # across it
    th = np.arctan2(v, u)
    if style == "bar":
        base = rho < 0.93
        hgt = np.where(base, 1.6 * S * sstep((0.93 - rho) / 0.06), 0.0)
        wv = np.where(u < 0.25, 0.31, 0.31 - 0.25 * (u - 0.25) / 0.73)
        inside = (np.abs(v) < wv) & (u > -0.82) & (u < 0.98)
        prof = np.sqrt(np.clip(1 - (v / np.maximum(wv, 1e-3)) ** 2, 0, 1)) ** 0.6
        endf = sstep((u + 0.82) / 0.12) * sstep((0.98 - u) / 0.07)
        hgt = np.where(inside, 1.6 * S + 9.5 * S * prof * endf, hgt)
        alb = np.where(inside[..., None], np.array([24, 24, 26.0]), np.array([74, 77, 82.0]) * (0.85 + 0.3 * np.abs(np.sin(th * 2 + a))[..., None]))
        line = inside & (np.abs(v) < 0.055) & (u > 0.12) & (u < 0.9)
        alb = np.where(line[..., None], np.array([238, 236, 224.0]), alb)
        rgb = shade(hgt, alb, spec=0.55, gloss=26, amb=0.36)
        al = 255 * sstep((0.95 - rho) / 0.03)
        al = np.maximum(al, 255 * inside)
    else:
        nfl = 36 if style == "spun" else 10
        depth = 0.022 if style == "spun" else 0.075
        edge = 0.85 - depth * (0.5 - 0.5 * np.cos(nfl * th)) ** 1.4
        body = rho < edge
        hgt = np.where(rho < 1, 2.4 * S * np.clip((1 - rho) / 0.15, 0, 1), 0.0)
        wall = sstep((edge - rho) / 0.085)
        hgt = np.where(body, 2.4 * S + 8.5 * S * wall + 1.6 * S * (1 - (rho / edge) ** 2), hgt)
        if style == "spun":
            top = rho < edge - 0.10
            ths = np.arctan2(dy, dx)
            spun = 118 + 78 * np.abs(np.cos(ths - 0.9)) ** 3 + 30 * np.abs(np.cos(2 * ths + 0.4))
            ring = 1.0 + 0.05 * np.sin(rho * R * 1.9)
            alb = np.where(top[..., None], (spun * ring)[..., None] * np.array([1.0, 1.0, 1.04]), np.array([26, 26, 28.0]))
            dd = np.hypot(u - 0.50, v) / 0.17
            hgt -= np.where(dd < 1, 3.4 * S * (1 - dd * dd), 0)
            alb = np.where((dd < 1)[..., None], np.array([44, 45, 48.0]), alb)
            rgb = shade(hgt, alb, spec=0.5, gloss=22, amb=0.42)
        else:
            alb = np.where(body[..., None], np.array([33, 33, 36.0]), np.array([42, 42, 46.0]))
            line = (np.abs(v) < 0.075) & (u > 0.18) & (rho < edge - 0.03)
            alb = np.where(line[..., None], np.array([240, 238, 226.0]), alb)
            skl = (np.abs(v) < 0.045) & (u > 0.86) & (rho < 0.985)
            alb = np.where(skl[..., None], np.array([240, 238, 226.0]), alb)
            rgb = shade(hgt, alb, spec=0.6, gloss=30, amb=0.34)
        al = 255 * sstep((1.0 - rho) / 0.02)
    out = _fast(down(surf(rgb, al), S), True)
    if len(_cache) > 9000:
        _cache.clear()
    _cache[k] = out
    return out


# ---------------------------------------------------------------- buttons
def button(w, h, color, lit, pressed):
    """Illuminated legend push-button in a black bezel."""
    k = ("btn", w, h, color, lit, pressed)
    if k not in _cache:
        S = 2
        W, H = w * S, h * S
        x, y = grid(W, H)
        e = -rrect_sd(x, y, W, H, 5 * S)                      # inside distance, whole switch
        cap = e - 3.2 * S                                     # inside distance, lens cap
        hgt = np.minimum(e, 2.0 * S) * 0.9
        up = 1.4 if pressed else 4.2
        hgt = np.where(cap > 0, 1.8 * S - 1.6 * S + up * S * sstep(cap / (2.6 * S)) + 0.6 * S * sstep(cap / (min(W, H) * 0.5)), hgt)
        hgt = np.where((cap <= 0) & (cap > -1.2 * S), 0.4 * S, hgt)
        col = np.asarray(color, dtype=np.float64)
        if lit:
            u, v = (x - W / 2) / (W / 2), (y - H / 2) / (H / 2)
            hot = np.exp(-(u * u * 1.1 + v * v * 1.6))
            em = col[None, None, :] * (0.62 + 0.42 * hot)[..., None] + 105 * (hot ** 2)[..., None]
            sh = shade(hgt, np.array([255, 255, 255.0]), spec=0.2, gloss=20, amb=0.78) / 255.0
            body = shade(hgt, np.array([22, 23, 25.0]), spec=0.5, gloss=18)
            rgb = np.where((cap > 0)[..., None], em * sh, body)
        else:
            dark = col * 0.10 + np.array([40, 42, 46.0])
            alb = np.where((cap > 0)[..., None], dark[None, None, :], np.array([22, 23, 25.0]))
            rgb = shade(hgt, alb, spec=0.55, gloss=24, amb=0.42)
            if pressed:
                rgb *= 0.86
        al = 255 * sstep((e + 0.5) / 1.0)
        _cache[k] = _fast(down(surf(rgb, al), S), True)
    return _cache[k]


def halo(w, h, color, strength=0.34, spread=16):
    """Additive light spill around something lit (blit with BLEND_RGB_ADD)."""
    k = ("halo", w, h, color, strength, spread)
    if k not in _cache:
        W, H = w + 2 * spread, h + 2 * spread
        x, y = grid(W, H)
        e = np.clip(rrect_sd(x - spread, y - spread, w, h, 6), 0, None)
        f = np.exp(-e / (spread * 0.36)) * strength
        _cache[k] = _fast(surf(np.asarray(color, dtype=np.float64)[None, None, :] * f[..., None]))
    return _cache[k]


def lamp(r, color, on):
    """Jewelled indicator lamp in a chrome bezel."""
    k = ("lamp", r, color, on)
    if k not in _cache:
        S = 4
        R = (r + 2.5) * S
        n = int(2 * R + 2 * S)
        x, y = grid(n, n)
        c = (n - 1) / 2.0
        dx, dy = (x - c) / R, (y - c) / R
        rho = np.hypot(dx, dy)
        lens = rho < 0.70
        hgt = np.where(lens, 0.9 * R * np.sqrt(np.clip(1 - (rho / 0.74) ** 2, 0, 1)) * 0.55,
                       0.26 * R * np.sin(np.clip((1 - rho) / 0.30, 0, 1) * math.pi))
        col = np.asarray(color, dtype=np.float64)
        chrome = shade(hgt, np.array([150, 152, 158.0]), spec=0.95, gloss=18, amb=0.3)
        if on:
            core = np.exp(-(rho / 0.42) ** 2)
            em = col[None, None, :] * (0.72 + 0.4 * core)[..., None] + 150 * (core ** 2)[..., None]
            gl = shade(hgt, np.array([255, 255, 255.0]), spec=0.5, gloss=40, amb=0.85) / 255.0
            lensrgb = em * gl
        else:
            lensrgb = shade(hgt, col * 0.20 + 14, spec=0.75, gloss=38, amb=0.4)
        rgb = np.where(lens[..., None], lensrgb, chrome)
        al = 255 * sstep((1.0 - rho) / 0.04)
        _cache[k] = _fast(down(surf(rgb, al), S), True)
    return _cache[k]


def glow(r, color, strength=0.5):
    k = ("glow", r, color, strength)
    if k not in _cache:
        n = r * 8
        x, y = grid(n, n)
        f = np.exp(-(np.hypot(x - n / 2.0, y - n / 2.0) / (r * 1.5)) ** 1.5) * strength
        _cache[k] = _fast(surf(np.asarray(color, dtype=np.float64)[None, None, :] * f[..., None]))
    return _cache[k]


def guard(w, h, is_open, pressed):
    """Distress button: mushroom push under a hinged, striped safety cover."""
    k = ("guard", w, h, is_open, pressed)
    if k not in _cache:
        S = 2
        W, H = w * S, h * S
        x, y = grid(W, H)
        e = -rrect_sd(x, y, W, H, 8 * S)
        if is_open:
            hgt = np.minimum(e, 3.0 * S) * 0.8 - 4.0 * S * sstep((e - 4 * S) / (4.0 * S))
            alb = np.where((e > 5 * S)[..., None], np.array([20, 20, 22.0]), np.array([150, 28, 22.0]))
            R = min(W, H) * 0.34
            rho = np.hypot(x - W / 2.0, y - H / 2.0 - 2 * S) / R
            dome = rho < 1
            hgt = np.where(dome, -4.0 * S + (4.0 if pressed else 9.0) * S + R * 0.42 * np.sqrt(np.clip(1 - rho ** 2, 0, 1)), hgt)
            red = np.array([232, 34, 26.0]) if not pressed else np.array([255, 120, 100.0])
            alb = np.where(dome[..., None], red, alb)
            rgb = shade(hgt, alb, spec=0.75, gloss=26, amb=0.38)
            lid = (y < 7 * S) & (e > 0)                       # cover standing open, seen edge-on
            rgb[lid] = rgb[lid] * 0.35 + np.array([170, 40, 30.0]) * 0.65 * (0.7 + 0.5 * (y[lid] / (7.0 * S)))[:, None]
        else:
            hgt = np.minimum(e, 4.0 * S) * 1.5 + 2.5 * S * sstep(e / (min(W, H) * 0.5))
            stripe = ((x + y) // (9 * S)).astype(int) % 2 == 0
            border = e < 7 * S
            alb = np.where((border & stripe)[..., None], np.array([226, 190, 30.0]),
                           np.where(border[..., None], np.array([24, 24, 24.0]), np.array([190, 26, 20.0])))
            rgb = shade(hgt, alb, spec=0.85, gloss=22, amb=0.42)
            hinge = (y < 5 * S) & (np.abs(x - W / 2.0) < W * 0.32) & (e > 0)
            rgb[hinge] = shade(np.where(hinge, 3.0 * S * np.sin(np.clip(y / (5.0 * S), 0, 1) * math.pi), 0),
                               np.array([120, 122, 128.0]), spec=0.9, gloss=16)[hinge]
        al = 255 * sstep((e + 0.5) / 1.0)
        _cache[k] = _fast(down(surf(rgb, al), S), True)
    return _cache[k]


def module(w, h, sel):
    """Small raised equipment module (block-diagram card)."""
    k = ("module", w, h, sel)
    if k not in _cache:
        S = 2
        W, H = w * S, h * S
        x, y = grid(W, H)
        e = -rrect_sd(x, y, W, H, 6 * S)
        hgt = np.minimum(e, 3.0 * S) * 1.3 + _rng.random((W, H)) * 0.5
        base = np.array([78, 86, 98.0]) if sel else np.array([56, 62, 70.0])
        rgb = shade(hgt, base[None, None, :] * (0.9 + 0.2 * noise(W, H, 30))[..., None], spec=0.3, gloss=12, amb=0.5)
        _cache[k] = _fast(down(surf(rgb, 255 * sstep((e + 0.5) / 1.0)), S), True)
    return _cache[k]


def radar_housing(w, h, cx, cy, R, y0):
    """Cast housing of the PPI with its raised, edge-lit bearing ring."""
    k = ("housing", w, h, cx, cy, R)
    if k not in _cache:
        x, y = grid(w, h)
        d = np.hypot(x - cx, y - cy)
        o = d - R                                             # distance outside the tube face
        hgt = _rng.random((w, h)) * 0.4 + noise(w, h, 3) * 1.0
        collar = (o > 0) & (o < 40)
        prof = np.where(o < 6, -12.0 + 18.0 * sstep(o / 6.0), np.where(o < 34, 6.0, 6.0 * (1 - sstep((o - 34) / 6.0))))
        hgt = np.where(collar, prof, hgt)
        alb = np.array([50, 54, 57.0])[None, None, :] * (0.88 + 0.24 * noise(w, h, 56))[..., None]
        alb = np.where(collar[..., None], np.array([30, 31, 33.0]), alb)
        rgb = shade(hgt, alb, spec=0.3, gloss=9, amb=0.5)
        rgb *= light_at(x, y + y0)[..., None]
        rgb += np.array([10, 34, 18.0])[None, None, :] * (np.clip(1 - o / 7.0, 0, 1) * (o > 0))[..., None]   # tube light on the inner wall
        _cache[k] = surf(rgb, np.where(o > 0, 255, 0))
    return _cache[k]


# ================================================================ COMM-SIM
# Equipment boxes, connectors, terminators and cables for the wiring view.

def device(w, h, base=(58, 64, 72), sel=False):
    """Small lit equipment enclosure with a recessed dark face."""
    k = ("device", w, h, base, sel)
    if k not in _cache:
        S = 2
        W, H = w * S, h * S
        x, y = grid(W, H)
        e = -rrect_sd(x, y, W, H, 5 * S)
        face = e - 4.0 * S
        hgt = np.minimum(e, 3.0 * S) * 1.2 + _rng.random((W, H)) * 0.35
        hgt = np.where(face > 0, 3.6 * S - 1.4 * S * sstep(face / (1.5 * S)), hgt)
        b = np.array(base, dtype=np.float64) * (1.25 if sel else 1.0)
        alb = np.where((face > 0)[..., None], np.array([22, 24, 27.0]), b[None, None, :] * (0.9 + 0.2 * noise(W, H, 24))[..., None])
        rgb = shade(hgt, alb, spec=0.35, gloss=14, amb=0.5)
        _cache[k] = _fast(down(surf(rgb, 255 * sstep((e + 0.5) / 1.0)), S), True)
    return _cache[k]


_CONN = {   # kind: (shape, w, h, body, insert)
    "db9": ("trap", 26, 13, (168, 170, 176), (24, 24, 28)), "db25": ("trap", 40, 13, (168, 170, 176), (24, 24, 28)),
    "db37": ("trap", 52, 13, (168, 170, 176), (24, 24, 28)), "db15": ("trap", 30, 13, (168, 170, 176), (24, 24, 28)),
    "rj45": ("rect", 14, 17, (200, 210, 214), (190, 160, 70)), "m12": ("round", 17, 17, (120, 122, 128), (30, 30, 34)),
    "m8": ("round", 12, 12, (120, 122, 128), (30, 30, 34)), "xlr": ("round", 18, 18, (150, 152, 158), (20, 20, 22)),
    "bnc": ("round", 13, 13, (190, 192, 198), (60, 60, 64)), "twinax": ("round", 17, 17, (176, 160, 110), (40, 40, 44)),
    "deutsch": ("round", 18, 18, (60, 120, 70), (25, 25, 28)), "dt": ("rect", 18, 12, (130, 132, 136), (210, 110, 40)),
    "j1962": ("trap", 28, 13, (34, 34, 38), (60, 60, 64)), "usba": ("rect", 16, 9, (180, 182, 188), (30, 30, 34)),
    "usbb": ("rect", 12, 12, (180, 182, 188), (30, 30, 34)), "usbc": ("rect", 13, 7, (180, 182, 188), (30, 30, 34)),
    "lc": ("rect", 16, 10, (70, 120, 200), (230, 230, 230)), "sc": ("rect", 14, 14, (70, 120, 200), (230, 230, 230)),
    "lcmm": ("rect", 16, 10, (90, 200, 210), (230, 230, 230)), "sma": ("round", 10, 10, (210, 175, 70), (120, 100, 40)),
    "screw": ("rect", 18, 12, (40, 130, 70), (120, 122, 128)), "centronics": ("rect", 40, 14, (170, 172, 178), (210, 200, 180)),
    "mil": ("round", 20, 20, (90, 96, 70), (30, 30, 34)), "tap": ("rect", 16, 16, (230, 200, 40), (30, 30, 30)),
    "coupler": ("rect", 22, 14, (80, 90, 110), (180, 180, 190)), "n2k": ("round", 17, 17, (40, 40, 44), (20, 20, 22)),
    "stng": ("round", 15, 15, (50, 90, 190), (20, 20, 22)), "header": ("rect", 18, 8, (30, 30, 34), (210, 180, 80)),
    "arinc600": ("rect", 30, 12, (120, 122, 128), (40, 40, 44)), "jack": ("round", 11, 11, (190, 192, 198), (20, 20, 20)),
    "pof": ("round", 11, 11, (40, 40, 44), (230, 60, 40)), "ant": ("round", 9, 9, (210, 175, 70), (60, 60, 60)),
}


def connector(kind):
    k = ("conn", kind)
    if k not in _cache:
        shape, w, h, body, ins = _CONN.get(kind, ("rect", 12, 10, (150, 150, 150), (40, 40, 40)))
        S = 3
        W, H = w * S, h * S
        x, y = grid(W, H)
        if shape == "round":
            r = np.hypot(x - W / 2.0, y - H / 2.0) / (min(W, H) / 2.0)
            e = (1 - r) * min(W, H) / 2.0
            hgt = np.where(r < 1, 2.0 * S + 2.0 * S * sstep((1 - r) / 0.25), 0)
            knurl = (np.abs(np.sin(np.arctan2(y - H / 2.0, x - W / 2.0) * 9)) > 0.6) & (r > 0.72)
            hgt = hgt + knurl * 0.8 * S
            inner = r < 0.52
            alb = np.where(inner[..., None], np.array(ins, dtype=np.float64), np.array(body, dtype=np.float64))
            hgt = np.where(inner, hgt - 2.0 * S, hgt)
        else:
            if shape == "trap":
                sl = 0.18 * (y / H)
                e = np.minimum(np.minimum(x - W * sl, W * (1 - sl) - x), np.minimum(y, H - y))
            else:
                e = -rrect_sd(x, y, W, H, 2 * S)
            hgt = np.where(e > 0, 2.0 * S + 1.5 * S * sstep(e / (2.0 * S)), 0)
            inner = e > min(W, H) * 0.22
            alb = np.where(inner[..., None], np.array(ins, dtype=np.float64), np.array(body, dtype=np.float64))
            hgt = np.where(inner, hgt - 1.2 * S, hgt)
        rgb = shade(hgt, alb, spec=0.7, gloss=22, amb=0.42)
        al = 255 * np.clip(e / 1.5, 0, 1)
        _cache[k] = _fast(down(surf(rgb, al), S), True)
    return _cache[k]


def resistor(vert=False):
    k = ("resistor", vert)
    if k not in _cache:
        S = 3
        w, h = (12, 30) if vert else (30, 12)
        W, H = w * S, h * S
        x, y = grid(W, H)
        u, v = (y, x) if vert else (x, y)
        Lx, Ly = (H, W) if vert else (W, H)
        body = (np.abs(u - Lx / 2) < Lx * 0.30) & (np.abs(v - Ly / 2) < Ly * 0.42)
        lead = (np.abs(v - Ly / 2) < Ly * 0.09)
        prof = np.sqrt(np.clip(1 - ((v - Ly / 2) / (Ly * 0.42)) ** 2, 0, 1))
        hgt = np.where(body, 4.0 * S * prof, np.where(lead, 1.0 * S, 0))
        band = body & (((np.abs(u - Lx * 0.30) < Lx * 0.035)) | (np.abs(u - Lx * 0.42) < Lx * 0.035) |
                       (np.abs(u - Lx * 0.54) < Lx * 0.035) | (np.abs(u - Lx * 0.70) < Lx * 0.03))
        alb = np.where(band[..., None], np.array([150, 40, 30.0]), np.where(body[..., None], np.array([206, 180, 130.0]), np.array([190, 190, 196.0])))
        rgb = shade(hgt, alb, spec=0.6, gloss=20, amb=0.45)
        al = np.where(body | lead, 255, 0)
        _cache[k] = _fast(down(surf(rgb, al), S), True)
    return _cache[k]


def mount_panel(rect, base=(30, 33, 37)):
    """Perforated mounting plate behind the wiring view."""
    r = pygame.Rect(rect)
    k = ("mount", r.x, r.y, r.w, r.h, base)
    if k not in _cache:
        w, h = r.w, r.h
        x, y = grid(w, h)
        hx, hy = (x % 22) - 11, (y % 22) - 11
        hole = np.hypot(hx, hy) < 2.2
        hgt = noise(w, h, 3) * 0.6 - hole * 2.5
        alb = np.array(base, dtype=np.float64)[None, None, :] * (0.9 + 0.18 * noise(w, h, 60))[..., None]
        alb = np.where(hole[..., None], np.array([6, 6, 7.0]), alb)
        rgb = shade(hgt, alb, spec=0.12, gloss=6, amb=0.6)
        rgb *= light_at(r.x + x, r.y + y)[..., None]
        _cache[k] = _fast(surf(rgb))
    return _cache[k]


def cable(s, pts, col, w, dash=False, hot=0.0):
    """Shaded round cable drawn live: drop shadow, body, highlight."""
    if len(pts) < 2:
        return
    ip = [(int(p[0]), int(p[1])) for p in pts]
    sh = [(p[0] + 2, p[1] + 3) for p in ip]
    pygame.draw.lines(s, (8, 8, 9), False, sh, w)
    dark = tuple(int(c * 0.55) for c in col)
    pygame.draw.lines(s, dark, False, ip, w)
    for p in ip:
        pygame.draw.circle(s, dark, p, w // 2)
    pygame.draw.lines(s, col, False, ip, max(1, w - 2))
    for p in ip:
        pygame.draw.circle(s, col, p, max(1, (w - 2) // 2))
    hi = tuple(min(255, int(c * 0.6 + 110)) for c in col)
    hp = [(p[0] - 1, p[1] - 1) for p in ip]
    pygame.draw.lines(s, hi, False, hp, 1)
    if dash:
        for a, b in zip(ip, ip[1:]):
            L = max(1, int(math.hypot(b[0] - a[0], b[1] - a[1])))
            for i in range(0, L, 14):
                f0, f1 = i / L, min(1, (i + 6) / L)
                pygame.draw.line(s, (20, 20, 22), (a[0] + (b[0] - a[0]) * f0, a[1] + (b[1] - a[1]) * f0),
                                 (a[0] + (b[0] - a[0]) * f1, a[1] + (b[1] - a[1]) * f1), max(1, w - 2))
    if hot > 0:
        hc = tuple(min(255, int(c * (1 + hot))) for c in col)
        pygame.draw.lines(s, hc, False, ip, max(1, w - 3))


def glyph(s, kind, r, col=(150, 200, 230)):
    """Tiny vector icon for a device type, drawn inside rect r."""
    cx, cy = r.center
    a = min(r.w, r.h) // 2
    d = pygame.draw
    if kind in ("pc", "laptop", "hmi", "display", "mfd", "scope"):
        d.rect(s, col, (cx - a, cy - a + 2, 2 * a, int(1.3 * a)), 1)
        d.line(s, col, (cx, cy + int(0.35 * a)), (cx, cy + a - 1))
        d.line(s, col, (cx - a // 2, cy + a - 1), (cx + a // 2, cy + a - 1))
    elif kind in ("plc", "io", "rtu", "ied", "coupler"):
        for i in range(3):
            d.rect(s, col, (cx - a + i * (2 * a // 3), cy - a, 2 * a // 3 - 2, 2 * a), 1)
        d.circle(s, col, (cx - a + 4, cy - a + 5), 1)
    elif kind in ("drive", "motor", "servo"):
        d.circle(s, col, (cx, cy), a, 1)
        d.circle(s, col, (cx, cy), a // 3)
        d.line(s, col, (cx - a, cy), (cx + a, cy))
    elif kind in ("sensor", "temp", "xmtr", "pressure"):
        d.circle(s, col, (cx, cy + a // 3), a // 2, 1)
        d.line(s, col, (cx, cy - a), (cx, cy + a // 3 - a // 2))
        d.arc(s, col, (cx - a, cy - a, 2 * a, 2 * a), 0.4, 2.7, 1)
    elif kind in ("meter", "inverter", "evse", "battery"):
        d.rect(s, col, (cx - a, cy - a, 2 * a, 2 * a), 1)
        d.arc(s, col, (cx - a + 2, cy - a // 2, 2 * a - 4, 2 * a - 4), 0.5, 2.6, 1)
        d.line(s, col, (cx, cy + a // 2), (cx + a // 2, cy - a // 4))
    elif kind in ("ecu", "mcu", "chip", "flash", "eeprom", "adc", "rtc", "fpga"):
        d.rect(s, col, (cx - a + 3, cy - a + 3, 2 * a - 6, 2 * a - 6), 1)
        for i in range(4):
            yy = cy - a + 5 + i * (2 * a - 10) // 3
            d.line(s, col, (cx - a, yy), (cx - a + 3, yy))
            d.line(s, col, (cx + a - 3, yy), (cx + a, yy))
    elif kind in ("switch", "hub", "router", "gw", "bridge"):
        d.rect(s, col, (cx - a, cy - a // 2, 2 * a, a), 1)
        for i in range(4):
            d.rect(s, col, (cx - a + 3 + i * (2 * a - 6) // 4, cy - 2, 3, 4))
    elif kind in ("server", "cloud", "broker", "csms", "scada"):
        for i in range(3):
            d.rect(s, col, (cx - a, cy - a + i * (2 * a // 3), 2 * a, 2 * a // 3 - 2), 1)
            d.circle(s, col, (cx + a - 4, cy - a + i * (2 * a // 3) + a // 3 - 1), 1)
    elif kind in ("gps", "ant", "radio", "gateway", "tower", "base", "rgs"):
        d.line(s, col, (cx, cy + a), (cx, cy - a // 3))
        for k in (1, 2, 3):
            d.arc(s, col, (cx - k * a // 3, cy - a // 3 - k * a // 3, 2 * k * a // 3, 2 * k * a // 3), 0.5, 2.64, 1)
    elif kind in ("plane", "aircraft"):
        d.polygon(s, col, [(cx, cy - a), (cx + 2, cy - a // 3), (cx + a, cy + 2), (cx + 2, cy + 2), (cx + 2, cy + a - 3),
                           (cx + a // 3, cy + a), (cx - a // 3, cy + a), (cx - 2, cy + a - 3), (cx - 2, cy + 2), (cx - a, cy + 2), (cx - 2, cy - a // 3)], 1)
    elif kind in ("ship", "vessel"):
        d.polygon(s, col, [(cx - a, cy), (cx + a, cy), (cx + a - 4, cy + a // 2), (cx - a + 4, cy + a // 2)], 1)
        d.rect(s, col, (cx - a // 3, cy - a // 2, 2 * a // 3, a // 2), 1)
    elif kind in ("sat", "spacecraft"):
        d.rect(s, col, (cx - 3, cy - 3, 6, 6), 1)
        d.rect(s, col, (cx - a, cy - 2, a - 4, 4), 1)
        d.rect(s, col, (cx + 4, cy - 2, a - 4, 4), 1)
    elif kind in ("lamp", "light", "fixture", "ballast"):
        d.circle(s, col, (cx, cy - a // 4), a // 2, 1)
        d.line(s, col, (cx - a // 4, cy + a // 2), (cx + a // 4, cy + a // 2))
        for ang in (0.6, 1.57, 2.5):
            d.line(s, col, (cx + math.cos(ang) * a * 0.7, cy - a // 4 - math.sin(ang) * a * 0.7),
                   (cx + math.cos(ang) * a, cy - a // 4 - math.sin(ang) * a))
    elif kind in ("tstat", "button", "keypad"):
        d.rect(s, col, (cx - a, cy - a, 2 * a, 2 * a), 1)
        d.circle(s, col, (cx, cy), a // 2, 1)
    elif kind in ("phone",):
        d.rect(s, col, (cx - a // 2, cy - a, a, 2 * a), 1)
        d.circle(s, col, (cx, cy + a - 3), 1)
    elif kind in ("tool", "tester", "scantool"):
        d.rect(s, col, (cx - a // 2, cy - a, a, 2 * a - 4), 1)
        d.rect(s, col, (cx - a // 2 + 2, cy - a + 2, a - 4, a // 2), 1)
        d.line(s, col, (cx, cy + a - 4), (cx, cy + a))
    elif kind in ("valve",):
        d.polygon(s, col, [(cx - a, cy - a // 2), (cx + a, cy + a // 2), (cx + a, cy - a // 2), (cx - a, cy + a // 2)], 1)
        d.line(s, col, (cx, cy), (cx, cy - a))
        d.line(s, col, (cx - a // 3, cy - a), (cx + a // 3, cy - a))
    elif kind in ("camera",):
        d.rect(s, col, (cx - a, cy - a // 2, int(1.4 * a), a), 1)
        d.polygon(s, col, [(cx + int(0.4 * a), cy - 2), (cx + a, cy - a // 2), (cx + a, cy + a // 2), (cx + int(0.4 * a), cy + 2)], 1)
    elif kind in ("lock",):
        d.rect(s, col, (cx - a // 2, cy, a, a - 2), 1)
        d.arc(s, col, (cx - a // 3, cy - a // 2, 2 * a // 3, a), 0, math.pi, 1)
    elif kind in ("radar",):
        d.circle(s, col, (cx, cy), a, 1)
        d.line(s, col, (cx, cy), (cx + int(0.7 * a), cy - int(0.7 * a)))
    elif kind in ("store",):
        d.ellipse(s, col, (cx - a, cy - a // 3, 2 * a, 2 * a // 3), 1)
    elif kind in ("wind", "anemometer"):
        d.line(s, col, (cx, cy + a), (cx, cy - a // 3))
        for k in range(3):
            ang = k * 2 * math.pi / 3
            ex, ey = cx + int(a * 0.8 * math.cos(ang)), cy - a // 3 + int(a * 0.4 * math.sin(ang))
            d.line(s, col, (cx, cy - a // 3), (ex, ey))
            d.circle(s, col, (ex, ey), 2, 1)
    elif kind in ("pilot", "helm", "wheel"):
        d.circle(s, col, (cx, cy), int(a * 0.7), 1)
        for k in range(6):
            ang = k * math.pi / 3
            d.line(s, col, (cx, cy), (cx + int(a * math.cos(ang)), cy + int(a * math.sin(ang))))
    elif kind in ("compass", "gyro"):
        d.circle(s, col, (cx, cy), a, 1)
        d.polygon(s, col, [(cx, cy - a + 2), (cx + a // 3, cy), (cx, cy + a - 2), (cx - a // 3, cy)], 1)
        d.line(s, col, (cx - a // 3, cy), (cx + a // 3, cy))
    elif kind in ("yacht", "sail"):
        d.line(s, col, (cx, cy - a), (cx, cy + a // 2))
        d.polygon(s, col, [(cx + 1, cy - a), (cx + a, cy + a // 3), (cx + 1, cy + a // 3)], 1)
        d.polygon(s, col, [(cx - a, cy + a // 2), (cx + a, cy + a // 2), (cx + a // 2, cy + a), (cx - a // 2, cy + a)], 1)
    elif kind in ("buoy", "aton"):
        d.polygon(s, col, [(cx - a // 2, cy + a), (cx + a // 2, cy + a), (cx + a // 4, cy - a // 4), (cx - a // 4, cy - a // 4)], 1)
        d.polygon(s, col, [(cx - a // 3, cy - a // 3), (cx, cy - a), (cx + a // 3, cy - a // 3)], 1)
    elif kind in ("engine",):
        d.rect(s, col, (cx - a, cy - a // 2, 2 * a, a), 1)
        d.rect(s, col, (cx - a // 2, cy - a, a, a // 2), 1)
        d.line(s, col, (cx + a, cy), (cx + a + 3, cy))
    elif kind in ("box", "mux", "unit"):
        d.rect(s, col, (cx - a, cy - a // 2, 2 * a, a), 1)
        for k in range(3):
            d.circle(s, col, (cx - a // 2 + k * a // 2, cy), 2, 1)
    else:
        d.rect(s, col, (cx - a // 2, cy - a // 2, a, a), 1)
