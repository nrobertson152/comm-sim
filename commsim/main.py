"""Application shell: window, category selector, protocol rack, time
control, status bar and audio mixing."""
import os
import sys
import time
import pygame
from . import ui, fx, engine
from .ui import C, text, W, H
from .audio import Audio
from .bench import Bench, Rack

SPEEDS = [(1e-4, "1/10000×"), (1e-3, "1/1000×"), (1e-2, "1/100×"), (0.1, "1/10×"),
          (1.0, "REAL TIME"), (10.0, "10×"), (100.0, "100×")]


class App:
    def __init__(self):
        pygame.mixer.pre_init(22050, -16, 1, 512)
        pygame.init()
        pygame.display.set_caption("COMM-SIM  |  Communication Protocol Lab Bench")
        try:
            self.screen = pygame.display.set_mode((W, H), pygame.SCALED | pygame.RESIZABLE)
        except pygame.error:
            self.screen = pygame.display.set_mode((W, H))
        engine.WALL = lambda: pygame.time.get_ticks() / 1000.0
        self.audio = Audio()
        ui.SFX = self.audio.play
        from .protocols import CATS, BY_KEY
        from .labs import Labs
        from .reference import Reference
        self.cats, self.by_key = CATS, BY_KEY
        self.modes = [c[0] for c in CATS] + ["LABS", "REFERENCE"]
        self.cache = {}
        self.cur_key = {i: c[3][0].key for i, c in enumerate(CATS)}
        self.bench = Bench(self)
        self.rack = Rack(self)
        self.labs = Labs(self)
        self.ref = Reference(self)
        self.speed_i = 4
        self.paused = False
        self.status_note = ""
        self.clock = pygame.time.Clock()
        self.running = True
        self.mode = -1
        self.tabs = []
        x = 232
        for i, m in enumerate(self.modes):
            self.tabs.append(pygame.Rect(x + i * 116, 5, 112, 34))
        rx = self.tabs[-1].right + 10
        self.r_pause = pygame.Rect(rx, 6, 54, 32)
        self.r_slow = pygame.Rect(rx + 58, 6, 24, 32)
        self.r_fast = pygame.Rect(rx + 234, 6, 24, 32)
        self.r_clock = pygame.Rect(rx + 86, 6, 144, 32)
        self.r_snd = pygame.Rect(W - 58, 6, 52, 32)
        self.set_mode(0)

    # --------------------------------------------------------------- state
    @property
    def speed(self):
        return 0.0 if self.paused else SPEEDS[self.speed_i][0]

    def scenario(self, key):
        s = self.cache.get(key)
        if s is None:
            s = self.cache[key] = self.by_key[key]()
            s._speed_i = s.speed
        return s

    def set_mode(self, i):
        if i == self.mode:
            return
        self.mode = i
        ui.sfx("tab", 0.8)
        ui.FOCUS[0] = None
        if i < len(self.cats):
            cat = self.cats[i]
            self.rack.build([(c.key, c.name, "%s - %s" % (c.name, c.blurb)) for c in cat[3]], self.cur_key[i], self.pick)
            self.load(self.cur_key[i])
        elif self.modes[i] == "LABS":
            self.labs.enter()
        else:
            self.ref.enter()

    def pick(self, key):
        if self.mode < len(self.cats):
            self.cur_key[self.mode] = key
            self.rack.cur = key
        self.load(key)
        ui.sfx("clunk", 0.8)

    def load(self, key):
        if self.bench.scn is not None:
            self.bench.scn._speed_i = self.speed_i
        s = self.scenario(key)
        self.bench.load(s)
        self.speed_i = getattr(s, "_speed_i", s.speed)

    def open(self, key, cat=None):
        """Jump to the category that holds protocol `key` (preferably `cat`) and load it."""
        order = sorted(range(len(self.cats)), key=lambda i: self.cats[i][0] != cat)
        for i in order:
            c = self.cats[i]
            if any(x.key == key for x in c[3]):
                self.cur_key[i] = key
                self.mode = -1
                self.set_mode(i)
                return
        self.load(key)

    @property
    def scn(self):
        return self.bench.scn

    # ---------------------------------------------------------------- loop
    def handle(self, ev):
        if ev.type == pygame.QUIT:
            self.running = False
            return
        if ev.type in (pygame.MOUSEMOTION, pygame.MOUSEBUTTONDOWN, pygame.MOUSEBUTTONUP):
            ui.MOUSE[0], ui.MOUSE[1] = ev.pos
        if ev.type == pygame.KEYDOWN:
            if pygame.K_F1 <= ev.key <= pygame.K_F9:
                self.set_mode(ev.key - pygame.K_F1)
                return
            if ev.key == pygame.K_F10:
                self.audio.mute = not self.audio.mute
                return
            if ev.key == pygame.K_F11:
                pygame.display.toggle_fullscreen()
                return
            if ui.FOCUS[0] is None and not (self.mode < len(self.cats) and self.bench.inst[self.bench.cur].name == "COMPOSE" and self.bench.inst[5].focus is not None):
                if ev.key == pygame.K_SPACE:
                    self.paused = not self.paused
                    ui.sfx("relay", 0.6)
                    return
                if ev.key in (pygame.K_MINUS, pygame.K_KP_MINUS):
                    self.speed_i = max(0, self.speed_i - 1)
                    ui.sfx("detent", 0.6)
                    return
                if ev.key in (pygame.K_EQUALS, pygame.K_PLUS, pygame.K_KP_PLUS):
                    self.speed_i = min(len(SPEEDS) - 1, self.speed_i + 1)
                    ui.sfx("detent", 0.6)
                    return
        if ev.type == pygame.MOUSEBUTTONDOWN and ev.button == 1 and ev.pos[1] < ui.TOP:
            for i, r in enumerate(self.tabs):
                if r.collidepoint(ev.pos):
                    self.set_mode(i)
            if self.r_pause.collidepoint(ev.pos):
                self.paused = not self.paused
                ui.sfx("relay", 0.6)
            if self.r_slow.collidepoint(ev.pos):
                self.speed_i = max(0, self.speed_i - 1)
                ui.sfx("detent", 0.6)
            if self.r_fast.collidepoint(ev.pos):
                self.speed_i = min(len(SPEEDS) - 1, self.speed_i + 1)
                ui.sfx("detent", 0.6)
            if self.r_snd.collidepoint(ev.pos):
                self.audio.mute = not self.audio.mute
            return
        if self.mode < len(self.cats):
            if self.labs.card_handle(ev):
                return
            if self.rack.handle(ev):
                return
            self.bench.handle(ev)
        elif self.modes[self.mode] == "LABS":
            self.labs.handle(ev)
        else:
            self.ref.handle(ev)

    def step(self, dt):
        s = self.bench.scn
        if s is not None:
            s.advance(s.t + dt * self.speed)
            self.bench.update(dt)
        self.labs.update(dt)

    def gen_audio(self, syn, n):
        out = syn.rumble("fan", n, 12) * 0.03 + syn.osc("hum", 120.0, n) * 0.004
        s = self.bench.scn
        if s is not None and not self.paused:
            try:
                a = s.audio(syn, n)
            except Exception:
                a = None
            if a is not None:
                out = out + a
        return out

    def draw(self):
        s = self.screen
        s.fill((7, 8, 9))
        mode = self.modes[self.mode]
        if self.mode < len(self.cats):
            self.rack.nvis = 13 if self.labs.card_on() else 25
            self.rack.draw(s, self.cats[self.mode][1])
            self.labs.draw_card(s)
            self.bench.draw(s)
        elif mode == "LABS":
            self.labs.draw(s)
        else:
            self.ref.draw(s)
        ui.finish(s)
        self._header(s)
        self._footer(s)
        pygame.display.flip()

    def _header(self, s):
        s.blit(fx.strip((0, 0, W, ui.TOP - 2)), (0, 0))
        pygame.draw.line(s, (4, 4, 5), (0, ui.TOP - 2), (W, ui.TOP - 2), 2)
        pygame.draw.rect(s, (10, 10, 11), (8, 5, 214, 34), border_radius=3)
        pygame.draw.rect(s, (120, 100, 50), (8, 5, 214, 34), 1, border_radius=3)
        text(s, "COMM-SIM", (16, 6), 18, (226, 190, 96), bold=True)
        text(s, "PROTOCOL LAB BENCH", (16, 27), 8, (150, 130, 80), bold=True)
        for i, (m, r) in enumerate(zip(self.modes, self.tabs)):
            act = i == self.mode
            col = C["amber"] if i < len(self.cats) else C["cyan"]
            if act:
                s.blit(fx.halo(r.w, r.h, col, 0.28), (r.x - 16, r.y - 16), special_flags=pygame.BLEND_RGB_ADD)
            s.blit(fx.button(r.w, r.h, col, act, False), r)
            tc = (26, 16, 6) if act else (200, 202, 198)
            text(s, "F%d" % (i + 1), (r.x + 6, r.y + 4), 8, tc if act else C["dim"], bold=True)
            text(s, m, (r.centerx + 6, r.centery), 10, tc, bold=True, align="m")
        r = self.r_pause
        s.blit(fx.button(r.w, r.h, C["red"] if self.paused else C["green"], True, False), r)
        text(s, "PAUSED" if self.paused else "RUN", r.center, 9, (16, 12, 8), bold=True, align="m")
        for rr, lab in ((self.r_slow, "-"), (self.r_fast, "+")):
            s.blit(fx.button(rr.w, rr.h, C["amber"], False, False), rr)
            text(s, lab, rr.center, 13, (220, 220, 210), bold=True, align="m")
        cr = self.r_clock
        fx.draw_well(s, cr, (16, 4, 3), (70, 12, 6))
        scn = self.bench.scn
        t = scn.t if scn else 0.0
        text(s, "T %.6f s" % t, (cr.x + 7, cr.y + 1), 13, (255, 70, 44), bold=True)
        text(s, "SPEED " + SPEEDS[self.speed_i][1], (cr.x + 7, cr.y + 18), 10, (220, 60, 40))
        fx.finish_glass(s, cr, "lcd", 150)
        r = self.r_snd
        mute = self.audio.mute or not self.audio.ok
        s.blit(fx.button(r.w, r.h, (70, 255, 120) if not mute else (255, 66, 56), True, False), r)
        text(s, "MUTED" if mute else "SOUND", (r.centerx, r.y + 6), 9, (10, 20, 10), bold=True, align="c")
        text(s, "F10", (r.centerx, r.y + 17), 9, (10, 20, 10), bold=True, align="c")

    def _footer(self, s):
        s.blit(fx.strip((0, ui.BOT, W, H - ui.BOT), (30, 31, 33)), (0, ui.BOT))
        pygame.draw.line(s, (4, 4, 5), (0, ui.BOT), (W, ui.BOT), 2)
        p = ui.MOUSE
        tip = ""
        if p[1] < ui.TOP:
            for i, r in enumerate(self.tabs):
                if r.collidepoint(p):
                    tip = ("F%d  " % (i + 1)) + (self.cats[i][2] if i < len(self.cats) else ("Guided exercises that check your actions live." if self.modes[i] == "LABS" else "Protocol matrix, OSI map, connectors, line codes, CRCs and glossary."))
            if self.r_pause.collidepoint(p):
                tip = "Pause / run the simulation (SPACE)."
            if self.r_slow.collidepoint(p) or self.r_fast.collidepoint(p) or self.r_clock.collidepoint(p):
                tip = "Simulation time scale (- / + keys). Slow motion lets you watch single frames and arbitration travel along the wires."
        elif ui.TOP <= p[1] < ui.BOT:
            if self.mode < len(self.cats):
                tip = self.labs.card_tip(p) or self.rack.tip_at(p) or self.bench.tip_at(p)
            elif self.modes[self.mode] == "LABS":
                tip = self.labs.tip_at(p)
            else:
                tip = self.ref.tip_at(p)
        if not tip and self.status_note:
            tip = self.status_note
        if not tip:
            tip = "Pick a category (F1-F9) and a protocol on the left. Click devices to inspect, cables to probe, terminators to pull. SPACE pauses, -/+ change speed."
        ui.text_block(s, tip, (12, ui.BOT + 3, 1050, 32), 11, (226, 224, 210), lh=14, mono=False)
        self.labs.draw_status(s, pygame.Rect(1070, ui.BOT + 1, W - 1070, H - ui.BOT - 1))

    def run(self):
        while self.running:
            dt = min(0.1, self.clock.tick(60) / 1000.0)
            for ev in pygame.event.get():
                self.handle(ev)
            self.step(dt)
            self.audio.pump(self.gen_audio)
            self.draw()
        pygame.quit()


def selftest(outdir, only=None):
    """Headless smoke test: every protocol, every instrument, one screenshot each."""
    os.makedirs(outdir, exist_ok=True)
    app = App()
    n = 0
    t0 = time.time()
    for ci, cat in enumerate(app.cats):
        for cls in cat[3]:
            if only and only not in cls.key:
                continue
            app.mode = -1
            app.set_mode(ci)
            app.pick(cls.key)
            scn = app.scn
            for _ in range(30):
                app.step(1 / 30.0)
            app.paused = False
            for k in range(len(app.bench.inst)):
                app.bench.set_deck(k)
                if k == 0 and scn.cap:
                    app.bench.select(scn.cap[-1])
                app.draw()
            app.bench.set_deck(0)
            for side in range(4):
                app.bench.set_side(side)
                app.draw()
            app.bench.set_side(0)
            app.draw()
            pygame.image.save(app.screen, os.path.join(outdir, "%s_%s.png" % (cat[0][:4].lower(), cls.key)))
            n += 1
    for i in (len(app.cats), len(app.cats) + 1):
        app.set_mode(i)
        app.draw()
        pygame.image.save(app.screen, os.path.join(outdir, "zz_%s.png" % app.modes[i].lower()))
    print("selftest ok: %d protocols in %.1f s" % (n, time.time() - t0))


def main():
    if "--selftest" in sys.argv:
        os.environ.setdefault("SDL_VIDEODRIVER", "dummy")
        os.environ.setdefault("SDL_AUDIODRIVER", "dummy")
        i = sys.argv.index("--selftest")
        out = sys.argv[i + 1] if len(sys.argv) > i + 1 and not sys.argv[i + 1].startswith("-") else "shots"
        only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
        selftest(out, only)
        return
    App().run()


if __name__ == "__main__":
    main()
