"""Guided labs: step-by-step exercises that are checked live against the
running simulation.

A lab (see labdata.py) is a list of steps. A step is either a task with one
or more checks, all of which must be true at the same time, or a
multiple-choice question. Event checks (a frame, a log entry, a composer
send) only count when they happen after the step became current; state
checks (instrument deck, fault switches, selected frame, device variables)
are read live. While a lab runs, its current step is shown on a card at the
bottom of the protocol rack and in the status bar on every tab.
"""
import json
import os
import time
import pygame
from . import ui, fx
from .ui import C, text
from .labdata import LABS, GROUPS

DECKS = ["ANALYZER", "SCOPE", "LOGIC", "FLOW", "SPECTRUM", "COMPOSE", "STATS"]
SIDES = ["DEVICE", "FAULTS", "GUIDE", "SPEC"]
CARD = pygame.Rect(6, 526, 238, 336)        # lab card at the foot of the protocol rack
LIST = pygame.Rect(0, ui.TOP, 480, ui.BOT - ui.TOP)
BRIEF = pygame.Rect(484, ui.TOP, ui.W - 484, ui.BOT - ui.TOP)


def state_path():
    """Where completed labs are remembered. COMMSIM_STATE='' disables saving."""
    p = os.environ.get("COMMSIM_STATE")
    if p is not None:
        return p or None
    return os.path.join(os.path.expanduser("~"), ".commsim", "labs.json")


def ftext(fr):
    return ("%s %s" % (fr.proto, fr.info)).lower()


def _num(v):
    try:
        return float(str(v).split()[0])
    except (ValueError, IndexError):
        return None


def frame_ok(fr, c, scn):
    """Does captured frame `fr` satisfy a ('frame', substr, opts) check?"""
    sub, o = c[1], c[2] if len(c) > 2 else {}
    if sub and sub.lower() not in ftext(fr):
        return False
    if "src" in o and fr.src != o["src"]:
        return False
    if "dst" in o:
        d = fr.dst if isinstance(fr.dst, (list, tuple, set)) else [fr.dst]
        if o["dst"] not in d:
            return False
    if "kind" in o and fr.kind != o["kind"]:
        return False
    if "err" in o:
        e = o["err"]
        if e is False and fr.err:
            return False
        if e is True and not fr.err:
            return False
        if isinstance(e, str) and (not fr.err or e.lower() not in fr.err.lower()):
            return False
    return True


def describe(c):
    """Short human-readable form of a check (shown in the briefing)."""
    k = c[0]
    if k == "deck":
        return "%s deck" % DECKS[c[1]]
    if k == "side":
        return "%s panel" % SIDES[c[1]]
    if k == "fault":
        return "fault '%s' %s" % (c[1], "on" if (len(c) < 3 or c[2]) else "off")
    return k


class Run:
    """Progress through one lab."""

    def __init__(self, lab):
        self.lab = lab
        self.i = 0
        self.t_wall = time.time()
        self.hints = self.mistakes = self.skipped = 0
        self.latch = set()
        self.no0 = self.scan = 0
        self.t0 = 0.0
        self.sent0 = 0
        self.show_hint = False
        self.wrong = set()
        self.last = None                 # (step, skipped) just completed
        self.done = False
        self.secs = 0

    @property
    def step(self):
        st = self.lab["steps"]
        return st[self.i] if self.i < len(st) else None


class Labs:
    def __init__(self, app):
        self.app = app
        self.labs = LABS
        self.by_id = {l["id"]: l for l in LABS}
        self.sel = 0
        self.run = None
        self.scroll = 0
        self.rows = []                   # (rect, lab index) of the visible list rows
        self.opt_r = []                  # quiz option rects on the card
        self.page_opt_r = []
        self.flash = 0.0
        self.store = {"done": {}}
        self._load()
        b = ui.Button
        self.b_start = b((0, 0, 196, 40), "START LAB", "Reset the protocol bench to its initial state and start this lab.", color="green", size=13,
                         on_click=lambda _: self.start(self.labs[self.sel]))
        self.b_cont = b((0, 0, 220, 40), "CONTINUE ON BENCH", "Go to the protocol bench where this lab runs.", size=12,
                        on_click=lambda _: self.goto_bench())
        self.b_stop = b((0, 0, 150, 40), "STOP LAB", "Abandon the running lab.", color="red", size=12, on_click=lambda _: self.stop())
        self.page_btns = [self.b_start, self.b_cont, self.b_stop]
        self.c_hint = b((0, 0, 70, 24), "HINT", "Show a hint for the current step.", color="cyan", size=10, on_click=lambda _: self.hint())
        self.c_skip = b((0, 0, 70, 24), "SKIP", "Skip this step (it is marked as skipped).", size=10, on_click=lambda _: self.skip())
        self.c_stop = b((0, 0, 70, 24), "STOP", "Stop the lab.", color="red", size=10, on_click=lambda _: self.stop())
        self.c_back = b((0, 0, 222, 26), "BACK TO THE LAB BENCH", "Load the protocol this lab runs on.", color="green", size=10,
                        on_click=lambda _: self.goto_bench())
        self.c_next = b((0, 0, 108, 26), "NEXT LAB", "Start the next lab in the list.", color="green", size=10, on_click=lambda _: self.next_lab())
        self.c_close = b((0, 0, 108, 26), "CLOSE", "Close this card.", size=10, on_click=lambda _: self.close())
        self.card_btns = []

    # ------------------------------------------------------------ persistence
    def _load(self):
        p = state_path()
        if not p:
            return
        try:
            with open(p) as f:
                d = json.load(f)
            if isinstance(d.get("done"), dict):
                self.store["done"] = d["done"]
        except (OSError, ValueError, AttributeError):
            pass

    def _save(self):
        p = state_path()
        if not p:
            return
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                json.dump(self.store, f, indent=1)
        except OSError:
            pass

    # --------------------------------------------------------------- control
    def scn(self):
        """The lab's scenario if it is the one on the bench, else None."""
        s = self.app.scn
        if self.run is None or s is None or s.key != self.run.lab["key"]:
            return None
        return s

    def cat_index(self, lab):
        cats = self.app.cats
        for i, c in enumerate(cats):
            if c[0] == lab.get("cat") and any(x.key == lab["key"] for x in c[3]):
                return i
        for i, c in enumerate(cats):
            if any(x.key == lab["key"] for x in c[3]):
                return i
        return None

    def goto_bench(self):
        if self.run is None:
            lab = self.labs[self.sel]
        else:
            lab = self.run.lab
        app = self.app
        ci = self.cat_index(lab)
        if ci is None:
            return
        app.cur_key[ci] = lab["key"]
        app.mode = -1
        app.set_mode(ci)
        ui.sfx("clunk", 0.8)

    def start(self, lab):
        """Fresh scenario, default bench layout, step 1."""
        app = self.app
        app.cache.pop(lab["key"], None)
        self.run = Run(lab)
        self.sel = self.labs.index(lab)
        self.goto_bench()
        b = app.bench
        b.set_deck(0)
        b.set_side(0)
        b.f_filt.value = ""
        b.filter = ""
        b.held = None
        b.b_hold.on = False
        app.paused = False
        self._mark()
        ui.sfx("beep2", 0.8)

    def stop(self):
        self.run = None
        ui.sfx("relay", 0.6)

    def close(self):
        self.run = None

    def next_lab(self):
        i = self.labs.index(self.run.lab) if self.run else self.sel
        self.start(self.labs[(i + 1) % len(self.labs)])

    def _mark(self):
        r = self.run
        s = self.scn()
        r.latch = set()
        r.wrong = set()
        r.show_hint = False
        if s is not None:
            r.no0 = r.scan = s.nfr
            r.t0 = s.t
            r.sent0 = getattr(s, "_sent_seq", 0)
        else:
            r.no0 = r.scan = -1                  # set when the scenario is loaded

    def hint(self):
        r = self.run
        if r and not r.done and r.step is not None:
            if not r.show_hint:
                r.hints += 1
            r.show_hint = not r.show_hint
            ui.sfx("key", 0.5)

    def skip(self):
        r = self.run
        if r and not r.done:
            r.skipped += 1
            self._advance(True)

    def answer(self, k):
        r = self.run
        st = r.step if r else None
        if st is None or "quiz" not in st or r.done:
            return
        if k == st["ans"]:
            self._advance(False)
        elif k not in r.wrong:
            r.wrong.add(k)
            r.mistakes += 1
            ui.sfx("error", 0.7)

    def _advance(self, skipped):
        r = self.run
        r.last = (r.step, skipped)
        r.i += 1
        self.flash = time.time()
        if r.i >= len(r.lab["steps"]):
            r.done = True
            r.secs = int(time.time() - r.t_wall)
            if r.skipped == 0:
                rec = {"secs": r.secs, "date": time.strftime("%Y-%m-%d"), "hints": r.hints, "mistakes": r.mistakes}
                old = self.store["done"].get(r.lab["id"])
                if old and old.get("best"):
                    rec["best"] = min(old["best"], r.secs)
                else:
                    rec["best"] = r.secs
                self.store["done"][r.lab["id"]] = rec
                self._save()
            ui.sfx("done", 0.9)
        else:
            self._mark()
            ui.sfx("ok" if not skipped else "detent", 0.8)

    # ---------------------------------------------------------------- checks
    def check(self, c, s, idx):
        """Evaluate one check. Event checks latch in run.latch."""
        app, r, b = self.app, self.run, self.app.bench
        k = c[0]
        if (r.i, idx) in r.latch:
            return True
        if k == "deck":
            return app.mode < len(app.cats) and b.cur == c[1]
        if k == "side":
            return app.mode < len(app.cats) and b.side == c[1]
        if k == "node":
            return s.sel == c[1]
        if k == "fault":
            return bool(s.fault.get(c[1], False)) == (c[2] if len(c) > 2 else True)
        if k == "nofaults":
            return not any(s.fault.values())
        if k == "select":
            fr = b.selfr
            return fr is not None and frame_ok(fr, c, s)
        if k == "probe":
            sc = b.scope
            nets = sc.nets()
            return bool(nets) and nets[sc.net[0] % len(nets)] == c[1]
        if k == "scope":
            sc = b.scope
            w = {"math": sc.bm, "eye": sc.beye, "decode": sc.bdec}.get(c[1])
            return w is not None and w.on
        if k == "slow":
            return app.speed_i <= (c[1] if len(c) > 1 else 3)
        if k == "filter":
            return c[1].lower() in b.filter.lower()
        if k == "var":
            n = s.by.get(c[1])
            if n is None:
                return False
            v = n.vars.get(c[2])
            if v is None:
                return False
            op, want = c[3], c[4]
            if op == "~":
                return str(want).lower() in str(v).lower()
            if op == "!~":
                return str(want).lower() not in str(v).lower()
            x = _num(v)
            if x is None:
                return False
            return x > want if op == ">" else x < want if op == "<" else abs(x - want) < 1e-9
        if k == "event":
            for t, m in s.events:
                if t >= r.t0 and c[1].lower() in m.lower():
                    r.latch.add((r.i, idx))
                    return True
            return False
        if k == "send":
            for seq, t, name in getattr(s, "_sent", ()):
                if seq > r.sent0 and c[1].lower() in name.lower():
                    r.latch.add((r.i, idx))
                    return True
            return False
        if k == "frame":
            return False                     # latched by the frame scanner
        return False

    def _scan(self, s, checks):
        """Latch frame checks on frames captured since the last scan."""
        r = self.run
        if r.scan < 0:
            r.no0 = r.scan = s.nfr
            r.t0 = s.t
            r.sent0 = getattr(s, "_sent_seq", 0)
            return
        if s.nfr <= r.scan:
            return
        new = []
        for fr in reversed(s.cap):
            if fr.no <= r.scan:
                break
            new.append(fr)
        r.scan = s.nfr
        fc = [(i, c) for i, c in enumerate(checks) if c[0] == "frame" and (r.i, i) not in r.latch]
        for fr in reversed(new):
            for i, c in fc:
                if (r.i, i) not in r.latch and frame_ok(fr, c, s):
                    r.latch.add((r.i, i))

    def update(self, dt):
        r = self.run
        if r is None or r.done:
            return
        s = self.scn()
        st = r.step
        if s is None or st is None or "quiz" in st:
            if s is not None and r.scan < 0:
                self._scan(s, [])
            return
        checks = st["chk"]
        try:
            self._scan(s, checks)
            ok = all(self.check(c, s, i) for i, c in enumerate(checks))
        except Exception:                    # a broken check must never stop the bench
            ok = False
        if ok:
            self._advance(False)

    # ------------------------------------------------------------------ page
    def enter(self):
        if self.run is not None:
            self.sel = self.labs.index(self.run.lab)

    def _layout_list(self):
        self.rows = []
        y = 104 - self.scroll
        out = []
        for g, gname in GROUPS:
            labs = [i for i, l in enumerate(self.labs) if l["group"] == g]
            if not labs:
                continue
            out.append(("h", gname, y))
            y += 20
            for i in labs:
                out.append(("l", i, y))
                y += 22
            y += 4
        self._list_h = y + self.scroll - 104
        return out

    def handle(self, ev):
        for b in self.page_btns:
            if b.visible and b.handle(ev):
                return True
        if ev.type == pygame.MOUSEWHEEL and LIST.collidepoint(ui.MOUSE):
            vis = LIST.bottom - 110
            self.scroll = max(0, min(max(0, getattr(self, "_list_h", 0) - vis), self.scroll - ev.y * 30))
            return True
        if ev.type == pygame.MOUSEBUTTONDOWN and ev.button == 1:
            for rr, i in self.rows:
                if rr.collidepoint(ev.pos):
                    self.sel = i
                    ui.sfx("detent", 0.6)
                    return True
            for rr, k in self.page_opt_r:
                if rr.collidepoint(ev.pos):
                    self.answer(k)
                    return True
        return False

    def tip_at(self, p):
        for b in self.page_btns:
            if b.visible and b.hit(p):
                return b.tip
        for rr, i in self.rows:
            if rr.collidepoint(p):
                l = self.labs[i]
                return "%s - %d steps on the %s bench. Click to read the briefing." % (l["title"], len(l["steps"]), self.app.by_key[l["key"]].name)
        if LIST.collidepoint(p):
            return "Labs are grouped by category. Completed labs show a green tick and your best time."
        return "Read the briefing, press START LAB, then follow the card at the bottom left of the bench. Checks run live."

    def draw(self, s):
        ui.panel(s, LIST, "LAB INDEX")
        ui.panel(s, BRIEF, "BRIEFING")
        self._draw_list(s)
        self._draw_brief(s)

    def _draw_list(self, s):
        n_done = sum(1 for l in self.labs if l["id"] in self.store["done"])
        text(s, "COMPLETED %d OF %d LABS" % (n_done, len(self.labs)), (22, 72), 11, C["amber"], bold=True)
        ui.bar(s, (262, 73, 196, 12), n_done / max(1, len(self.labs)), "green", segs=len(self.labs))
        clip = s.get_clip()
        area = pygame.Rect(8, 98, LIST.w - 16, LIST.bottom - 106)
        s.set_clip(area)
        self.rows = []
        mp = ui.MOUSE
        for kind, v, y in self._layout_list():
            if y < 80 or y > LIST.bottom:
                continue
            if kind == "h":
                ui.legend(s, v, (22, y + 4), 10, align="l", color=(150, 158, 170))
                pygame.draw.line(s, (70, 76, 86), (22 + ui.font(10, True).size(v)[0] + 10, y + 11), (LIST.right - 22, y + 11), 1)
                continue
            lab = self.labs[v]
            rr = pygame.Rect(18, y, LIST.w - 40, 20)
            self.rows.append((rr, v))
            sel = v == self.sel
            act = self.run is not None and self.run.lab is lab
            bg = (58, 50, 26) if sel else ((34, 38, 44) if rr.collidepoint(mp) else (24, 27, 31))
            pygame.draw.rect(s, bg, rr, border_radius=4)
            if sel:
                pygame.draw.rect(s, C["amber"], rr, 1, border_radius=4)
            rec = self.store["done"].get(lab["id"])
            cx, cy = rr.x + 12, rr.centery
            if rec:
                pygame.draw.circle(s, C["green"], (cx, cy), 7)
                pygame.draw.lines(s, (10, 30, 14), False, [(cx - 4, cy), (cx - 1, cy + 3), (cx + 4, cy - 3)], 2)
            elif act:
                pygame.draw.circle(s, C["amber"], (cx, cy), 7, 2)
                pygame.draw.circle(s, C["amber"], (cx, cy), 3)
            else:
                pygame.draw.circle(s, (90, 96, 106), (cx, cy), 7, 1)
            col = C["white"] if sel else C["text"]
            text(s, ui.clip_text(lab["title"], 11, rr.w - 120, mono=False, bold=sel), (rr.x + 26, rr.y + 2), 11, col, bold=sel, mono=False)
            if act and not self.run.done:
                tag = "STEP %d/%d" % (self.run.i + 1, len(lab["steps"]))
                text(s, tag, (rr.right - 8, rr.y + 3), 10, C["amber"], bold=True, align="r")
            elif rec:
                text(s, fmt_secs(rec.get("best", rec["secs"])), (rr.right - 8, rr.y + 3), 10, C["green"], bold=True, align="r")
            else:
                text(s, "%d STEPS" % len(lab["steps"]), (rr.right - 8, rr.y + 3), 10, (110, 118, 130), align="r")
        s.set_clip(clip)
        ui.scrollbar(s, (LIST.right - 14, 100, 6, LIST.bottom - 110), self.scroll, LIST.bottom - 110, max(1, getattr(self, "_list_h", 0)))

    def _draw_brief(self, s):
        lab = self.labs[self.sel]
        cls = self.app.by_key[lab["key"]]
        x0 = BRIEF.x + 24
        text(s, lab["title"], (x0, 72), 22, C["amber"], bold=True, mono=False)
        nq = sum(1 for st in lab["steps"] if "quiz" in st)
        sub = "PROTOCOL  %s     CATEGORY  %s     %d STEPS (%d QUESTIONS)     ABOUT %d MIN" % (
            cls.name.upper(), self._catname(lab), len(lab["steps"]), nq, lab.get("mins", 10))
        text(s, sub, (x0, 106), 11, C["cyan"], bold=True)
        rec = self.store["done"].get(lab["id"])
        run = self.run if (self.run and self.run.lab is lab) else None
        if run and not run.done:
            st, col = "IN PROGRESS  -  STEP %d OF %d" % (run.i + 1, len(lab["steps"])), C["amber"]
        elif run and run.done:
            st, col = "COMPLETE  -  %s%s" % (fmt_secs(run.secs), ("  (%d skipped)" % run.skipped) if run.skipped else ""), C["green"]
        elif rec:
            st, col = "COMPLETED %s  -  BEST %s" % (rec.get("date", ""), fmt_secs(rec.get("best", rec["secs"]))), C["green"]
        else:
            st, col = "NOT STARTED", C["dim"]
        text(s, st, (BRIEF.right - 24, 78), 12, col, bold=True, align="r")
        # left column: learning goals and briefing
        lx, lw = x0, 520
        y = 136
        ui.legend(s, "YOU WILL LEARN", (lx, y), 11, align="l")
        y += 20
        for g in lab.get("learn", []):
            lines = ui.wrap(g, 13, lw - 22, mono=False)
            pygame.draw.circle(s, C["amber"], (lx + 6, y + 9), 3)
            for ln in lines:
                text(s, ln, (lx + 18, y), 13, C["text"], mono=False)
                y += 19
            y += 3
        y += 10
        ui.legend(s, "BRIEFING", (lx, y), 11, align="l")
        y += 20
        paras = lab["brief"].split("\n")
        need = 20 + sum(19 * len(ui.wrap(p_, 13, lw - 28, mono=False)) + 8 for p_ in paras)
        box = pygame.Rect(lx, y, lw, min(need, BRIEF.bottom - 74 - y))
        ui.crt(s, box, (4, 10, 8))
        yy = box.y + 10
        for para in paras:
            yy = ui.text_block(s, para, (box.x + 14, yy, box.w - 28, box.bottom - yy - 6), 13, C["lcdfg"], lh=19, mono=False)
            yy += 8
        y = box.bottom + 18
        if y < BRIEF.bottom - 150:
            ui.legend(s, "HOW LABS WORK", (lx, y), 11, align="l")
            y += 20
            for ln in HOWTO:
                lines = ui.wrap(ln, 12, lw - 22, mono=False)
                if y + 17 * len(lines) > BRIEF.bottom - 74:
                    break
                pygame.draw.circle(s, C["cyan"], (lx + 6, y + 8), 3)
                for l2 in lines:
                    text(s, l2, (lx + 18, y), 12, (170, 178, 188), mono=False)
                    y += 17
                y += 3
        # right column: the steps
        rx = x0 + lw + 26
        rw = BRIEF.right - rx - 24
        y = 136
        ui.legend(s, "STEPS", (rx, y), 11, align="l")
        y += 22
        self.page_opt_r = []
        for i, stp in enumerate(lab["steps"]):
            done = run is not None and (i < run.i or run.done)
            cur = run is not None and not run.done and i == run.i
            quiz = "quiz" in stp
            body = stp["quiz"] if quiz else stp["do"]
            lines = ui.wrap(body, 12, rw - 46, mono=False, bold=cur)
            if not cur:
                lines = lines[:2] if len(lines) <= 2 else lines[:1] + [ui.clip_text(" ".join(lines[1:]), 12, rw - 46, mono=False)]
            h = 8 + 16 * len(lines)
            if y + h > BRIEF.bottom - 70:
                text(s, "... %d more" % (len(lab["steps"]) - i), (rx + 40, y), 11, C["dim"])
                break
            rr = pygame.Rect(rx, y, rw, h)
            pygame.draw.rect(s, (40, 36, 18) if cur else (20, 23, 27), rr, border_radius=5)
            col = C["green"] if done else (C["white"] if cur else (150, 156, 166))
            cx, cy = rx + 16, y + 12
            pygame.draw.circle(s, col, (cx, cy), 9, 0 if done else 2)
            if done:
                pygame.draw.lines(s, (10, 30, 14), False, [(cx - 5, cy), (cx - 1, cy + 4), (cx + 5, cy - 4)], 2)
            else:
                text(s, "?" if quiz else str(i + 1), (cx, cy), 10, col, bold=True, align="m")
            yy = y + 4
            for ln in lines:
                text(s, ln, (rx + 34, yy), 12, col, bold=cur, mono=False)
                yy += 16
            y += h + 4
        # buttons
        by = BRIEF.bottom - 56
        self.b_start.rect.topleft = (x0, by)
        self.b_start.label = "RESTART LAB" if run else "START LAB"
        self.b_cont.rect.topleft = (x0 + 206, by)
        self.b_stop.rect.topleft = (x0 + 436, by)
        self.b_cont.visible = run is not None and not run.done
        self.b_stop.visible = run is not None and not run.done
        self.b_cont.label = "CONTINUE ON BENCH"
        for b in self.page_btns:
            if b.visible:
                b.draw(s)
        if run is None and self.run is not None:
            text(s, "Another lab is running: %s (starting this one stops it)." % self.run.lab["title"], (x0 + 210, by + 13), 11, C["dim"], mono=False)

    def _catname(self, lab):
        ci = self.cat_index(lab)
        return self.app.cats[ci][0] if ci is not None else "-"

    # ---------------------------------------------------------- bench card
    def card_on(self):
        app = self.app
        return self.run is not None and app.mode < len(app.cats)

    def card_handle(self, ev):
        if not self.card_on():
            return False
        if ev.type in (pygame.MOUSEBUTTONDOWN, pygame.MOUSEBUTTONUP) and not CARD.collidepoint(ev.pos):
            down = any(b.down for b in self.card_btns)
            if not down:
                return False
        for b in self.card_btns:
            if b.visible and b.handle(ev):
                return True
        if ev.type == pygame.MOUSEBUTTONDOWN and ev.button == 1:
            for rr, k in self.opt_r:
                if rr.collidepoint(ev.pos):
                    self.answer(k)
                    return True
            return CARD.collidepoint(ev.pos)
        if ev.type == pygame.MOUSEWHEEL and CARD.collidepoint(ui.MOUSE):
            return True
        return False

    def card_tip(self, p):
        if not self.card_on() or not CARD.collidepoint(p):
            return ""
        for b in self.card_btns:
            if b.visible and b.hit(p):
                return b.tip
        for rr, k in self.opt_r:
            if rr.collidepoint(p):
                return "Click to answer."
        return "Lab card: the current step. It is checked live - just do it on the bench."

    def draw_card(self, s):
        self.card_btns = []
        self.opt_r = []
        if not self.card_on():
            return
        r = self.run
        lab = r.lab
        fx.draw_well(s, CARD, (14, 15, 17), (40, 40, 30))
        pygame.draw.rect(s, (96, 84, 46), CARD, 1, border_radius=4)
        x, w = CARD.x + 8, CARD.w - 16
        lit = time.time() - self.flash < 0.6
        lr = pygame.Rect(x, CARD.y + 6, 44, 15)
        pygame.draw.rect(s, C["green"] if lit else (12, 13, 14), lr, border_radius=2)
        text(s, "LAB", lr.center, 10, (10, 20, 10) if lit else (214, 212, 196), bold=True, align="m")
        n = len(lab["steps"])
        text(s, ("STEP %d / %d" % (min(r.i + 1, n), n)) if not r.done else "COMPLETE", (CARD.right - 8, CARD.y + 7), 10,
             C["green"] if r.done else C["amber"], bold=True, align="r")
        y = CARD.y + 26
        for ln in ui.wrap(lab["title"], 11, w, mono=False, bold=True)[:2]:
            text(s, ln, (x, y), 11, C["amber"], bold=True, mono=False)
            y += 14
        y += 3
        sw = (w - (n - 1) * 2) / n
        for i in range(n):
            rr = pygame.Rect(int(x + i * (sw + 2)), y, max(2, int(sw)), 6)
            col = C["green"] if (i < r.i or r.done) else (C["amber"] if i == r.i else (50, 54, 60))
            pygame.draw.rect(s, col, rr, border_radius=2)
        y += 13
        bottom = CARD.bottom - 34
        scn = self.scn()
        if r.done:
            text(s, "LAB COMPLETE", (x, y + 2), 16, C["green"], bold=True, mono=False)
            y += 26
            msg = "Time %s.  Hints %d, wrong answers %d%s." % (fmt_secs(r.secs), r.hints, r.mistakes, (", skipped %d" % r.skipped) if r.skipped else "")
            y = ui.text_block(s, msg, (x, y, w, 40), 11, C["text"], lh=14, mono=False)
            if r.skipped:
                y = ui.text_block(s, "Skipped steps: run the lab again without skipping to record it as completed.", (x, y + 4, w, 40), 10, C["dim"], lh=13, mono=False)
            if r.last and r.last[0].get("why"):
                y = ui.text_block(s, r.last[0]["why"], (x, y + 8, w, bottom - y - 10), 10, (110, 210, 140), lh=13, mono=False)
            self.c_next.rect.topleft = (x, CARD.bottom - 30)
            self.c_close.rect.topleft = (x + 114, CARD.bottom - 30)
            self.card_btns = [self.c_next, self.c_close]
        elif scn is None:
            nm = self.app.by_key[lab["key"]].name
            y = ui.text_block(s, "This lab runs on the %s bench." % nm, (x, y, w, 40), 11, C["white"], lh=14, mono=False)
            self.c_back.rect.topleft = (x, y + 8)
            self.c_stop.rect.topleft = (x, CARD.bottom - 30)
            self.card_btns = [self.c_back, self.c_stop]
        else:
            st = r.step
            quiz = "quiz" in st
            if quiz:
                text(s, "QUESTION", (x, y), 9, C["cyan"], bold=True)
                y += 13
            y = ui.text_block(s, st["quiz"] if quiz else st["do"], (x, y, w, bottom - y), 11, C["white"], lh=14, mono=False, bold=quiz)
            y += 4
            if quiz:
                for k, opt in enumerate(st["opts"]):
                    lines = ui.wrap(opt, 10, w - 26, mono=False)[:3]
                    h = 8 + 12 * len(lines)
                    if y + h > bottom:
                        break
                    rr = pygame.Rect(x, y, w, h)
                    bad = k in r.wrong
                    hov = rr.collidepoint(ui.MOUSE) and not bad
                    pygame.draw.rect(s, (60, 24, 22) if bad else ((44, 52, 60) if hov else (28, 32, 37)), rr, border_radius=4)
                    pygame.draw.rect(s, C["red"] if bad else ((90, 215, 255) if hov else (70, 78, 88)), rr, 1, border_radius=4)
                    text(s, "ABCD"[k], (x + 9, y + 4), 10, C["red"] if bad else C["cyan"], bold=True, align="c")
                    yy = y + 4
                    for ln in lines:
                        text(s, ln, (x + 20, yy), 10, (150, 110, 105) if bad else C["text"], mono=False)
                        yy += 12
                    self.opt_r.append((rr, k))
                    y += h + 3
                if r.wrong:
                    y = ui.text_block(s, "Not quite - try another answer." + ((" Hint: " + st["hint"]) if st.get("hint") else ""),
                                      (x, y + 2, w, bottom - y), 10, C["red"], lh=13, mono=False)
            elif r.show_hint and st.get("hint"):
                y = ui.text_block(s, "HINT: " + st["hint"], (x, y, w, bottom - y), 10, C["cyan"], lh=13, mono=False)
                y += 4
            if r.last is not None and r.last[0].get("why") and y < bottom - 30:
                last, skipped = r.last
                pygame.draw.line(s, (60, 66, 74), (x, y + 2), (x + w, y + 2), 1)
                ui.text_block(s, ("SKIPPED. " if skipped else "DONE. ") + last["why"], (x, y + 6, w, bottom - y - 6), 10,
                              (150, 150, 150) if skipped else (110, 210, 140), lh=13, mono=False)
            self.c_hint.visible = bool(st.get("hint")) and not quiz
            self.c_hint.on = r.show_hint
            self.c_hint.rect.topleft = (x, CARD.bottom - 30)
            self.c_skip.rect.topleft = (x + 76, CARD.bottom - 30)
            self.c_stop.rect.topleft = (x + 152, CARD.bottom - 30)
            self.card_btns = [self.c_hint, self.c_skip, self.c_stop]
        for b in self.card_btns:
            if b.visible:
                b.draw(s)

    # ------------------------------------------------------------ status bar
    def draw_status(self, s, r):
        run = self.run
        if run is None:
            text(s, "LABS (F8): guided exercises with live checks", (r.x + 8, r.y + 10), 11, C["dim"], mono=False)
            return
        lab = run.lab
        if run.done:
            text(s, "LAB COMPLETE: %s" % lab["title"], (r.x + 8, r.y + 3), 10, C["green"], bold=True)
            text(s, "%s, hints %d, wrong answers %d" % (fmt_secs(run.secs), run.hints, run.mistakes), (r.x + 8, r.y + 17), 11, C["text"], mono=False)
            return
        st = run.step
        text(s, ui.clip_text("LAB %d/%d  %s" % (run.i + 1, len(lab["steps"]), lab["title"]), 10, r.w - 16, bold=True), (r.x + 8, r.y + 2), 10, C["amber"], bold=True)
        msg = ("QUESTION: " + st["quiz"]) if "quiz" in st else st["do"]
        text(s, ui.clip_text(msg, 11, r.w - 16, mono=False), (r.x + 8, r.y + 17), 11, C["white"], mono=False)


HOWTO = ["START LAB resets that protocol's bench to its initial state and opens it.",
         "The lab card at the bottom left shows the current step. Just do it on the bench - every step is checked "
         "live and ticks off by itself, with a short explanation of what you just saw.",
         "Questions are answered on the card. HINT helps with the current step; SKIP moves on, but a lab with skipped "
         "steps is not recorded as completed.",
         "The status bar shows the current step on every tab. Completed labs and your best times are remembered."]


def fmt_secs(t):
    t = int(t)
    return "%d min %02d s" % (t // 60, t % 60) if t >= 60 else "%d s" % t
