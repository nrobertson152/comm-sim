"""Headless end-to-end check: every lab can be completed by doing what its
steps ask, on the real bench (deck buttons, fault switches, the COMPOSE
instrument, device selection), and every quiz has a working answer.

    python tests/test_labs.py [lab-id ...] [--shots DIR]
"""
import os
import sys
import time

os.environ.setdefault("SDL_VIDEODRIVER", "dummy")
os.environ.setdefault("SDL_AUDIODRIVER", "dummy")
os.environ["COMMSIM_STATE"] = ""                     # never touch the user's saved progress
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pygame  # noqa: E402
from commsim.main import App  # noqa: E402
from commsim.labs import frame_ok  # noqa: E402
from commsim.protocols.auto_b import uds_key  # noqa: E402

args = [a for a in sys.argv[1:] if not a.startswith("--")]
SHOTS = sys.argv[sys.argv.index("--shots") + 1] if "--shots" in sys.argv else None
if SHOTS in args:
    args.remove(SHOTS)
app = App()
L = app.labs
E = pygame.event.Event


def tick(n=1):
    for _ in range(n):
        app.step(1 / 30.0)


def click(pos):
    app.handle(E(pygame.MOUSEMOTION, pos=pos, rel=(0, 0), buttons=(0, 0, 0)))
    app.handle(E(pygame.MOUSEBUTTONDOWN, pos=pos, button=1))
    app.handle(E(pygame.MOUSEBUTTONUP, pos=pos, button=1))


def set_param(scn, p, val):
    if val == "uds_key":
        val = uds_key(scn.seed)
    if p.kind == "sel":
        p.v = p.opts.index(val)
    else:
        p.v = val


def compose(scn, name, values):
    comp = app.bench.inst[5]
    tpls = comp.tpls()
    idx = next(i for i, t in enumerate(tpls) if name.lower() in t.name.lower())
    comp.idx = idx
    t = tpls[idx]
    for k, v in values.items():
        p = next((p for p in t.params if p.key == k), None)
        if p is not None:
            set_param(scn, p, v)
    comp.send()


def act(scn, c, auto):
    k = c[0]
    b = app.bench
    if k == "deck":
        click(b.dbtn[c[1]].rect.center)          # the real deck button
    elif k == "side":
        click(b.sbtn[c[1]].rect.center)
    elif k == "node":
        scn.sel = c[1]
        b.on_select_node()
    elif k == "fault":
        scn.set_fault(c[1], c[2] if len(c) > 2 else True)
    elif k == "send":
        compose(scn, c[1], auto.get("set", {}))
    elif k == "probe":
        b.probe(c[1])
    elif k == "scope":
        {"math": b.scope.bm, "eye": b.scope.beye}[c[1]].on = True
    elif k == "var":
        for (nid, var), v in auto.get("vars", {}).items():
            scn.by[nid].vars[var] = v


def select_latest(scn, c):
    for fr in reversed(scn.cap):
        if frame_ok(fr, c, scn):
            app.bench.select(fr)
            return True
    return False


def solve(lab):
    L.start(lab)
    tick(2)
    assert L.run is not None and L.run.lab is lab
    app.speed_i = 5                                  # 10x: tests do not need to watch
    wrong_tried = False
    while not L.run.done:
        i = L.run.i                                  # a step may complete by itself (state already right)
        st = lab["steps"][i]
        scn = app.scn
        assert scn.key == lab["key"], (lab["id"], scn.key)
        if "quiz" in st:
            if not wrong_tried:                      # the wrong-answer path once per lab
                L.answer((st["ans"] + 1) % len(st["opts"]))
                assert L.run.mistakes == 1 and L.run.i == i
                wrong_tried = True
            L.answer(st["ans"])
            assert L.run.i == i + 1, "%s quiz %d not accepted" % (lab["id"], i)
            continue
        auto = st.get("auto", {})
        for c in st["chk"]:
            act(scn, c, auto)
        sends = [c for c in st["chk"] if c[0] == "send"]
        t_end = scn.t + 90.0
        last = scn.t
        while L.run.i == i and scn.t < t_end:
            for c in st["chk"]:
                if c[0] == "select":
                    select_latest(scn, c)
            tick(3)
            if sends and scn.t - last > 4.0 and L.run.i == i:
                last = scn.t
                for c in sends:
                    act(scn, c, auto)
        if L.run.i == i:
            raise AssertionError("%s step %d not completed: %s\n  checks: %r" % (lab["id"], i + 1, st["do"], st["chk"]))
    assert L.run.done and L.run.skipped == 0, lab["id"]
    app.draw()                                       # the completed card renders
    if SHOTS:
        os.makedirs(SHOTS, exist_ok=True)
        pygame.image.save(app.screen, os.path.join(SHOTS, "lab_%s.png" % lab["id"]))


def ui_paths():
    """Card buttons, LABS page clicks and the status bar through real events."""
    lab = L.labs[0]
    app.set_mode(app.modes.index("LABS"))
    app.draw()
    rr, idx = L.rows[2]
    click(rr.center)
    assert L.sel == idx, "lab list click"
    click(L.b_start.rect.center)
    assert L.run is not None and L.run.lab is L.labs[idx], "START LAB button"
    assert app.mode < len(app.cats), "start goes to the bench"
    app.draw()
    h0 = L.run.hints
    st = L.run.step
    if "quiz" not in st and st.get("hint"):
        click(L.c_hint.rect.center)
        assert L.run.hints == h0 + 1 and L.run.show_hint, "HINT button"
    app.draw()
    click(L.c_skip.rect.center)
    assert L.run.i == 1 and L.run.skipped == 1, "SKIP button"
    app.draw()
    click(L.c_stop.rect.center)
    assert L.run is None, "STOP button"
    L.start(lab)
    app.set_mode(app.modes.index("REFERENCE"))
    app.draw()                                       # status bar shows the lab from another tab
    app.set_mode(app.modes.index("LABS"))
    app.draw()
    L.stop()


t0 = time.time()
ui_paths()
todo = [l for l in L.labs if not args or l["id"] in args]
for lab in todo:
    t1 = time.time()
    solve(lab)
    print("  %-10s %2d steps  ok  (%.1f s)" % (lab["id"], len(lab["steps"]), time.time() - t1))
print("labs ok: %d labs in %.1f s" % (len(todo), time.time() - t0))
