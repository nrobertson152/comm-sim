"""Headless check of the real mouse / keyboard event paths: category tabs,
the protocol rack, instrument decks, side panels, fault buttons, device and
cable clicks in the wiring view, the composer, text fields, the LABS and
REFERENCE pages.

    python tests/test_input.py
"""
import os
import sys

os.environ.setdefault("SDL_VIDEODRIVER", "dummy")
os.environ.setdefault("SDL_AUDIODRIVER", "dummy")
os.environ["COMMSIM_STATE"] = ""
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import pygame  # noqa: E402
from commsim.main import App  # noqa: E402
from commsim import ui  # noqa: E402

app = App()
E = pygame.event.Event


def move(p):
    app.handle(E(pygame.MOUSEMOTION, pos=p, rel=(0, 0), buttons=(0, 0, 0)))


def click(p, b=1):
    move(p)
    app.handle(E(pygame.MOUSEBUTTONDOWN, pos=p, button=b))
    app.handle(E(pygame.MOUSEBUTTONUP, pos=p, button=b))
    app.step(1 / 30)
    app.draw()


def key(k, uni=""):
    app.handle(E(pygame.KEYDOWN, key=k, unicode=uni, mod=0, scancode=0))
    app.step(1 / 30)


def typ(s):
    for ch in s:
        key(ord(ch.lower()) if ch.isalpha() else ord(ch), ch)


app.draw()
# category tabs and F-keys
click(app.tabs[1].center)
assert app.mode == 1 and app.scn.key == app.cats[1][3][0].key, "tab click"
key(pygame.K_F3)
assert app.mode == 2, "F3"
key(pygame.K_F1)
# rack: pick the CAN bus
b = next(b for b in app.rack.btns if b._key == "can")
click(b.rect.center)
assert app.scn.key == "can", "rack click"
scn = app.scn
# decks and side panels through their buttons
for i in range(7):
    click(app.bench.dbtn[i].rect.center)
    assert app.bench.cur == i, "deck %d" % i
for i in range(4):
    click(app.bench.sbtn[i].rect.center)
    assert app.bench.side == i, "side %d" % i
# a fault button toggles the fault
click(app.bench.sbtn[1].rect.center)
fb = next(w for w in app.bench.dyn if getattr(w, "_fkey", None) == "babble")
click(fb.rect.center)
assert scn.fault["babble"], "fault button on"
click(fb.rect.center)
assert not scn.fault["babble"], "fault button off"
# wiring view: click a device, then a cable
topo = app.bench.topo
n = scn.by["brk"]
click((int(topo.ox + n.x + n.w // 2), int(topo.oy + n.y + 10)))
assert scn.sel == "brk", "device click"
assert app.bench.side == 0, "device click opens DEVICE"
# terminator click pulls the resistor
t = next(t for t in scn.terms if t.key)
click((int(topo.ox + t.x), int(topo.oy + t.y)))
assert scn.fault["no_" + t.key], "terminator click"
click((int(topo.ox + t.x), int(topo.oy + t.y)))
assert not scn.fault["no_" + t.key], "terminator back"
# composer: transmit the selected template with the button
click(app.bench.dbtn[5].rect.center)
comp = app.bench.inst[5]
n0 = scn.nfr
click(comp.bsend.rect.center)
for _ in range(30):
    app.step(1 / 30)
assert getattr(scn, "_sent", None), "composer send recorded"
assert any(fr.src == "tool" for fr in scn.cap if fr.no > n0), "composer frame on the bus"
# analyzer filter text field
click(app.bench.dbtn[0].rect.center)
click(app.bench.f_filt.rect.center)
typ("engine")
assert app.bench.filter == "engine", "filter typing: %r" % app.bench.filter
key(pygame.K_ESCAPE)
assert ui.FOCUS[0] is None
# SPACE pauses, +/- change speed
key(pygame.K_SPACE, " ")
assert app.paused
key(pygame.K_SPACE, " ")
s0 = app.speed_i
key(pygame.K_MINUS, "-")
assert app.speed_i == s0 - 1
key(pygame.K_EQUALS, "=")
assert app.speed_i == s0
# REFERENCE page: sub tabs, a protocol row, filter typing, CRC field
key(pygame.K_F9)
R = app.ref
app.draw()
for i, tb in enumerate(R.tabs):
    click(tb.rect.center)
    assert R.page == i, "reference tab %d" % i
click(R.tabs[0].rect.center)
click(R.f_proto.rect.center)
typ("lin")
app.draw()
rr, (cat, k) = R.rows[0]
click(rr.center)
assert R.sel_key == k, "reference row click"
key(pygame.K_ESCAPE)
click(R.tabs[4].rect.center)
click(R.f_crc.rect.center)
for _ in range(9):
    key(pygame.K_BACKSPACE)
typ("01030000000A")
click(R.b_hex.rect.center)
assert R._crc_data() == (bytes.fromhex("01030000000A"), None), R._crc_data()
key(pygame.K_ESCAPE)
click(R.tabs[1].rect.center)
rr, layer = R.rows[3]
click(rr.center)
assert R.osi_sel == layer
cr, (cat, k) = R.chips[0]
click(cr.center)
assert R.page == 0 and R.sel_key == k, "chip opens the protocol"
click(R.b_open.rect.center)
assert app.mode < len(app.cats) and app.scn.key == k, "OPEN ON BENCH"
# LABS page: tested in depth by test_labs.py; just the tab and a row click here
key(pygame.K_F8)
app.draw()
rr, i = app.labs.rows[3]
click(rr.center)
assert app.labs.sel == i
# F10 mutes
m = app.audio.mute
key(pygame.K_F10)
assert app.audio.mute != m
print("input ok")
