"""Every simulated protocol, headless: run it, switch every fault on and off,
preview and send every COMPOSE template, and build the dissection and the
wire model of the frames it produces.

    python tests/test_protocols.py [key ...]
"""
import os
import sys
import time
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from commsim.protocols import CATS  # noqa: E402
from commsim.engine import Frame  # noqa: E402

only = sys.argv[1:]
problems = []
seen = set()


def check_frames(s, frs, where):
    for fr in frs:
        try:
            p = fr.pdu
            assert p is not None
            w = fr.wire
            if w is not None:
                for sg in w.segs:
                    if "wire model error" in str(sg[2]):
                        problems.append("%s %s: %s (%s)" % (s.key, where, sg[2], fr.info))
                        break
        except Exception as e:
            problems.append("%s %s: frame '%s' failed: %r" % (s.key, where, fr.info, e))


t0 = time.time()
count = 0
for cat in CATS:
    for cls in cat[3]:
        if cls.key in seen or (only and cls.key not in only):
            continue
        seen.add(cls.key)
        try:
            s = cls()
            assert s.nodes, "no devices"
            s.advance(2.0)
            assert s.nfr > 0, "nothing transmitted in 2 s"
            check_frames(s, list(s.cap)[-60:], "start")
            for k, _, _ in s.faults:
                s.set_fault(k, True)
                s.advance(s.t + 0.6)
                check_frames(s, list(s.cap)[-25:], "fault " + k)
                s.set_fault(k, False)
                s.advance(s.t + 0.2)
            for t in s.tpls():
                n0, q0 = s.nfr, len(s.q)
                pv = t.fn(s, t.vals(), False)               # preview: no side effects
                assert pv is None or isinstance(pv, Frame), "%s preview returned %r" % (t.name, type(pv))
                assert s.nfr == n0 and len(s.q) == q0, "%s preview changed the simulation" % t.name
                if pv is not None:
                    pv.pdu
                t.fn(s, t.vals(), True)
                s.advance(s.t + 0.3)
            check_frames(s, list(s.cap)[-40:], "templates")
            for n in s.nodes:
                s.inspect(n)
            count += 1
        except Exception:
            problems.append("%s: %s" % (cls.key, traceback.format_exc()))

for p in problems:
    print("PROBLEM", p)
assert not problems, "%d problems" % len(problems)
print("protocols ok: %d scenarios in %.1f s" % (count, time.time() - t0))
