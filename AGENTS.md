# AGENTS.md

One page of rules for anyone - human or AI - working on COMM-SIM.

## Roles

- **Owner (nrobertson152)** decides scope and priorities, approves and merges releases.
- **Claude** is the primary developer and architect: implements on a branch and opens a pull request.
- **ChatGPT / Codex** reviews and tests pull requests independently (a different model from the implementer).
- **GitHub** holds everything: issues, branches, pull requests, review comments and CI. Report there, not in chat.

## Workflow

1. Branch from `main` (`claude/<topic>`, `codex/<topic>` ...). Never push to `main`.
2. Keep pull requests focused; describe what changed, how it was tested, and anything left open.
3. CI (`.github/workflows/appimage.yml`) runs every test and the selftest, then builds the AppImage. It must be green.
4. The owner merges. Releases are version tags (`v*`).

## Run and test

```
pip install -r requirements.txt
python run.py                       # the application
python tests/test_bits.py           # CRC check values, checksums, floats, stuffing
python tests/test_protocols.py      # every protocol: faults, templates, frame and wire models
python tests/test_input.py          # mouse / keyboard event paths
python tests/test_labs.py           # every lab played to the end on the real bench
python run.py --selftest shots      # one screenshot per protocol + LABS + REFERENCE (120 PNGs)
```

## Code map

`engine.py` discrete-event core, `Frame`, `Wire`, dissection builder - `phy.py` line models - `bits.py` CRCs and
codings - `bench.py` / `topo.py` / `instruments.py` the bench - `labs.py` + `labdata.py` labs - `reference.py` +
`refdata.py` reference - `ui.py` / `fx.py` / `audio.py` look and sound - `protocols/` one scenario class per protocol,
grouped by category (`phys`, `industrial`, `auto`, `marine`, `aero`, `power`, `net`), shared families in `fam.py`
and `webfam.py`.

## Rules for scenarios

- A protocol is a subclass of `engine.Scenario`, listed in its category's `ALL` list.
- Do not shadow the base class's names: `at every advance slot tx emit rx log busload node seg term trunk p2p place
  inspect set_fault on_fault tpls audio draw_extra draw_stats node_label src_str dst_str frame speed nfr cap by nodes
  segs terms fault anim free keys loadw nerr events sel user rng map_m t q key name cat` (`path` and `cond` may be
  overridden on purpose).
- A composer template's preview (`send=False`) must not change the simulation; it returns a `Frame`, or `None` for
  actions that start a multi-message exchange.
- Frames are byte-exact where it teaches something: real field layouts, CRCs from `bits.CRCS` (each with its check
  value), real stuffing and encodings. Devices, values and vendors are fictional.
- Responses are scheduled from the moment the request is actually on the wire (`on_tx` on shared buses), never
  before it.
- Faults are `(key, label, description)`. A terminator with key `k` is toggled by the fault `no_k`.
- Labs check frame texts, fault keys, template names and device variables. If you change any of them, run
  `tests/test_labs.py` and update `labdata.py`.

## Content boundaries

- This is a study aid built from public, generally documented information.
- **MIL-STD-1760 stays at concept level**: it only shows that the aircraft-store interface carries data over
  MIL-STD-1553, with generic 1553 traffic. Do not add store-management, release, arming or other weapon functions,
  and do not reproduce controlled or withheld content.
- Security topics (TLS, SSH, WPA2, UDS SecurityAccess) are explained conceptually. No exploit code, real
  credentials, real key algorithms or attack tooling.

## Style

Python 3.9+, `pygame-ce` and `numpy` only, no asset files: everything is drawn and synthesised at start-up. Keep the
lit 2.5D hardware look of `ui.py` / `fx.py` on the 1600x900 logical canvas. Plain, accurate wording in the guides and
labs; explain *why*, not just *what*.
