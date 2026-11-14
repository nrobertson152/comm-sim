"""Lab content. Each lab runs on one protocol bench (key) and is a list of
steps; see labs.py for how the checks are evaluated.

Check grammar (all text matches are case-insensitive substrings of
"<protocol> <info>" of a captured frame):

    deck(i)                instrument deck i is open (ANALYZER ... STATS)
    side(i)                side panel i is open (DEVICE, FAULTS, GUIDE, SPEC)
    sel(text, **opts)      the selected frame matches
    frame(text, **opts)    a matching frame was captured after the step began
    err(text)              an errored frame (error text contains `text`) was captured
    fault(key, on=True)    fault switch state
    send(name)             the COMPOSE template `name` was sent
    node(id)               device `id` is selected
    var(id, name, op, v)   device variable: op '~' contains, '!~' does not contain, '>' '<' '='
    event(text)            a protocol event containing `text` was logged after the step began
    probe(net)             scope channel 1 is on net `net`
    scope(attr)            scope button on: 'math', 'eye'

opts: src=, dst=, kind=, err=

`auto` holds hints for the automatic solver in tests/test_labs.py (template
parameters to set, device variables to turn); it is never shown.
"""

ANALYZER, SCOPE, LOGIC, FLOW, SPECTRUM, COMPOSE, STATS = range(7)
DEVICE, FAULTS, GUIDE, SPEC = range(4)


def deck(i):
    return ("deck", i)


def side(i):
    return ("side", i)


def sel(text="", **o):
    return ("select", text, o)


def frame(text="", **o):
    return ("frame", text, o)


def err(text="", **o):
    o["err"] = text or True
    return ("frame", "", o)


def fault(key, on=True):
    return ("fault", key, on)


def send(name):
    return ("send", name)


def node(nid):
    return ("node", nid)


def var(nid, name, op, val):
    return ("var", nid, name, op, val)


def event(text):
    return ("event", text)


def probe(net):
    return ("probe", net)


def scope(attr):
    return ("scope", attr)


def step(do, *chk, hint="", why="", auto=None):
    return {"do": do, "chk": list(chk), "hint": hint, "why": why, "auto": auto or {}}


def quiz(q, opts, ans, why="", hint=""):
    return {"quiz": q, "opts": opts, "ans": ans, "why": why, "hint": hint}


GROUPS = [("start", "START HERE"), ("phys", "PHYSICAL LAYER"), ("ind", "INDUSTRIAL"), ("auto", "AUTOMOTIVE"),
          ("marine", "MARINE"), ("aero", "AVIATION / AEROSPACE"), ("power", "POWER / BUILDING"), ("net", "NETWORKING / WIRELESS")]

LABS = []


def lab(**kw):
    LABS.append(kw)


# =================================================================== START
lab(id="tour", group="start", key="rs232", cat="PHYSICAL", mins=8,
    title="Bench tour: a PC talks to a bench meter",
    learn=["Read the ANALYZER: one row per message, decoded fields and raw bytes",
           "Look at the same message with the SCOPE, the LOGIC analyser and FLOW",
           "Inject a fault and recognise its symptom",
           "Send your own message with COMPOSE"],
    brief="A PC asks a bench multimeter for a reading twice a second over an RS-232 cable: 9600 bit/s, 8 data bits, "
          "no parity, 1 stop bit (8N1). All the instruments at the bottom of the bench look at the same capture: the "
          "ANALYZER lists the messages, the SCOPE shows the voltages of the selected message, LOGIC shows its bits, "
          "FLOW shows who talks to whom.\n"
          "This first lab is a guided tour. Every step is checked automatically as you do it - you never have to tell "
          "the simulator that you are done. The current step is always on the card at the bottom left.",
    steps=[
        step("In the ANALYZER, click a row with the PC's request MEAS:VOLT:DC? to select it.", deck(ANALYZER), sel("MEAS:VOLT"),
             hint="Rows from PC to DMM carry the command text. Click anywhere on the row.",
             why="Each row is one message: time, source, destination, protocol and a decoded summary. Below the list, "
                 "the decoded fields are on the left and the raw bytes on the right."),
        step("Open the SCOPE deck (the buttons above the instruments). It shows the selected message.", deck(SCOPE),
             why="The scope shows the real voltage on the TXD wire. Press AUTOSET if the trace does not fit the screen."),
        quiz("Between characters the TXD line rests at about -9 V. What is that state called?",
             ["Mark - logic 1", "Space - logic 0", "A break condition", "A ground fault"], 0,
             why="RS-232 is inverted: mark (logic 1, also the idle state) is -3 to -15 V, space (logic 0) is +3 to "
                 "+15 V. Every character begins with a positive-going start bit."),
        step("Open the LOGIC deck: the same message as logic levels, with start, data and stop bits marked.", deck(LOGIC),
             why="Each character is a start bit (0), 8 data bits sent least significant bit first, and a stop bit (1)."),
        quiz("At 9600 bit/s, how long does one bit last?", ["9.6 us", "104 us", "1.04 ms", "0.96 ms"], 1,
             why="1 / 9600 s = 104 us. A 10-bit character (start + 8 data + stop) takes 1.04 ms, so the line carries at "
                 "most 960 characters per second."),
        step("Open FLOW to see the conversation as a sequence diagram.", deck(FLOW),
             why="FLOW draws one arrow per message between the devices - here a strict request / reply rhythm."),
        step("Open the FAULTS panel (right side) and switch on 'PC set to 19200, instrument at 9600'. Watch the requests turn red.",
             side(FAULTS), fault("baud"), err("framing"),
             hint="FAULTS is the second tab of the instrument panel on the right. Each button is one fault.",
             why="The meter samples at 9600 bit/s while the PC sends at 19200: every bit is half as long as expected. "
                 "The receiver sees garbage and framing errors, so it never answers."),
        step("Switch the fault off again and check that the meter answers.", fault("baud", False), frame("", src="dmm"),
             why="Fault finding is always one change at a time, then confirm that the symptom is gone."),
        step("Open COMPOSE, pick 'SCPI command' and send *IDN? (the default). Find the identity string in the reply.",
             deck(COMPOSE), send("SCPI"), frame("COMMSIM,DMM"),
             hint="COMPOSE is the sixth deck. Select the template on the left, then press SEND.",
             why="*IDN? is the standard SCPI identification query. COMPOSE builds a real message and shows its bytes "
                 "before you send it; the simulated instrument answers it like the real one."),
    ])

# =============================================================== PHYSICAL
lab(id="can-phy", group="phys", key="can", cat="PHYSICAL", mins=10,
    title="CAN: dominant bits, terminators and error frames",
    learn=["How CAN_H and CAN_L form a differential, wired-AND bus",
           "How arbitration picks the winner without losing a bit",
           "Why both 120 ohm terminators matter, and what error frames look like"],
    brief="Five ECUs share a 500 kbit/s high-speed CAN bus. Every node hears every frame. The identifier names the "
          "message and sets its priority, because a dominant 0 overwrites a recessive 1 on the wire. The bus is one "
          "twisted pair terminated by 120 ohm at each end - 60 ohm between CAN_H and CAN_L.\n"
          "You will look at the voltages, then break the bus in two different ways and watch CAN's error handling.",
    steps=[
        step("Select one of the engine ECU's EngineStatus frames.", sel("EngineStatus"),
             why="EngineStatus is sent every 10 ms. The tree shows the 11-bit identifier, DLC, data bytes, the 15-bit CRC "
                 "and the ACK slot that every other node fills in."),
        step("Open the SCOPE. CH1 is CAN_H, CH2 is CAN_L.", deck(SCOPE),
             why="Recessive: both wires near 2.5 V (0 V difference). Dominant: CAN_H about 3.5 V and CAN_L about 1.5 V "
                 "(2 V difference). The receiver only looks at the difference."),
        quiz("Two nodes start to send at the same moment, with identifiers 0x100 and 0x0C8. Which one wins?",
             ["0x100, the higher number", "0x0C8, the lower number", "Neither - both frames are destroyed", "Whichever is closer to the terminator"], 1,
             why="Identifiers go out MSB first and a dominant 0 overwrites a recessive 1. A node that sends 1 but reads "
                 "back 0 stops at once. The lowest identifier wins, and its frame is not damaged."),
        step("Open LOGIC and look for the stuff bits (red 'S' markers).", deck(LOGIC),
             why="After five identical bits the transmitter inserts one bit of the opposite level so receivers can keep "
                 "their clocks synchronised. Receivers remove it again."),
        step("Pull the right-hand terminator: switch on 'Terminator missing (right end)' in FAULTS.", fault("no_term1"),
             hint="You can also click the resistor at the end of the bus in the wiring view.",
             why="With one terminator the bus is 120 ohm instead of 60 ohm. Edges ring a little, but on a short bus the "
                 "frames still get through."),
        quiz("Does the bus still work with only one terminator?",
             ["No - every frame fails", "Yes, mostly - with less margin", "Only the high-priority frames", "Only after a reset"], 1,
             why="One terminator usually works on a short bus. That is why a missing terminator can go unnoticed for "
                 "years - until the cable gets longer or the environment noisier."),
        step("Now pull the left terminator as well and watch for error frames.", fault("no_term0"), fault("no_term1"), err("signal integrity"),
             why="Without termination nothing pulls the bus back to recessive quickly: edges crawl, reflections corrupt "
                 "bits, and the receivers flag error frames. CAN retransmits automatically, so data still trickles through."),
        step("Put both terminators back.", fault("no_term0", False), fault("no_term1", False),
             why="Field check with the power off: CAN_H to CAN_L reads 60 ohm with both terminators, 120 ohm with one "
                 "missing, open circuit with none."),
        step("Switch on 'Brake ECU babbling on ID 0x000'.", fault("babble"), frame("BABBLE"),
             why="ID 0x000 wins every arbitration, so a babbling node starves everybody else. Error counters and "
                 "bus-off contain some failures; a stuck transmitter needs a bus guardian."),
        step("Switch the babbling off.", fault("babble", False)),
    ])

lab(id="i2c", group="phys", key="i2c", cat="PHYSICAL", mins=8,
    title="I2C: addresses, ACK and pull-up resistors",
    learn=["How a controller addresses a device and what ACK / NACK mean",
           "How to scan a bus for devices",
           "Why open-drain lines need pull-ups, and how to free a stuck bus"],
    brief="A microcontroller reads a TMP102 temperature sensor (address 0x48), a DS1307 real-time clock (0x68) and an "
          "EEPROM (0x50) over I2C at 100 kHz. SDA and SCL are open-drain: a device can only pull a line low; 4.7 kohm "
          "resistors pull them high again.\n"
          "Every byte is followed by an acknowledge bit driven by the receiver: low = ACK, left high = NACK.",
    steps=[
        step("Select a 'TMP102 read' transaction and open LOGIC.", sel("TMP102 read"), deck(LOGIC),
             why="START (SDA falls while SCL is high), address 0x48 + write, ACK, pointer register 0x00, repeated START, "
                 "0x48 + read, two data bytes, NACK from the MCU, STOP."),
        quiz("A read from address 0x48 is sent on the wire as which byte?", ["0x48", "0x90", "0x91", "0x24"], 2,
             why="The 7-bit address is shifted left one place and the R/W bit added: (0x48 << 1) | 1 = 0x91 for a read, "
                 "0x90 for a write."),
        step("In COMPOSE, send 'Scan bus' and watch which addresses answer.", send("Scan bus"), frame("PROBE 0x48 ACK"),
             why="A scan addresses every 7-bit address in turn. Only addresses with a device pull SDA low in the ACK "
                 "slot; empty addresses leave it high (NACK)."),
        quiz("Which of these addresses did NOT answer the scan?", ["0x48", "0x50", "0x20", "0x68"], 2,
             why="0x48 (sensor), 0x50 (EEPROM) and 0x68 (clock) are present. Nothing lives at 0x20."),
        step("Open the SCOPE and compare the rising and falling edges.", deck(SCOPE),
             why="Falling edges are fast - a transistor pulls the line down. Rising edges are slow RC curves: the pull-up "
                 "resistor has to charge the bus capacitance."),
        step("Switch on 'Pull-up resistors missing'.", fault("nopull"), err("pull-up"),
             why="With nothing pulling the lines high the bus never leaves 0 V: every transfer fails."),
        step("Restore the pull-ups, then inject 'RTC holding SDA low after a reset'.", fault("nopull", False), fault("stuck"), err("SDA held low"),
             why="The clock was reset in the middle of sending a byte and still drives a 0. Nobody else can create a "
                 "START or STOP: the bus is locked."),
        step("COMPOSE 'Bus recovery (9 clocks)' to free the bus.", send("Bus recovery"), frame("Bus recovery"),
             why="The controller clocks SCL up to nine times. The stuck device finishes shifting out its byte and "
                 "releases SDA, then a STOP returns the bus to idle."),
    ])

lab(id="rs485", group="phys", key="rs485", cat="PHYSICAL", mins=8,
    title="RS-485: two wires, many devices",
    learn=["Differential signalling: the receiver looks at B - A",
           "Half-duplex direction control with the driver-enable line",
           "Fail-safe bias, and what happens when two drivers fight"],
    brief="A master polls three temperature controllers over a 2-wire RS-485 bus at 19200 bit/s with a simple ASCII "
          "protocol: ':01RPV' asks controller 1 for its process value, ':01PV+021.0' is the answer.\n"
          "Only one device may drive the pair at a time. The master switches its driver on (DE high) just for its "
          "own message and then listens.",
    steps=[
        step("Select a poll from the master (:01RPV) and open the SCOPE.", sel(":01RPV"), deck(SCOPE),
             why="CH1 and CH2 show the two wires. Each swings only a few volts, in opposite directions."),
        step("Switch on MATH on the scope: B - A, the signal the receiver actually decodes.", scope("math"),
             why="Noise couples equally into both wires and cancels in the difference. A receiver decides on more than "
                 "+200 mV or less than -200 mV."),
        step("Open LOGIC and find the DE (driver enable) line of the master.", deck(LOGIC),
             why="The master enables its driver just before the first start bit and releases it after the last stop "
                 "bit. Release too late and the reply collides; too early and the last bits are cut off."),
        quiz("What are fail-safe bias resistors for?",
             ["To terminate the cable", "To hold a defined idle level when no driver is enabled", "To limit driver current", "To power the slaves"], 1,
             why="Between messages nobody drives the bus. A pull-up on one wire and a pull-down on the other, fitted at "
                 "one point, keep the difference above 200 mV so receivers see a clean idle state."),
        step("Switch on 'Fail-safe bias resistors missing' and watch the analyzer.", fault("nobias"), err("floating bus"),
             why="The idle bus now floats near 0 V. Noise is decoded as start bits: garbage characters appear between "
                 "the real messages."),
        step("Restore the bias, then set two controllers to address 02.", fault("nobias", False), fault("dup"), err("contention"),
             why="Both controllers answer ':02RPV' at the same moment. Two enabled drivers fight on the pair and the "
                 "reply is destroyed."),
        step("Clear the duplicate address.", fault("dup", False)),
        quiz("How many standard unit loads can one RS-485 driver handle?", ["2", "10", "32", "247"], 2,
             why="TIA-485 drivers handle 32 unit loads. Receivers rated 1/4 or 1/8 unit load allow 128 or 256 devices."),
    ])

# ============================================================= INDUSTRIAL
lab(id="modbus", group="ind", key="modbus_rtu", cat="INDUSTRIAL", mins=12,
    title="Modbus RTU: poll, decode and break it",
    learn=["The request / response cycle of a Modbus master and its slaves",
           "Function codes, register addresses, exceptions and the CRC",
           "Recognise a wrong address, noise and a word-order mistake"],
    brief="An HMI (the Modbus master, or client) polls a drive, a power meter and a temperature controller over RS-485 "
          "every 100 ms: function 04 (read input registers) from slaves 1 and 2, function 03 (read holding registers) "
          "from slave 3. A slave only speaks when asked. A frame ends with 3.5 character times of silence and carries "
          "a CRC-16.\n"
          "32-bit values such as the meter's voltage do not fit in a 16-bit register: they span two registers, and the "
          "order of the two halves is not standardised.",
    steps=[
        step("Select a reply from the POWER METER (slave 2).", sel("Input Registers reply", src="s2"),
             why="Registers 0-1 hold the voltage as an IEEE-754 float, 2-3 the current, 4-5 the power ... The tree "
                 "decodes each pair."),
        quiz("Registers 0 and 1 contain 0x4366 and 0x6666 = 230.4 as a float. What does a master read if it swaps the two words?",
             ["230.4 - the order doesn't matter", "About 2.7e23 - nonsense", "-230.4", "0"], 1,
             why="0x66664366 is a completely different float (about 2.7 x 10^23). Word order is the most common Modbus "
                 "integration mistake."),
        step("Inject 'Master decodes floats with the wrong word order' and read the HMI's values in its DEVICE panel.",
             fault("swap"), node("m"), side(DEVICE), var("m", "Meter V", "~", "wrong"),
             hint="Click the HMI / MASTER in the wiring view; DEVICE is the first tab on the right.",
             why="The bytes on the wire did not change - only their interpretation. An analyzer cannot see this mistake; "
                 "only a sanity check of the value can."),
        step("Clear the fault. In COMPOSE send 'Illegal function (fc 0x41)' to slave 1.", fault("swap", False), send("Illegal function"), frame("Exception 1"),
             why="The slave answers with the function code + 0x80 and exception code 1, Illegal Function. Exceptions are "
                 "valid replies with a correct CRC."),
        quiz("Which exception does a slave return for a register address that does not exist?",
             ["01 Illegal Function", "02 Illegal Data Address", "03 Illegal Data Value", "04 Server Device Failure"], 1,
             why="02 Illegal Data Address. Try it later: 'Read registers' on slave 1 from address 500."),
        step("Inject 'Master configured to poll slave 4 instead of 3' and watch the event log (DEVICE or STATS).",
             fault("wrongaddr"), event("Timeout"),
             why="No device has address 4, so nobody answers and the master's response timeout expires. A timeout means "
                 "'nobody answered': check address, baud rate, wiring and power."),
        step("Fix the address, then inject 'Electrical noise on the bus'.", fault("wrongaddr", False), fault("noise"), err("CRC"),
             why="Damaged bits make the CRC check fail. The master discards the reply and counts a CRC error - it never "
                 "uses corrupted data."),
        step("Clear the noise.", fault("noise", False)),
        quiz("At 19200 bit/s with 11-bit characters, how long is the 3.5-character silence that ends a frame?",
             ["0.18 ms", "2.0 ms", "3.5 ms", "18 ms"], 1,
             why="11 bits / 19200 = 0.57 ms per character; x 3.5 = 2.0 ms. Above 19200 bit/s the standard fixes it at 1.75 ms."),
    ])

lab(id="canopen", group="ind", key="canopen", cat="INDUSTRIAL", mins=10,
    title="CANopen: boot-up, heartbeat and SDO",
    learn=["The NMT boot-up sequence and the heartbeat",
           "COB-IDs: function code + node-ID",
           "Reading the object dictionary with SDO, and SDO aborts"],
    brief="An NMT master manages an I/O module (node 2), a servo drive (node 3) and an encoder (node 4) on a 500 kbit/s "
          "CAN bus. The 11-bit identifier is a function code plus the node-ID: 0x000 NMT, 0x080 SYNC, 0x180 + n "
          "TPDO1, 0x200 + n RPDO1, 0x580 + n SDO reply, 0x600 + n SDO request, 0x700 + n heartbeat.\n"
          "Every device has an object dictionary of numbered parameters (16-bit index, 8-bit sub-index) that SDOs read "
          "and write; PDOs carry the live process data.",
    steps=[
        step("Open FLOW and find the boot-up messages and the NMT 'Start remote node' command.", deck(FLOW),
             why="After 'Reset communication' each node sends a boot-up message. The master reads each node's device "
                 "type (0x1000) and then starts all nodes with NMT 'Start remote node'."),
        step("Select a heartbeat from node 2.", sel("Heartbeat node 2"),
             why="The heartbeat carries the NMT state: 0x05 Operational, 0x7F Pre-operational, 0x04 Stopped. Boot-up "
                 "uses the same identifier with 0x00."),
        quiz("Which COB-ID does node 3 use for its heartbeat?", ["0x083", "0x183", "0x583", "0x703"], 3,
             why="0x700 + node-ID = 0x703."),
        step("COMPOSE 'SDO upload (read)' of index 0x1008 (device name) from the servo drive.", send("SDO upload"), frame("SDO upload res 0x1008", src="drv"),
             why="The master sends 0x40 + index + sub-index to 0x603; the drive answers on 0x583 with the data. Index and "
                 "data are little-endian."),
        step("Pull the encoder's heartbeat (fault) and wait for the master to react.", fault("hb"), event("Heartbeat timeout"),
             why="The master expects node 4's heartbeat within its consumer time. When it is missing, the master raises a "
                 "heartbeat event - the application then stops the machine safely."),
        step("Restore the heartbeat.", fault("hb", False)),
        quiz("Which service carries fast cyclic process data with no request and no confirmation?", ["SDO", "PDO", "NMT", "EMCY"], 1,
             why="PDOs carry up to 8 bytes of mapped process data, triggered by SYNC or by events. SDOs are confirmed "
                 "and meant for configuration."),
        step("COMPOSE 'SDO upload (read)' of index 0x2FFF from the drive - an object that does not exist.", send("SDO upload"), frame("SDO ABORT 0x06020000"),
             auto={"set": {"idx": 0x2FFF}},
             hint="Change the Index parameter to 0x2FFF before sending.",
             why="Abort code 0x06020000: object does not exist in the object dictionary. SDO aborts are CANopen's error "
                 "replies, like Modbus exceptions."),
    ])

lab(id="hart", group="ind", key="hart", cat="INDUSTRIAL", mins=8,
    title="HART: digital talk on a 4-20 mA loop",
    learn=["How HART adds FSK on top of the analogue loop current",
           "Read the dynamic variables from a command 3 reply",
           "Why the 250 ohm resistor matters, and the fixed-current trap"],
    brief="A pressure transmitter, PT-101 (range 0-10 bar), sends its measurement to the DCS as a 4-20 mA current. "
          "HART adds a +/-0.5 mA frequency-shift-keyed signal on top at 1200 bit/s (1200 Hz = 1, 2200 Hz = 0). Its "
          "average is zero, so the analogue value is not disturbed.\n"
          "The DCS asks for command 3 every second; a handheld communicator can join the same loop as a second master.",
    steps=[
        step("Select a 'cmd 3 reply' from PT-101 and read the dynamic variables in the tree.", sel("cmd 3 reply"),
             why="Command 3 returns the loop current and up to four dynamic variables (PV, SV, TV, QV), each a unit code "
                 "plus an IEEE-754 float, with two status bytes in front."),
        step("Open the SCOPE on the LOOP probe point and press AUTOSET.", deck(SCOPE), probe("LOOP"),
             why="The DC level is the analogue signal; the HART FSK rides on top as a small sine burst while a message "
                 "is sent."),
        quiz("The range is 0-10 bar and the loop current is 12 mA. What pressure does the analogue signal represent?",
             ["4.0 bar", "5.0 bar", "6.0 bar", "7.5 bar"], 1,
             why="(12 - 4) / 16 x 10 bar = 5.0 bar. The 'live zero' at 4 mA lets the receiver tell 0 % from a broken "
                 "wire (0 mA)."),
        step("Remove the 250 ohm resistor (fault).", fault("res"), err("250"),
             why="HART devices signal by modulating current; the receiver sees current x loop resistance. Without at "
                 "least 230 ohm there is no voltage to detect - but the 4-20 mA signal still works."),
        step("Put the resistor back and wait for a good reply.", fault("res", False), frame("cmd 3 reply")),
        step("Inject 'Transmitter left in fixed-current mode' and compare the DCS readings in its DEVICE panel.",
             fault("fixed"), node("dcs"), var("dcs", "Analogue reading", "~", "12.00 mA"),
             why="In fixed-current (loop test) mode the output is held at a set value. The digital PV still tells the "
                 "truth, the analogue value does not - a classic commissioning leftover."),
        quiz("Which field device status bit warns the master about this?",
             ["Primary variable out of limits", "Loop current fixed", "Configuration changed", "Cold start"], 1,
             why="Bit 0x08, 'loop current fixed'. The transmitter's status now reads 0x08."),
        step("Clear the fault.", fault("fixed", False)),
    ])

# ============================================================= AUTOMOTIVE
lab(id="obd", group="auto", key="obd2", cat="AUTOMOTIVE", mins=10,
    title="OBD-II: live data, a misfire and the MIL",
    learn=["Request live data (mode 01) and decode it",
           "Pending and confirmed trouble codes and the check-engine lamp (MIL)",
           "What clearing codes does - and does not do"],
    brief="A scan tool on the J1962 connector talks to the engine (ECM, reply ID 0x7E8) and transmission (TCM, 0x7E9) "
          "over CAN at 500 kbit/s. Requests go to the functional address 0x7DF, so every emissions-related ECU may "
          "answer. A request is a mode (service) and a PID; the reply adds 0x40 to the mode.",
    steps=[
        step("Select an ECM reply to mode 01 PID 0C (engine speed).", sel("PID 0C:", src="ecm"),
             why="The reply is 41 0C A B: mode 01 + 0x40, the PID, then two data bytes."),
        quiz("The ECM answers 41 0C 0D 48. What is the engine speed?", ["3400 rpm", "850 rpm", "13.72 rpm", "1700 rpm"], 1,
             why="RPM = (256 x A + B) / 4 = (256 x 13 + 72) / 4 = 850 rpm."),
        step("Inject 'Cylinder 1 misfire', then COMPOSE 'Mode 07 pending DTCs'.", fault("misfire"), send("Mode 07"), frame("Pending DTCs: P0300"),
             why="The misfire monitor fails and stores a pending code at once. If it keeps failing, the code is confirmed."),
        step("Wait a few seconds, then COMPOSE 'Mode 03 stored DTCs'.", send("Mode 03"), frame("Stored DTCs: P030"),
             hint="If the reply still says 'none', the code is not confirmed yet - wait and send again.",
             why="P0300 = random / multiple misfire, P0301 = cylinder 1. P = powertrain, the 0 after it = a generic SAE code."),
        step("Select the ECM and look at its DEVICE panel: the MIL is on.", node("ecm"), var("ecm", "MIL", "~", "ON"),
             why="A confirmed emissions fault switches on the malfunction indicator lamp (check engine)."),
        step("COMPOSE 'Mode 04 clear DTCs'.", send("Mode 04"), frame("cleared", src="ecm"),
             why="Mode 04 erases codes and freeze frames and resets the readiness monitors. It repairs nothing."),
        quiz("The misfire is still there. What happens next?",
             ["The codes stay cleared", "The monitor fails again and the codes come back", "The engine will not start", "Mode 04 is refused while a fault exists"], 1,
             why="The monitor runs again: pending code, confirmed code, MIL. Readiness monitors showing 'not complete' "
                 "give away a recent clear."),
        step("COMPOSE 'Mode 09 PID 02 VIN': 17 characters do not fit one CAN frame.", send("Mode 09"), frame("VIN", src="ecm"), frame("Flow Control"),
             why="ISO-TP: the ECM sends a First Frame, the tool answers with Flow Control, then Consecutive Frames follow."),
    ])

lab(id="uds", group="auto", key="uds", cat="AUTOMOTIVE", mins=12,
    title="UDS: sessions, SecurityAccess and negative responses",
    learn=["Positive and negative responses (NRCs)",
           "Diagnostic sessions and why some services need one",
           "The seed / key exchange of SecurityAccess"],
    brief="A diagnostic tester talks UDS (ISO 14229) to the engine ECU over CAN: requests on 0x7E0, replies on 0x7E8, "
          "segmented by ISO-TP when longer than 7 bytes. A positive reply adds 0x40 to the service ID; a negative reply "
          "is 0x7F + service + a negative response code (NRC).\n"
          "Writing data is protected: it needs the extended session and an unlocked security level. The ECU sends a "
          "random seed; the tester must answer with the matching key.",
    steps=[
        step("COMPOSE 'ReadDataByIdentifier (0x22)' with DID 0xF190 (VIN).", send("ReadDataByIdentifier"), frame("DID 0xF190"), frame("Flow Control"),
             why="The 17-character VIN needs a multi-frame ISO-TP reply: First Frame, Flow Control from the tester, "
                 "Consecutive Frames."),
        quiz("What is the first byte of the positive reply to service 0x22?", ["0x22", "0x62", "0x7F", "0xA2"], 1,
             why="Positive reply = service ID + 0x40 = 0x62, followed by the DID and the data."),
        step("COMPOSE 'WriteDataByIdentifier 0x0123' in the default session.", send("WriteDataByIdentifier"), frame("NRC 0x7F"),
             why="NRC 0x7F serviceNotSupportedInActiveSession: the service exists, but not in the default session."),
        step("COMPOSE 'DiagnosticSessionControl (0x10)' for the extended session (03).", send("DiagnosticSessionControl"), frame("Session extended"),
             why="The reply carries the P2 and P2* timing. The tester keeps the session alive with TesterPresent; after "
                 "5 s of silence (S3) the ECU falls back to the default session."),
        step("COMPOSE 'SecurityAccess requestSeed (0x27 01)'.", send("requestSeed"), frame("Seed 0x"),
             why="The ECU answers with a random 2-byte seed."),
        step("Select the ENGINE ECM and read 'Last seed -> correct key' in its DEVICE panel.", node("ecm"), side(DEVICE),
             why="In a real ECU the key algorithm is the manufacturer's secret. Here the panel shows the result so you can "
                 "type it in."),
        step("COMPOSE 'SecurityAccess sendKey (0x27 02)' with that key.", send("sendKey"), frame("Security access granted"),
             auto={"set": {"k": "uds_key"}},
             hint="Set the Key parameter to the value shown in the ECM's panel. A wrong key costs the seed - request a new one.",
             why="Three wrong keys and the ECU locks the service for a time delay (NRC 0x36, then 0x37)."),
        step("COMPOSE 'WriteDataByIdentifier 0x0123' again.", send("WriteDataByIdentifier"), frame("accepted"),
             why="Extended session + unlocked = the write is accepted (positive reply 0x6E)."),
        quiz("An ECU replies 7F 31 78. What does it mean?",
             ["Service not supported", "Request received, response pending - wait", "Security access denied", "Wrong message length"], 1,
             why="NRC 0x78 requestCorrectlyReceived-ResponsePending: the ECU needs more time (P2* applies) and will "
                 "send the real answer later."),
    ])

lab(id="j1939", group="auto", key="j1939", cat="AUTOMOTIVE", mins=12,
    title="J1939: PGNs, SPNs, diagnostics and address claim",
    learn=["How a 29-bit identifier carries priority, PGN and source address",
           "Requests and the BAM transport protocol for long messages",
           "Active diagnostic codes (DM1) and address-claim conflicts"],
    brief="Six ECUs and a service tool share a 250 kbit/s J1939 bus. Each message is a parameter group (PGN) that "
          "carries signals (SPNs), for example EEC1 (PGN 61444) with the engine speed (SPN 190). The 29-bit identifier "
          "holds a 3-bit priority, the PGN and the 8-bit source address of the sender.\n"
          "Messages longer than 8 bytes use the transport protocol: a BAM announcement followed by data packets.",
    steps=[
        step("Select an EEC1 frame from the engine.", sel("EEC1"),
             why="EEC1 is sent every 10-20 ms at priority 3. SPN 190 engine speed is bytes 4-5: 0.125 rpm per bit."),
        quiz("EEC1 is sent with the identifier 0x0CF00400. Which source address sent it?", ["0x0C", "0xF0", "0x04", "0x00"], 3,
             why="The last byte is the source address: 0x00, engine #1. 0x0C >> 2 = priority 3, and 0xF004 = PGN 61444."),
        step("Select the ENGINE ECM, open DEVICE and turn the THROTTLE above 50 %. Watch the engine speed follow.",
             node("ecm"), var("ecm", "Throttle %", ">", 50), var("ecm", "RPM", ">", 1300),
             auto={"vars": {("ecm", "Throttle %"): 60.0}},
             why="EEC1 and the fuel rate (LFE1) follow at once; the instrument cluster reads them from the bus."),
        step("COMPOSE 'Request PGN (59904)' for PGN 65260 (vehicle identification).", send("Request PGN"), frame("TP.CM BAM"), frame("TP.DT"),
             why="The VIN is longer than 8 bytes, so the engine announces it with TP.CM BAM (size, packets, PGN) and sends "
                 "the bytes in TP.DT packets 50-200 ms apart."),
        step("Inject 'Engine coolant overheating' and wait for the diagnostic message to change.", fault("hot"), frame("BAM: DM1"),
             hint="The coolant warms up gradually; the code becomes active at about 110 C.",
             why="DM1 lists the active trouble codes (SPN + failure mode) and the lamp status. With a code inside it "
                 "grows beyond 8 bytes and needs the transport protocol too."),
        step("Look at the INSTRUMENT CLUSTER's DEVICE panel: the warning lamps.", node("ic"), var("ic", "Lamps", "~", "RED"),
             why="The lamp bits in DM1 drive the dashboard: red stop lamp, amber warning lamp, MIL, protect lamp."),
        step("Clear the overheat, then switch on the address conflict.", fault("hot", False), fault("conflict"), frame("Cannot Claim Address"),
             why="Both ECUs claim 0x00 with their 64-bit NAME. The lower NAME wins; the loser has no other address it can "
                 "use and announces 'Cannot Claim Address' from the null address 254."),
        step("Clear the conflict.", fault("conflict", False)),
    ])

lab(id="lin", group="auto", key="lin", cat="AUTOMOTIVE", mins=8,
    title="LIN: header, response and checksum",
    learn=["Break, sync and protected identifier: the master's header",
           "Who fills the response: master or slave",
           "Classic and enhanced checksums, sleep and wake-up"],
    brief="A body controller (the LIN master) runs a schedule of 10 ms slots on a single-wire 19.2 kbit/s bus with a "
          "window lift, a mirror and a rain/light sensor. In every slot the master sends a header; the one node that "
          "publishes that frame ID fills in the response: data bytes and a checksum.",
    steps=[
        step("Select a 'Window_Status' frame and open LOGIC.", sel("Window_Status"), deck(LOGIC),
             why="Break (at least 13 dominant bits), sync byte, protected ID, then the window lift's data and checksum."),
        quiz("What is the value of the sync byte that follows the break?", ["0x00", "0x55", "0xAA", "0xFF"], 1,
             why="0x55 = 01010101: alternating bits, so slaves with cheap RC oscillators can measure the bit time and "
                 "synchronise."),
        quiz("Window_Status comes from the window lift. Who sends its header?", ["The window lift", "The master", "Any node", "Nobody - LIN has no headers"], 1,
             why="The master sends every header. The slave that publishes the frame answers with the response."),
        step("Switch the rain sensor to the classic checksum (fault).", fault("cks"), err("classic checksum"),
             why="LIN 2.x uses the enhanced checksum over the protected ID + data; LIN 1.x used the classic checksum over "
                 "the data only. Mixing them makes every frame fail its check."),
        step("Fix it, then make the window lift stop responding.", fault("cks", False), fault("noresp"), err("No response"),
             why="The header goes out but the response slot stays empty - the master records a 'no response' error."),
        step("Clear the fault and COMPOSE 'Go to sleep'.", fault("noresp", False), send("Go to sleep"), frame("GO TO SLEEP"),
             why="A master request frame (ID 0x3C) with first data byte 0x00 tells all slaves to sleep. The bus falls silent."),
        step("COMPOSE 'Wake up'.", send("Wake up"), frame("Wake-up pulse"),
             why="Any node can wake the bus with a dominant pulse of 250 us - 5 ms; the master then resumes the schedule."),
    ])

# ================================================================= MARINE
lab(id="nmea0183", group="marine", key="nmea0183", cat="MARINE", mins=10,
    title="NMEA 0183: talkers, sentences and checksums",
    learn=["Read a sentence: talker ID, formatter, fields and checksum",
           "One talker, many listeners - and why boats need multiplexers",
           "Recognise polarity and two-talker wiring mistakes"],
    brief="A GPS, a depth sounder and a wind instrument each talk on their own RS-422 pair at 4800 baud. NMEA 0183 "
          "allows one talker and several listeners per pair, so a multiplexer combines the streams into one 38400 baud "
          "output for the chartplotter.\n"
          "A sentence is plain ASCII: $, a two-letter talker ID, a three-letter formatter, comma-separated fields, * "
          "and a two-digit hexadecimal checksum, ended by CR LF.",
    steps=[
        step("Select a $GPRMC sentence from the GPS and read its fields.", sel("$GPRMC"),
             why="RMC, recommended minimum: UTC time, status (A = valid), position, speed and course over ground, date "
                 "and magnetic variation."),
        quiz("In $SDDBT,46.4,f,14.2,M,7.7,F*07 - who is the talker?", ["SD, a depth sounder", "DB, a depth sensor", "DBT, the transducer", "F, a fathometer"], 0,
             why="The two letters after $ are the talker (GP GPS, SD sounder, WI weather instrument, II integrated "
                 "instrumentation). DBT = Depth Below Transducer in feet, metres and fathoms."),
        quiz("How is the checksum after * computed?",
             ["Sum of all bytes modulo 256", "XOR of all characters between $ and *", "CRC-16 of the line", "Number of fields in hex"], 1,
             why="An 8-bit XOR of the characters between $ and *, written as two hex digits."),
        step("Select a sentence forwarded by the multiplexer ('(mux)') and compare its duration with the original.", sel("(mux)"),
             why="Same characters, eight times faster: the 38400 baud output carries the combined traffic of several "
                 "4800 baud talkers."),
        step("COMPOSE 'Sentence with a wrong checksum' from the laptop.", send("wrong checksum"), err("Checksum mismatch"),
             why="The multiplexer recalculates the XOR, finds a mismatch and drops the sentence."),
        step("Inject 'Depth sounder wired with A and B swapped'.", fault("polarity"), err("polarity"),
             why="Swapping A and B inverts every bit: the idle line looks like a long start bit and nothing decodes."),
        step("Fix the wiring, then parallel the wind and depth outputs on one input.", fault("polarity", False), fault("twotalk"), err("Collision"),
             why="NMEA 0183 has no bus arbitration. Two talkers on one pair drive against each other and corrupt each "
                 "other's sentences. That is what multiplexers are for."),
        step("Clear the fault.", fault("twotalk", False)),
    ])

lab(id="n2k", group="marine", key="nmea2000", cat="MARINE", mins=10,
    title="NMEA 2000: PGNs, fast packets and the power budget",
    learn=["Address claiming with the 64-bit NAME",
           "Single-frame and fast-packet PGNs",
           "ISO Request, and why the power tee position matters"],
    brief="A chartplotter, GNSS antenna, depth/speed/temperature transducer, heading and wind sensors, two engine "
          "gateways and a battery monitor share a 250 kbit/s CAN backbone (based on ISO 11783 / J1939) with Micro-C "
          "drop cables. The backbone also carries 12 V; each device's draw is rated in LEN (1 LEN = 50 mA).",
    steps=[
        step("Select an ISO Address Claim (PGN 60928).", sel("Address Claim"),
             why="At power-up each device claims a source address by broadcasting its 64-bit NAME: manufacturer, device "
                 "class and function, instance. If two want the same address, the lower NAME wins."),
        step("Select a Vessel Heading message (PGN 127250).", sel("Heading"),
             why="Single 8-byte frame, 10 times a second: SID, heading, deviation, variation, reference."),
        quiz("The heading field holds 8378 in units of 0.0001 rad. What is the heading?", ["8.4 deg", "48.0 deg", "83.8 deg", "0.84 deg"], 1,
             why="8378 x 0.0001 rad = 0.8378 rad = 48.0 deg."),
        step("Select one frame of a GNSS Position Data fast packet (PGN 129029).", sel("GNSS position"),
             why="PGN 129029 is 43 bytes: fast packet splits it into 7 frames. The first byte of each frame holds a "
                 "sequence counter and a frame counter; frame 0 also carries the total length."),
        quiz("How many payload bytes does the FIRST frame of a fast packet carry?", ["8", "7", "6", "5"], 2,
             why="Frame 0: counters, length, 6 bytes. Later frames: counters + 7 bytes. 6 + 6 x 7 = 48 >= 43, so 7 frames."),
        step("COMPOSE an 'ISO Request (59904)' for Product Information (126996) to the depth transducer.", send("ISO Request"), frame("Product Information", src="dst"),
             why="ISO Request asks one device for a PGN it does not send by itself. Product Information (model, software "
                 "version, LEN) is a fast packet as well."),
        step("Move the power tee to one end of the long backbone (fault).", fault("power"), event("browns out"),
             why="Current through the backbone resistance drops the voltage along the cable; the device furthest from "
                 "the tee falls below 9 V and resets. Feed power near the middle."),
        step("Clear the fault.", fault("power", False)),
        quiz("What do you measure between NET-H and NET-L on a correctly terminated, unpowered backbone?", ["0 ohm", "60 ohm", "120 ohm", "240 ohm"], 1,
             why="Two 120 ohm terminators in parallel = 60 ohm. 120 ohm means one is missing."),
    ])

lab(id="ais", group="marine", key="ais", cat="MARINE", mins=8,
    title="AIS: who is out there?",
    learn=["Position and static reports from Class A and Class B transponders",
           "Why reporting intervals depend on speed",
           "Interrogations, safety messages and the hidden-station problem"],
    brief="Own ship (with ECDIS) sees a tanker, a fast ferry, a fishing vessel, a sailing yacht (Class B), a shore "
          "base station and an AIS buoy. AIS uses two VHF channels (161.975 and 162.025 MHz) at 9600 bit/s GMSK. "
          "Each minute has 2250 slots per channel; Class A stations reserve their future slots (SOTDMA).",
    steps=[
        step("Select a position report (message 1) from the ferry PRIDE OF SOLENT.", sel("Position report: PRIDE"),
             why="Message 1: MMSI, navigational status, rate of turn, SOG, position, COG, heading, time stamp and the "
                 "SOTDMA communication state."),
        quiz("Why does the ferry report every 6 s but the tanker every 10 s?",
             ["The ferry's transmitter is stronger", "The interval depends on speed and course changes", "The ferry is closer to the shore", "Class B ships report faster"], 1,
             why="Class A: 0-14 kn every 10 s, 14-23 kn every 6 s, faster or turning more often; at anchor every 3 min. "
                 "Faster ships move further between reports."),
        step("Open STATS and compare the reporting intervals.", deck(STATS)),
        step("COMPOSE a 'Safety broadcast (msg 14)'.", send("Safety"), frame("Safety broadcast"),
             why="Message 14 carries free text in 6-bit ASCII to every station in range."),
        step("COMPOSE 'Interrogate tanker for static data (msg 15)' and find its answer.", send("Interrogate"), frame("Static and voyage data: NORDIC STAR", dst="own"),
             why="Message 15 asks one MMSI for one message type; the tanker answers with message 5: name, call sign, "
                 "dimensions, ship type, destination, ETA and draught."),
        step("Inject 'Hidden stations pick the same slot'.", fault("hidden"), err("collision"),
             why="The yacht and the fishing boat cannot hear each other, so both pick the same free slot. Own ship hears "
                 "both at once and decodes neither."),
        step("Clear the fault.", fault("hidden", False)),
    ])

# ============================================================= AEROSPACE
lab(id="a429", group="aero", key="a429", cat="AEROSPACE", mins=10,
    title="ARINC 429: labels, SSM and BNR",
    learn=["The 32-bit word: label, SDI, data, SSM and parity",
           "Bipolar return-to-zero signalling",
           "Why parity does not catch a swapped pair"],
    brief="ADIRU 1 broadcasts air data and inertial data to the FMS, the EFIS and the autopilot on one twisted pair "
          "at 100 kbit/s. ARINC 429 is simplex: one transmitter, up to 20 receivers.\n"
          "Each 32-bit word: an 8-bit label (written in octal), a 2-bit source/destination identifier, 19 data bits, a "
          "2-bit sign/status matrix (SSM) and odd parity.",
    steps=[
        step("Select label 203 (pressure altitude).", sel("203 Pressure altitude"),
             why="Label 203 carries pressure altitude as BNR (two's-complement binary). The tree shows each field."),
        step("Open the SCOPE.", deck(SCOPE),
             why="+10 V for a 1, -10 V for a 0, back to 0 V in the middle of every bit: bipolar return-to-zero is "
                 "self-clocking. At least 4 bit times of NULL separate the words."),
        quiz("Label 203 (octal) is 10 000 011 in binary. In what order do its bits go on the wire?",
             ["Most significant bit first: 1 0 0 0 0 0 1 1", "Least significant bit first: 1 1 0 0 0 0 0 1", "After the data field", "The label is not transmitted"], 0,
             why="The label goes out MSB first, the rest of the word LSB first. Raw-word dumps therefore often show the "
                 "label 'reversed'."),
        step("Inject 'Air data module failure' and look at the SSM of label 203.", fault("ssm"), frame("SSM failure warning"),
             why="For BNR data, SSM 11 = normal operation, 00 = failure warning, 01 = no computed data, 10 = functional "
                 "test. The words still arrive - receivers must not use them."),
        step("Select the EFIS and look at its DEVICE panel.", node("efis"), var("efis", "Altitude", "~", "FAIL"),
             why="The display replaces the value with a FAIL flag instead of showing a wrong altitude."),
        step("Clear the failure, then swap A and B at the EFIS input.", fault("ssm", False), fault("swap"), node("efis"), var("efis", "Status", "~", "instead of"),
             why="Swapping the wires inverts all 32 bits. Label 203 (10000011) becomes 01111100 = 174 octal - a label the "
                 "EFIS does not use for altitude."),
        quiz("Why does the odd parity bit not catch the swapped wires?",
             ["Only the transmitter checks parity", "Inverting all 32 bits leaves an odd number of ones", "The EFIS ignores parity", "Parity only covers the label"], 1,
             why="A word with n ones (n odd) has 32 - n ones after inversion - still odd. Parity catches an odd number of "
                 "flipped bits, never all 32."),
        step("Restore the wiring.", fault("swap", False)),
    ])

lab(id="m1553", group="aero", key="m1553", cat="AEROSPACE", mins=10,
    title="MIL-STD-1553: command, response and bus redundancy",
    learn=["Command, data and status words",
           "BC-to-RT and RT-to-BC transfers, and mode codes",
           "How the bus controller handles a silent terminal"],
    brief="The mission computer is the bus controller (BC). An INS, an air data computer, a display processor and a "
          "radar altimeter are remote terminals (RT 1-4) on a dual-redundant 1 Mbit/s bus. Nothing is sent unless the "
          "BC commands it. Every word is 20 bit times: a 3-bit sync, 16 data bits (Manchester II bi-phase) and odd parity.",
    steps=[
        step("Select a BC->RT transfer to the display processor (RT 3).", sel("BC->RT 3"),
             why="Receive command (RT address, T/R = 0, subaddress, word count), the data words, then the RT's status "
                 "word 4-12 us later."),
        step("Select an RT->BC transfer from the INS (RT 1).", sel("RT 1->BC"),
             why="Transmit command (T/R = 1); the RT answers with its status word and then the data words."),
        step("Open LOGIC and compare the sync of a command word with that of a data word.", deck(LOGIC),
             why="Command and status words start with a positive-then-negative sync, data words with the opposite. "
                 "That is how a receiver tells them apart."),
        quiz("A command word has a word count field of 00000. How many data words follow?", ["0", "1", "31", "32"], 3,
             why="0 means 32. In a mode code (subaddress 0 or 31) the same field holds the mode code number."),
        step("Make the air data computer (RT 2) stop responding.", fault("rt_dead"), err("No response"), frame("bus B"),
             why="No status word within the timeout (about 14 us): the BC retries the message on the other bus. If that "
                 "fails as well, it marks the RT as failed."),
        step("Look at the bus controller's DEVICE panel.", node("bc"), var("bc", "Failed RTs", "~", "RT 2")),
        step("Restore RT 2 and COMPOSE 'Mode code to an RT' (mode code 2, transmit status word).", fault("rt_dead", False), send("Mode code"), frame("Mode code 2"),
             why="Mode code 2 makes the RT send its last status word - a cheap health check."),
        quiz("Which status word bit tells the BC that the RT could not handle the message right now?",
             ["Message error", "Busy", "Service request", "Terminal flag"], 1,
             why="Busy. Message error = the last message was invalid, service request = the RT wants attention, terminal "
                 "flag = an internal fault."),
    ])

lab(id="adsb", group="aero", key="adsb", cat="AEROSPACE", mins=8,
    title="ADS-B: decoding extended squitters",
    learn=["The 112-bit DF17 message: ICAO address, type code, payload, parity",
           "Airborne position (CPR), identification and the PPM waveform",
           "What a ground station sees when an aircraft loses GNSS"],
    brief="Five aircraft broadcast ADS-B Out on 1090 MHz. An extended squitter is 112 bits with pulse-position "
          "modulation at 1 Mbit/s after an 8 us preamble: downlink format 17, the 24-bit ICAO address, a 56-bit message "
          "and a 24-bit parity field. Positions use Compact Position Reporting (CPR).",
    steps=[
        step("Select an airborne position message.", sel("Airborne position"),
             why="Type codes 9-18: barometric altitude plus a CPR-encoded latitude and longitude (17 bits each), and an "
                 "even / odd flag."),
        quiz("Why do aircraft alternate between even and odd position messages?",
             ["To save power", "One alone is ambiguous; an even + odd pair gives the global position", "Even is airborne, odd is surface", "To share the channel with Mode S"], 1,
             why="CPR encodes the position within a zone. A recent even + odd pair resolves the zone anywhere on Earth; "
                 "with a known reference position, one message is enough."),
        step("Select an identification message.", sel("Identification"),
             why="Type codes 1-4: the aircraft category and an 8-character call sign, 6 bits per character."),
        step("Open the SCOPE: the preamble, then the data bits.", deck(SCOPE),
             why="Preamble pulses at 0, 1, 3.5 and 4.5 us; then every bit is 1 us long with the pulse in the first or "
                 "the second half."),
        quiz("A pulse in the FIRST half of the 1 us bit period means:", ["0", "1", "end of message", "parity error"], 1,
             why="Pulse-position modulation: first half = 1, second half = 0."),
        step("COMPOSE 'Encode airborne position' and find your message.", send("Encode airborne"), frame("(composed)"),
             why="The composer encodes the altitude and the CPR position, computes the 24-bit parity and transmits it."),
        step("Make aircraft 3 lose GNSS.", fault("gps"), frame("NO GNSS"),
             why="Without a position source the aircraft sends type code 0 (no position) with altitude only."),
        step("Select GROUND STATION 1: it now tracks one aircraft less.", node("gs1"), var("gs1", "Tracks", "<", 5)),
    ])

# ========================================================== POWER / BLDG
lab(id="dnp3", group="power", key="dnp3", cat="POWER/BLDG", mins=10,
    title="DNP3: polls, events and select-before-operate",
    learn=["Integrity and event polls; static data and event classes",
           "Internal indications (IIN) after a restart",
           "Select-before-operate controls and unsolicited responses"],
    brief="A SCADA master talks DNP3 over TCP port 20000 to a substation RTU (address 10) and a pole-top recloser "
          "(address 20). Class 0 is the current value of every point; classes 1-3 are time-stamped events by priority. "
          "The master reads everything once (integrity poll) and then only the events, every 2 seconds. The recloser "
          "may also report on its own (unsolicited).",
    steps=[
        step("Select the RTU's first RESPONSE with static data and read its IIN flags.", sel("static data", src="rtu"),
             why="After a restart the outstation sets IIN1.7 DEVICE_RESTART and IIN1.4 NEED_TIME."),
        step("Select the master's WRITE that clears DEVICE_RESTART.", sel("WRITE g80v1"),
             why="Writing 0 to group 80 variation 1, index 7 clears the restart flag; the master then sets the clock."),
        quiz("What does a class 0 poll return?",
             ["The events since the last poll", "The current value of all static points", "The restart counter", "Nothing"], 1,
             why="Class 0 = static data. Classes 1, 2 and 3 = buffered events, in priority order."),
        step("COMPOSE 'Control: select before operate' to trip CB1 on the RTU.", send("select before operate"),
             frame("SELECT TRIP CB1"), frame("OPERATE TRIP CB1"), event("CB1 OPENED"),
             why="SELECT arms the control and the RTU echoes it. Only an identical OPERATE within the select timeout "
                 "trips the breaker - a single corrupted message cannot operate plant."),
        step("Watch the next event poll report the breaker change.", frame("BI + ", src="rtu"),
             why="The status change is a class event with a time stamp: the master learns exactly when it happened."),
        step("Inject 'Permanent fault on the recloser's feeder'.", fault("feeder"), frame("UNSOLICITED_RESPONSE"), frame("CONFIRM unsolicited"),
             why="The recloser trips, recloses, trips again - and reports each change without waiting for a poll. The "
                 "master confirms every unsolicited response."),
        step("Read the recloser state in the master's DEVICE panel.", node("m"), var("m", "Recloser", "~", "LOCKOUT"),
             why="After its reclose attempts fail the recloser locks out; a crew must find the fault."),
        step("Clear the fault.", fault("feeder", False)),
    ])

lab(id="goose", group="power", key="iec61850", cat="POWER/BLDG", mins=10,
    title="IEC 61850: a GOOSE trip",
    learn=["GOOSE publishing: stNum, sqNum and the retransmission burst",
           "How the bay controller acts on a trip",
           "MMS control and GOOSE supervision"],
    brief="A feeder protection IED, a bay controller and a merging unit share the station bus with the HMI. The merging "
          "unit streams the currents as Sampled Values (shown 1 in 200). The protection IED publishes its trip as a "
          "GOOSE message: a layer-2 multicast repeated as a heartbeat. When the value changes, stNum increases and the "
          "message is repeated in a fast burst. The bay controller subscribes and operates the breaker.",
    steps=[
        step("Select a GOOSE heartbeat from the protection IED (FDR1_TRIP).", sel("FDR1_TRIP"),
             why="gocbRef, dataset, goID, timeAllowedtoLive, stNum (state number), sqNum (repeat counter), confRev and the "
                 "values. Between changes only sqNum counts up."),
        quiz("What happens to stNum and sqNum when the trip value changes?",
             ["Both reset to 0", "stNum + 1, sqNum starts again at 0", "sqNum + 1, stNum unchanged", "Nothing"], 1,
             why="Subscribers detect a new state from stNum; sqNum counts the repetitions of that state."),
        step("Inject 'Short circuit on feeder 1' and find the trip GOOSE.", fault("fault"), frame("trip = TRUE"), event("opening breaker"),
             why="Overcurrent - the protection operates and publishes the trip at once, repeated after 2, 4, 8 ms ... "
                 "back to the heartbeat rate. The bay controller opens the breaker."),
        step("Clear the fault. The breaker stays open until someone closes it.", fault("fault", False)),
        step("COMPOSE 'Operate breaker (MMS SBOw + Oper)' to close it.", send("Operate breaker"), frame("SBOw"), frame("Pos = on"),
             why="Select-before-operate with value (SBOw), then Oper. The bay controller reports the new position in an "
                 "MMS InformationReport and publishes a new GOOSE state."),
        quiz("Why is GOOSE a layer-2 multicast instead of a TCP message?",
             ["Easier encryption", "Speed: no connection and no handshake, delivery in milliseconds", "TCP cannot carry binary data", "It works without switches"], 1,
             why="A trip must arrive in a few milliseconds. Reliability comes from repetition instead of acknowledgement."),
        step("Pull the protection IED's Ethernet link.", fault("link"), node("bcu"), var("bcu", "GOOSE from protection", "~", "ALARM"),
             why="Each GOOSE carries timeAllowedtoLive. When nothing arrives within it the subscriber declares the "
                 "publisher lost - a protection-critical alarm."),
        step("Restore the link.", fault("link", False)),
    ])

lab(id="bacnet", group="power", key="bacnet", cat="POWER/BLDG", mins=12,
    title="BACnet: priorities and the forgotten override",
    learn=["Device discovery with Who-Is / I-Am",
           "ReadProperty, WriteProperty and the 16-level priority array",
           "Find and remove a forgotten operator override"],
    brief="An operator workstation, an AHU controller, a boiler-plant controller and a router to an MS/TP field bus share "
          "a BACnet/IP network (UDP 47808). Every device holds objects (analog-input, binary-output, schedule ...) with "
          "properties (present-value, units, priority-array ...).\n"
          "A commandable object keeps 16 priority slots; the highest-priority (lowest-numbered) slot that is not NULL "
          "wins. The AHU's own schedule writes at priority 16 - every 15 s here, alternating day and night.",
    steps=[
        step("Select an I-Am reply.", sel("i-Am"),
             why="I-Am carries the device instance, max APDU length, segmentation support and vendor ID."),
        step("COMPOSE a 'ReadProperty' of present-value of analog-input,1 on the AHU.", send("ReadProperty"), frame("ComplexACK readProperty analog-input,1"),
             why="The ComplexACK returns the object, the property, then the value between opening and closing tags."),
        step("Inject 'Operator override left at priority 8' and wait for the night schedule.", fault("prio"), event("OFF (unoccupied)"),
             hint="The schedule switches every 15 seconds of simulated time.",
             why="The schedule writes OFF at priority 16 - but the manual ON at priority 8 wins."),
        step("Select the AHU: the fan is still running.", node("ahu"), var("ahu", "Supply fan", "~", "priority 8")),
        step("COMPOSE a 'ReadProperty' of priority-array (87) on binary-output,1.", send("ReadProperty"), frame("priority-array ="),
             auto={"set": {"o": (4, 1), "p": 87}},
             hint="Object: binary-output,1. Property: 87 priority-array.",
             why="Slot 8 holds 'active' (the operator), slot 16 the schedule. Present-value follows the highest-priority "
                 "slot that is not NULL."),
        quiz("How do you remove the override?",
             ["Write OFF at priority 16", "Write NULL at priority 8 (relinquish)", "Reboot the controller", "Write OFF at priority 1"], 1,
             why="Writing NULL empties the slot. Writing OFF at priority 8 would just be a new override."),
        step("COMPOSE 'Relinquish (write NULL)' at priority 8 on binary-output,1.", send("Relinquish"), frame("NULL (relinquish)"),
             var("ahu", "Supply fan", "!~", "priority 8"),
             why="With slot 8 empty, the schedule at priority 16 is in charge again."),
        quiz("Which priority is reserved for manual life safety?", ["1", "8", "10", "16"], 0,
             why="1 manual life safety, 2 automatic life safety, 5 critical equipment control, 6 minimum on/off, "
                 "8 manual operator, 16 lowest (schedules)."),
    ])

lab(id="meters", group="power", key="modbus_power", cat="POWER/BLDG", mins=8,
    title="Modbus meters: the off-by-one register",
    learn=["Register numbers in manuals versus addresses on the wire",
           "Floats and 64-bit counters spread over several registers",
           "Wiring mistakes that Modbus faithfully reports"],
    brief="An energy management system polls three meters on RS-485: a main incomer (holding-register floats), an HVAC "
          "sub-meter (input-register floats) and a PV meter (scaled integers). Manuals list registers by number, "
          "counting from 1 (sometimes with a 3xxxx or 4xxxx prefix); the protocol uses addresses counting from 0.",
    steps=[
        step("Select a reply from the MAIN INCOMER meter.", sel("Holding Registers reply", src="s1"),
             why="Two consecutive registers form one IEEE-754 float; the tree decodes each pair."),
        quiz("The manual says 'Current I1: register 3000 (float, 2 registers)'. Which address goes in the request?",
             ["3000", "2999", "3001", "43000"], 1,
             why="Address = register number - 1. The 4xxxx prefix only means 'holding register' and is never sent."),
        step("Inject 'Integrator typed the manual's register numbers as addresses' and look at the EMS DEVICE panel.",
             fault("offbyone"), node("m"), side(DEVICE),
             why="Every request starts one register late, so each float is built from the second half of one value and "
                 "the first half of the next: absurd - or worse, plausible - numbers."),
        step("Fix it. COMPOSE 'Read by manual register number' for register 3060 (2 registers) of the main meter.",
             fault("offbyone", False), send("Read by manual"), frame("addr 3059"),
             why="The template converts for you: 3060 - 1 = 3059."),
        step("Reverse the CT on phase L2 of the HVAC meter and watch the EMS readings.", fault("ctpol"), node("m"), var("m", "HVAC kW (L1 L2 L3)", "~", "-"),
             why="A CT fitted backwards measures that phase with the wrong sign: the total is low by twice that phase's "
                 "power. Modbus transports the wrong number perfectly."),
        quiz("How many registers does a 32-bit float occupy?", ["1", "2", "4", "8"], 1,
             why="Two 16-bit registers. A 64-bit energy counter needs four."),
        step("Clear the CT fault.", fault("ctpol", False)),
    ])

# ============================================================= NETWORKING
lab(id="tcp", group="net", key="tcp", cat="NETWORKING", mins=10,
    title="TCP: handshake, congestion and loss recovery",
    learn=["The three-way handshake and its options",
           "Slow start, the congestion window and a queue overflow",
           "Duplicate ACKs, SACK, fast retransmit and flow control"],
    brief="A client downloads files from a server across the internet: 40 ms round trip and a 20 Mbit/s bottleneck with "
          "a 30-packet router queue. TCP has to discover how fast it can send. Slow start doubles the congestion window "
          "every round trip until a packet is lost; then the window is halved and grows slowly (congestion avoidance). "
          "The graph in the wiring view shows the window.",
    steps=[
        step("Select the client's SYN.", sel("[SYN]"),
             why="The SYN carries the initial sequence number and options: MSS 1460, window scale and SACK permitted. "
                 "SYN-ACK and ACK complete the handshake."),
        quiz("The client advertises Win=2048 but can receive 256 KB. Why?",
             ["The window is counted in units of 128 bytes (window scale 7)", "It is almost out of memory", "2048 is the MSS", "A bug"], 0,
             why="The 16-bit window field stops at 64 KB. The window scale option multiplies it: 2048 x 2^7 = 262144."),
        step("COMPOSE 'Reconnect': a new connection starts in slow start. Watch for packets the router drops.", send("Reconnect"), err("tail drop"),
             why="Slow start doubles the window every round trip until it overshoots: the router queue overflows and the "
                 "newest packets are dropped (tail drop). That is how TCP finds the path capacity."),
        step("Select a duplicate ACK from the client.", sel("Dup ACK"),
             hint="Press HOLD to freeze the list, or type 'dup' in the FILTER box.",
             why="Segments behind the hole arrive out of order. The client keeps acknowledging the last in-order byte and "
                 "lists what it did receive in SACK blocks."),
        step("Select a retransmission from the server.", sel("RETRANSMISSION"),
             hint="Filter on 'retrans', or HOLD the capture.",
             why="After three duplicate ACKs the server resends the missing segment at once (fast retransmit) and halves "
                 "its congestion window."),
        quiz("Why wait for three duplicate ACKs before retransmitting?",
             ["To save bandwidth", "One or two can be caused by reordering, not loss", "The standard needs an odd number", "To let the queue drain"], 1,
             why="Packets are sometimes reordered on the way. Three duplicates make a real loss far more likely."),
        step("Inject 'Client application stops reading' and watch the window close.", fault("zwin"), frame("ZeroWindow"),
             why="The receive buffer fills and the client advertises a zero window: flow control. The server stops and "
                 "sends probes until the window opens again."),
        step("Let the application read again.", fault("zwin", False)),
    ])

lab(id="ip", group="net", key="ip", cat="NETWORKING", mins=8,
    title="IP: ARP, ping, traceroute and path MTU",
    learn=["How a host finds its gateway (ARP, IPv6 router advertisements)",
           "TTL, and how traceroute uses it",
           "Path MTU discovery with the don't-fragment bit"],
    brief="A host on 192.168.1.0/24 reaches a server two routers away; IPv6 runs alongside, and the host forms its "
          "address from the router advertisement (SLAAC). Each router decrements the TTL (hop limit in IPv6); a router "
          "that brings it to zero drops the packet and sends ICMP 'time exceeded' back.",
    steps=[
        step("Select the IPv6 Router Advertisement.", sel("Router Advertisement"),
             why="The router announces the /64 prefix. The host adds its interface identifier and checks that the address "
                 "is unique with duplicate address detection."),
        step("Select the ARP request for the default gateway.", sel("ARP who has"),
             why="To reach another subnet the host needs its gateway's MAC address: ARP request (broadcast), ARP reply. "
                 "Packets wait until it arrives."),
        step("COMPOSE 'Ping IPv4' to the server.", send("Ping IPv4"), frame("Echo (ping) reply"),
             why="The echo request goes to the router's MAC address but the server's IP address."),
        quiz("The reply arrives with TTL 62; the server sent it with TTL 64. How many routers are on the path?", ["0", "1", "2", "62"], 2),
        step("COMPOSE a 'Traceroute' and select a 'time exceeded' reply.", send("Traceroute"), sel("time exceeded"),
             why="Probes with TTL 1, 2, 3 ... Each router that brings the TTL to 0 answers 'time exceeded' and reveals "
                 "itself. The destination answers 'port unreachable'."),
        step("Inject 'Link between the routers has MTU 1400' and ping with 1472 data bytes, DF set.", fault("mtu"), send("Ping IPv4"), frame("fragmentation needed"),
             auto={"set": {"n": 1472}},
             why="1472 + 8 (ICMP) + 20 (IP) = 1500 bytes. Router 1 may not fragment it (DF), so it answers 'fragmentation "
                 "needed' with the next-hop MTU - path MTU discovery."),
        quiz("What is the largest ping payload that now passes with DF set?", ["1372 bytes", "1380 bytes", "1400 bytes", "1472 bytes"], 0,
             why="1400 - 20 (IP header) - 8 (ICMP header) = 1372."),
        step("Ping again with 1372 data bytes.", send("Ping IPv4"), frame("1372 data bytes"), frame("Echo (ping) reply"),
             auto={"set": {"n": 1372}}),
        step("Clear the fault.", fault("mtu", False)),
    ])

lab(id="mqtt", group="net", key="mqtt", cat="NETWORKING", mins=8,
    title="MQTT: publish/subscribe, QoS and the last will",
    learn=["Topics, wildcards and retained messages",
           "The QoS 2 exactly-once handshake",
           "Keep-alive and the last will and testament"],
    brief="Sensors, a smart plug and a phone app connect to an MQTT broker (TCP 1883). Clients never talk to each other "
          "directly: they publish to topics, and the broker forwards each message to every matching subscription. A "
          "retained message is kept by the broker and handed to new subscribers at once; a last will is published by "
          "the broker for a client that disappears.",
    steps=[
        step("Select the phone app's SUBSCRIBE.", sel("SUBSCRIBE home/+"),
             why="'+' matches exactly one topic level, '#' matches everything below. SUBACK returns the granted QoS for "
                 "each filter."),
        quiz("Which topic matches the filter home/+/temperature?",
             ["home/temperature", "home/livingroom/temperature", "home/livingroom/sensor/temperature", "office/livingroom/temperature"], 1),
        step("Select a message the broker delivers as a retained copy.", sel("retained copy"),
             why="Right after subscribing the phone gets the last retained value of each topic - no waiting for the next change."),
        step("COMPOSE 'Phone: switch the plug' with QoS 2 and follow the handshake.", send("Phone: switch"), frame("PUBREC"), frame("PUBREL"), frame("PUBCOMP"),
             why="PUBLISH, PUBREC (received), PUBREL (release), PUBCOMP (complete): the plug switches exactly once even "
                 "if the connection breaks in between."),
        quiz("Which QoS level can deliver a message twice?", ["QoS 0", "QoS 1", "QoS 2", "None"], 1,
             why="QoS 1 = at least once: the sender repeats until it gets a PUBACK, so a lost PUBACK causes a duplicate."),
        step("Unplug the smart plug and wait for the broker to publish its last will.", fault("plug"), event("last will"), frame("home/plug/status = offline"),
             why="The plug connected with keep-alive 3 s and a will 'offline'. After 1.5 x keep-alive with no packet the "
                 "broker publishes the will to every subscriber."),
        step("Plug it back in.", fault("plug", False), frame("CONNECT client-id plug-1")),
    ])

lab(id="wifi", group="net", key="wifi", cat="NETWORKING", mins=8,
    title="Wi-Fi: joining a WPA2 network",
    learn=["What beacons advertise",
           "Authentication, association and the 4-way handshake",
           "What a wrong passphrase looks like on the air"],
    brief="An access point on channel 6 (2.4 GHz) serves a laptop on a video call and an IP camera. A phone joins: it "
          "probes for the network, does Open System authentication and association, then proves it knows the "
          "passphrase in the WPA2 4-way handshake (EAPOL-Key messages). Every unicast frame is acknowledged.",
    steps=[
        step("Select a beacon.", sel("Beacon"),
             why="About ten per second: SSID, supported rates, channel and the RSN element - WPA2, CCMP, PSK."),
        step("COMPOSE 'Re-join the phone' and follow it in FLOW.", send("Re-join"), frame("Association Response"), frame("EAPOL-Key 4/4"), deck(FLOW),
             why="Probe, authentication (Open System), association (the AP assigns an AID), then EAPOL-Key 1/4 to 4/4."),
        quiz("What does the 4-way handshake prove?",
             ["The phone's MAC address is allowed", "Both sides know the passphrase, without sending it", "The channel is free", "The phone's IP address"], 1,
             why="Both derive the session keys from the passphrase-based PMK and two random nonces. Message 2 carries a MIC "
                 "made with that key - correct only if the phone knows the passphrase."),
        step("Select an ACK frame.", sel("802.11 ACK"),
             why="An ACK follows SIFS (10 us on 2.4 GHz) after a unicast frame - before anyone else may transmit. No ACK "
                 "means the sender retries."),
        step("Give the phone the wrong passphrase (fault) and let it re-join.", fault("psk"), send("Re-join"), frame("MIC INVALID"),
             why="The AP checks message 2's MIC, finds it wrong and aborts. Everything before the handshake succeeded."),
        quiz("Can someone who recorded this handshake learn the passphrase?",
             ["No, never", "Only by testing passphrase guesses offline against the MIC", "Yes, it is sent in message 1", "Only with access to the AP"], 1,
             why="The nonces and MIC let an attacker test guesses offline. Long random passphrases - or WPA3 SAE, which "
                 "resists offline guessing - defeat this."),
        step("Clear the fault.", fault("psk", False)),
    ])
