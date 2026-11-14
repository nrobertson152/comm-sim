"""Protocol registry: categories in the order of the syllabus."""
from . import phys, industrial, auto, marine, aero, power, net

CATS = [
    ("PHYSICAL", "PHYSICAL LAYER", "Physical interfaces and signalling standards: how devices communicate electrically or optically.", phys.ALL),
    ("INDUSTRIAL", "INDUSTRIAL AUTOMATION", "PLCs, HMIs, drives, motion controllers, instrumentation and manufacturing equipment.", industrial.ALL),
    ("AUTOMOTIVE", "AUTOMOTIVE / HEAVY EQUIPMENT", "Cars, trucks, buses, agricultural machinery and off-highway vehicles.", auto.ALL),
    ("MARINE", "MARINE ELECTRONICS", "Navigation instruments, engines, autopilots, AIS and ship bridge systems.", marine.ALL),
    ("AEROSPACE", "AVIATION / AEROSPACE", "Avionics buses, flight data, air traffic surveillance and data links, spacecraft networks.", aero.ALL),
    ("POWER/BLDG", "POWER / BUILDING AUTOMATION", "Utility SCADA, substations, metering, solar and EV charging, HVAC, lighting and stage control.", power.ALL),
    ("NETWORKING", "NETWORKING / WIRELESS", "Internet protocols, IoT messaging and the short- and long-range radios of the IoT.", net.ALL),
]
BY_KEY = {}
for _c in CATS:
    for _cls in _c[3]:
        BY_KEY[_cls.key] = _cls
