"""Marine category (syllabus order)."""
from .marine_a import NMEA0183, IEC61162_1, SeaTalk, AIS
from .marine_b import NMEA2000, SeaTalkNG, OneNet, IEC61162_450, SignalK

ALL = [NMEA0183, NMEA2000, OneNet, SeaTalk, SeaTalkNG, IEC61162_450, AIS, IEC61162_1, SignalK]
