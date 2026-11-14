"""Automotive and heavy equipment category (syllabus order)."""
from .auto_a import J1939, J1708, J1587, CANopenMobile, CANFDAuto, LIN, FlexRay
from .auto_b import AutoEth, UDS, ISOTP, OBD2, ISO9141, KWP2000, J1850, SENT, PSI5, MOST, ISOBUS
from .marine_b import NMEA2000

ALL = [J1939, J1708, J1587, CANopenMobile, CANFDAuto, LIN, FlexRay, AutoEth, UDS, ISOTP, OBD2, ISO9141, KWP2000, J1850, SENT, PSI5, MOST, ISOBUS, NMEA2000]
