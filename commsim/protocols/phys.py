"""Physical interfaces and signalling standards (in syllabus order)."""
from .phys_a import RS232, RS422, RS485, RS423, RS449, UART, GPIB
from .phys_b import CAN, CANFD, Ethernet, SPI, I2C, OneWire, USB, LVDS, Fiber

ALL = [RS232, RS422, RS485, CAN, CANFD, Ethernet, UART, SPI, I2C, OneWire, USB, LVDS, RS423, RS449, GPIB, Fiber]
