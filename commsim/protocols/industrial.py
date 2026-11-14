"""Industrial automation protocols (in syllabus order)."""
from .industrial_a import ModbusRTU, ModbusASCII, ModbusTCP, EtherNetIP, CIP, EtherCAT, PROFINET
from .industrial_b import ProfibusDP, ProfibusPA, CANopen, DeviceNet, ControlNet, IOLink, ASi, HART
from .industrial_c import WirelessHART, FFH1, CCLink, CCLinkIE, Sercos3, Powerlink, OPCUA, MQTTInd, DDS

ALL = [ModbusRTU, ModbusASCII, ModbusTCP, EtherNetIP, EtherCAT, PROFINET, ProfibusDP, ProfibusPA, CANopen, DeviceNet, ControlNet, IOLink, ASi, HART,
       WirelessHART, FFH1, CCLink, CCLinkIE, Sercos3, Powerlink, OPCUA, MQTTInd, DDS, CIP]
