"""Target and Port Parsing and Validation for Professional Network Audits."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import List, Sequence

# Well-known Top 20 Ports (Fast reconnaissance)
TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
    445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080
]

# Top 100 Ports
TOP_100_PORTS = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 102, 110, 111, 119, 123, 135,
    137, 138, 139, 143, 161, 162, 179, 389, 443, 445, 465, 500, 514, 515, 520,
    587, 593, 623, 631, 636, 873, 902, 989, 990, 993, 995, 1025, 1026, 1027,
    1080, 1194, 1433, 1434, 1521, 1723, 1812, 1813, 2049, 2082, 2083, 2086,
    2087, 2181, 2222, 3000, 3128, 3306, 3389, 3690, 4333, 4444, 4500, 5000,
    5060, 5357, 5432, 5601, 5672, 5900, 5985, 5986, 6000, 6379, 7001, 7077,
    8000, 8008, 8080, 8081, 8443, 8500, 8888, 9000, 9042, 9090, 9092, 9100,
    9200, 9300, 9443, 10000, 27017, 50000
]

# Standard Industry Top 1000 Ports (representative compilation of Nmap top ports)
TOP_1000_PORTS = sorted(list(set(
    TOP_100_PORTS + [
        1, 7, 9, 11, 13, 15, 17, 19, 26, 37, 42, 49, 70, 79, 81, 82, 83, 84, 85,
        89, 90, 99, 100, 107, 109, 113, 115, 118, 144, 146, 150, 156, 163, 175,
        199, 211, 212, 220, 264, 280, 311, 387, 399, 401, 407, 416, 417, 427, 444,
        458, 464, 481, 497, 502, 512, 513, 524, 541, 543, 544, 548, 554, 563, 585,
        591, 601, 616, 617, 631, 646, 648, 655, 666, 688, 691, 700, 705, 711, 714,
        720, 722, 726, 749, 765, 777, 782, 783, 787, 800, 801, 808, 843, 873, 880,
        888, 898, 901, 903, 911, 912, 981, 987, 992, 1000, 1001, 1002, 1008, 1010,
        1023, 1024, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038,
        1039, 1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051,
        1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064,
        1065, 1066, 1067, 1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077,
        1078, 1079, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091,
        1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106,
        1107, 1108, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124,
        1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151, 1152,
        1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185, 1186, 1187, 1192,
        1198, 1199, 1201, 1211, 1212, 1213, 1214, 1216, 1217, 1218, 1233, 1234, 1236,
        1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310,
        1311, 1322, 1328, 1334, 1352, 1417, 1431, 1432, 1443, 1455, 1461, 1494, 1500,
        1501, 1503, 1524, 1525, 1533, 1556, 1570, 1581, 1590, 1600, 1650, 1666, 1687,
        1688, 1700, 1717, 1718, 1719, 1720, 1721, 1755, 1761, 1777, 1782, 1783, 1801,
        1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971,
        1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007,
        2008, 2009, 2010, 2013, 2020, 2021, 2022, 2030, 2033, 2034, 2035, 2038, 2040,
        2041, 2042, 2043, 2045, 2046, 2047, 2048, 2065, 2068, 2080, 2100, 2102, 2103,
        2104, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170,
        2179, 2190, 2191, 2196, 2200, 2220, 2251, 2288, 2301, 2323, 2366, 2381, 2382,
        2383, 2399, 2401, 2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607,
        2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809, 2811, 2869, 2875,
        2909, 2910, 2920, 2967, 2968, 2998, 3001, 3005, 3017, 3030, 3031, 3052, 3071,
        3123, 3141, 3168, 3211, 3221, 3260, 3268, 3269, 3283, 3300, 3301, 3322, 3323,
        3324, 3325, 3333, 3351, 3367, 3372, 3388, 3404, 3476, 3493, 3517, 3527, 3546,
        3551, 3580, 3659, 3689, 3703, 3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826,
        3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920, 3945,
        3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004, 4005, 4006, 4045, 4111,
        4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4445, 4446, 4449, 4550,
        4567, 4662, 4848, 4899, 4900, 4998, 5001, 5002, 5003, 5004, 5005, 5050, 5051,
        5080, 5100, 5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5269, 5280, 5298,
        5351, 5353, 5355, 5405, 5431, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5631,
        5632, 5666, 5671, 5722, 5800, 5801, 5802, 5810, 5811, 5822, 5825, 5850, 5859,
        5862, 5877, 5901, 5902, 5903, 5904, 5906, 5907, 5910, 5911, 5915, 5922, 5925,
        5959, 5960, 5961, 5962, 5963, 5984, 5997, 5998, 5999, 6001, 6002, 6003, 6004,
        6005, 6006, 6007, 6009, 6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156,
        6346, 6389, 6443, 6502, 6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666,
        6667, 6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901,
        6969, 7000, 7002, 7004, 7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7201,
        7402, 7435, 7443, 7496, 7512, 7547, 7627, 7676, 7741, 7777, 7778, 7800, 7911,
        7920, 7921, 7937, 7938, 7999, 8007, 8009, 8022, 8031, 8042, 8045, 8082, 8083,
        8084, 8085, 8086, 8087, 8088, 8089, 8090, 8100, 8118, 8123, 8180, 8181, 8200,
        8222, 8254, 8290, 8291, 8292, 8300, 8332, 8333, 8383, 8400, 8402, 8444, 8501,
        8600, 8649, 8651, 8652, 8686, 8800, 8873, 8880, 8889, 8899, 8989, 8990, 9001,
        9002, 9010, 9020, 9030, 9050, 9080, 9081, 9091, 9101, 9102, 9110, 9111, 9207,
        9306, 9418, 9444, 9500, 9502, 9535, 9536, 9800, 9875, 9929, 9943, 9998, 9999,
        10001, 10008, 10010, 10024, 10025, 10082, 10180, 10243, 10566, 10616, 10621,
        10626, 10628, 10629, 10631, 11110, 11111, 11371, 12000, 12174, 12203, 12221,
        12222, 12223, 12345, 13456, 13720, 13721, 13724, 13782, 13783, 14000, 14238,
        14441, 14442, 15000, 15002, 15003, 15004, 15660, 16000, 16001, 16012, 16016,
        16018, 16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101,
        19283, 19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222,
        20828, 21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 26235, 27000,
        27018, 27019, 27352, 27353, 27355, 27356, 27715, 28201, 30000, 30718, 31099,
        32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778,
        32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899, 34571, 35500,
        38292, 40193, 40911, 41511, 42510, 44176, 44442, 44443, 44501, 45100, 48080,
        49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161, 49163,
        49165, 49167, 49175, 49176, 49400, 49999, 50001, 50003, 50006, 50300, 50500,
        50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328, 55055,
        55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020, 60443, 61532,
        62078, 63331, 64623, 64680, 65000, 65129, 65389
    ]
)))

WEB_DB_PORTS = [
    80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9443,  # Web
    1433, 1521, 3306, 5432, 6379, 27017, 9200                  # Databases & Caches
]


def parse_targets(target_str: str, max_hosts: int = 512) -> List[str]:
    """Parse a target string into a distinct list of IPv4 addresses."""
    targets: set[str] = set()
    cleaned = target_str.strip()
    if not cleaned:
        raise ValueError("Target specification cannot be empty.")

    tokens = [t.strip() for t in cleaned.split(",") if t.strip()]

    for token in tokens:
        # Hyphenated IP range
        if "-" in token and "/" not in token:
            parts = token.split("-")
            if len(parts) == 2:
                start_part, end_part = parts[0].strip(), parts[1].strip()
                try:
                    start_ip = ipaddress.IPv4Address(start_part)
                    if "." in end_part:
                        end_ip = ipaddress.IPv4Address(end_part)
                    else:
                        base = str(start_ip).rsplit(".", 1)[0]
                        end_ip = ipaddress.IPv4Address(f"{base}.{end_part}")
                    
                    if int(start_ip) > int(end_ip):
                        raise ValueError(f"Invalid range: start IP {start_ip} is greater than end IP {end_ip}")

                    count = int(end_ip) - int(start_ip) + 1
                    if len(targets) + count > max_hosts:
                        raise ValueError(f"Target count exceeds the maximum limit of {max_hosts} hosts.")

                    for ip_int in range(int(start_ip), int(end_ip) + 1):
                        targets.add(str(ipaddress.IPv4Address(ip_int)))
                    continue
                except ValueError as e:
                    if "exceeds" in str(e):
                        raise

        # CIDR Subnet
        if "/" in token:
            try:
                network = ipaddress.ip_network(token, strict=False)
                if not isinstance(network, ipaddress.IPv4Network):
                    raise ValueError(f"Only IPv4 is supported: {token}")

                if network.prefixlen >= 31:
                    hosts = [str(ip) for ip in network]
                else:
                    hosts = [str(ip) for ip in network.hosts()]

                if len(targets) + len(hosts) > max_hosts:
                    raise ValueError(
                        f"Subnet {token} contains {len(hosts)} hosts, exceeding maximum limit of {max_hosts}."
                    )
                targets.update(hosts)
                continue
            except ValueError as e:
                if "exceeding" in str(e):
                    raise
                raise ValueError(f"Invalid CIDR specification '{token}': {e}")

        # Single IP
        try:
            ip = ipaddress.IPv4Address(token)
            targets.add(str(ip))
            continue
        except ValueError:
            pass

        # Hostname resolution
        try:
            resolved = socket.gethostbyname(token)
            targets.add(resolved)
        except socket.gaierror:
            raise ValueError(f"Could not resolve or parse target: '{token}'")

    if not targets:
        raise ValueError("No valid targets could be found.")

    if len(targets) > max_hosts:
        raise ValueError(f"Total targets ({len(targets)}) exceed max allowed ({max_hosts}).")

    return sorted(list(targets), key=lambda x: int(ipaddress.IPv4Address(x)))


def parse_ports(selection: str = "top20", custom_ports: str | None = None) -> List[int]:
    """Return an ordered list of unique port numbers."""
    sel = (selection or "").strip().lower()

    if sel == "top20":
        return sorted(list(set(TOP_20_PORTS)))
    elif sel == "top100":
        return sorted(list(set(TOP_100_PORTS)))
    elif sel in ("top1000", "standard"):
        return sorted(list(set(TOP_1000_PORTS)))
    elif sel in ("all", "all_ports", "full", "65535"):
        # Full scan: 1-65535
        return list(range(1, 65536))
    elif sel in ("web_db", "web"):
        return sorted(list(set(WEB_DB_PORTS)))
    elif sel in ("1-1024", "system"):
        return list(range(1, 1025))
    elif sel == "custom" or custom_ports:
        port_str = custom_ports if (sel == "custom" and custom_ports) else selection
        ports: set[int] = set()
        for item in port_str.split(","):
            item = item.strip()
            if not item:
                continue
            if "-" in item:
                bounds = item.split("-")
                if len(bounds) == 2:
                    try:
                        start, end = int(bounds[0].strip()), int(bounds[1].strip())
                        if 1 <= start <= end <= 65535:
                            ports.update(range(start, end + 1))
                        else:
                            raise ValueError(f"Port range out of bounds (1-65535): {item}")
                    except ValueError:
                        raise ValueError(f"Invalid port range: '{item}'")
                else:
                    raise ValueError(f"Invalid port range syntax: '{item}'")
            else:
                try:
                    p = int(item)
                    if 1 <= p <= 65535:
                        ports.add(p)
                    else:
                        raise ValueError(f"Port number out of bounds (1-65535): {p}")
                except ValueError:
                    raise ValueError(f"Invalid port number: '{item}'")

        if not ports:
            raise ValueError("No valid ports parsed from custom input.")
        return sorted(list(ports))
    else:
        return sorted(list(set(TOP_20_PORTS)))
