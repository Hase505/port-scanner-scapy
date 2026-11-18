from scapy.all import TCP, UDP, ICMP

SYN = 0x02
ACK = 0x10
RST = 0x04

def interpret_syn(response):
    if response is None:
        return "filtered"
    
    if response.haslayer(TCP):
        flags = int(response[TCP].flags)

        if flags & (SYN | ACK) == (SYN | ACK):
            return "open"

        if flags & (RST) == (RST):
            return "closed"

    if response.haslayer(ICMP):
        icmp = response[ICMP]

        if icmp.type == 3:
            if icmp.code in [1, 2, 3, 9, 10, 13]:
                return "filtered"

    return "unknown"

def interpret_udp(response):
    if response is None:
        return "open|filtered"

    if response.haslayer(UDP):
        return "open"

    if response.haslayer(ICMP):
        icmp = response[ICMP]

        if icmp.type == 3:
            if icmp.code == 3:
                return "closed"

            if icmp.code in [1, 2, 9, 10, 13]:
                return "filtered"

    return "unknown"

def interpret_xmas(response):
    if response is None:
        return "open|filtered"
    
    if response.haslayer(TCP):
        flags = int(response[TCP].flags)

        if flags & RST == RST:
            return "closed"
    
    if response.haslayer(ICMP):
        icmp = response[ICMP]

        if icmp.type == 3:
            if icmp.code in [1, 2, 3, 9, 10, 13]:
                return "filtered"
    
    return "unknown"