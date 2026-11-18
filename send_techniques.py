from scapy.all import IP, TCP, UDP, sr1

def syn_send(ip, port, timeout):
    packet = IP(dst=str(ip)) / TCP(dport=port, flags="S")
    response = sr1(packet, timeout=timeout, verbose=False)
    return response

def udp_send(ip, port, timeout):
    packet = IP(dst=str(ip)) / UDP(dport=port)
    return sr1(packet, timeout=timeout, verbose=False)

def xmas_send(ip, port, timeout):
    packet = IP(dst=str(ip)) / TCP(dport=port, flags="FPU")
    return sr1(packet, timeout=timeout, verbose=False)