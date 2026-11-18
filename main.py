from cli import parser
from scanner import scanner
from send_techniques import syn_send, udp_send, xmas_send
from response_interpretation import interpret_syn, interpret_udp, interpret_xmas

send_techniques = {
    "syn": syn_send,
    "udp": udp_send,
    "xmas": xmas_send
}

interpretation_techniques = {
    "syn": interpret_syn,
    "udp": interpret_udp,
    "xmas": interpret_xmas
}

def main():
    args = parser()

    results = scanner(
        ip=args.IP,
        ports=args.ports,
        send_technique=send_techniques[args.type],
        interpretation_technique=interpretation_techniques[args.type],
        timeout=args.timeout
    )

    print(results)

if __name__ == "__main__":
    main()