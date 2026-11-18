from cli import parser
from collections import Counter
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

def print_results(ip, scan_type, results):
    counts = Counter(r["state"] for r in results)
    hidden_state = None
    shown = results

    # With many ports, hide the most common state (like nmap)
    if len(results) > 25:
        hidden_state, hidden_count = counts.most_common(1)[0]
        shown = [r for r in results if r["state"] != hidden_state]

    print(f"\n{scan_type.upper()} scan on {ip}\n")

    if hidden_state:
        print(f"Not shown: {hidden_count} ports in state {hidden_state}\n")

    if shown:
        print(f"{'PORT':<10}{'STATE'}")
        print("-" * 24)
        for r in shown:
            print(f"{r['port']:<10}{r['state']}")

    print("\nSummary: " + ", ".join(f"{n} {s}" for s, n in counts.most_common()))

def main():
    args = parser()

    results = scanner(
        ip=args.IP,
        ports=args.ports,
        send_technique=send_techniques[args.type],
        interpretation_technique=interpretation_techniques[args.type],
        timeout=args.timeout
    )

    print_results(args.IP, args.type, results)

if __name__ == "__main__":
    main()