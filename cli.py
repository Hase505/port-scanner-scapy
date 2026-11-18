import argparse
import ipaddress

def parse_ports(value):
    ports = set()

    try:
        for part in value.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))

                if not (1 <= start <= end <= 65535):
                    raise ValueError

                ports.update(range(start, end + 1))

            else:
                port = int(part)

                if not 1 <= port <= 65535:
                    raise ValueError

                ports.add(port)

    except ValueError:
        raise argparse.ArgumentTypeError(
            "Invalid ports. Use formats like 80,443 or 1-1000"
        )

    return sorted(ports)

def parser():
    parser = argparse.ArgumentParser(
        description="Port scanner",
        usage="%(prog)s IP -p PORT(S) -t SCAN_TECHNIQUE",
        formatter_class=lambda prog: argparse.HelpFormatter(
            prog,
            max_help_position=40
        )
    )

    parser.add_argument(
        "IP",
        type=ipaddress.ip_address,
        help="Destination IP address"
    )

    parser.add_argument(
        "-p", "--ports",
        required=True,
        type=parse_ports,
        help="Destination ports"
    )

    parser.add_argument(
        "-t", "--type",
        required=True,
        choices=["syn", "udp", "xmas"],
        help="Scan type"
    )

    parser.add_argument(
        "-T", "--timeout",
        type=float,
        default=2.0,
        help="Timeout per port in seconds (default: 2)"
    )

    return parser.parse_args()

    