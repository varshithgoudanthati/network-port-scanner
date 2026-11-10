"""TCP port scanner for systems you own or are authorized to test."""
import argparse
import csv
import math
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor


def ports(value):
    result = set()
    try:
        for item in value.split(","):
            parts = item.strip().split("-")
            if len(parts) == 1:
                start = end = int(parts[0])
            elif len(parts) == 2:
                start, end = map(int, parts)
            else:
                raise ValueError
            if not 1 <= start <= end <= 65535:
                raise ValueError
            result.update(range(start, end + 1))
    except ValueError:
        raise argparse.ArgumentTypeError(
            "Use ports 1-65535, for example 22,80,443,8000-8010"
        )
    return sorted(result)


def timeout_value(value):
    try:
        number = float(value)
        if not math.isfinite(number) or not 0 < number <= 60:
            raise ValueError
        return number
    except ValueError:
        raise argparse.ArgumentTypeError("Timeout must be greater than 0 and at most 60")


def workers_value(value):
    try:
        number = int(value)
        if not 1 <= number <= 200:
            raise ValueError
        return number
    except ValueError:
        raise argparse.ArgumentTypeError("Workers must be between 1 and 200")


def probe(target, family, address, port, timeout):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect((address, port))
        status, detail = "open", "TCP connection established"
    except (socket.timeout, TimeoutError):
        status, detail = "timeout", "No response before deadline"
    except ConnectionRefusedError:
        status, detail = "closed", "Connection refused"
    except OSError as error:
        status, detail = "error", str(error)
    return {
        "target": target, "address": address, "port": port,
        "status": status, "detail": detail
    }


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Only scan systems you own or have explicit permission to test."
    )
    parser.add_argument("target", help="Hostname, IPv4, or IPv6 address")
    parser.add_argument("-p", "--ports", type=ports, default=ports("1-1024"))
    parser.add_argument("--timeout", type=timeout_value, default=1.0)
    parser.add_argument("--workers", type=workers_value, default=50)
    parser.add_argument("--csv", metavar="FILE")
    parser.add_argument("--open-only", action="store_true")
    args = parser.parse_args()
    started = time.monotonic()

    try:
        resolved = socket.getaddrinfo(
            args.target, None, type=socket.SOCK_STREAM
        )[0]
        family, address = resolved[0], resolved[4][0]
        print(f"Target: {args.target} ({address})")
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            results = list(pool.map(
                lambda port: probe(
                    args.target, family, address, port, args.timeout
                ),
                args.ports
            ))

        print(f'{"PORT":<8} {"STATUS":<9} DETAIL')
        for row in results:
            if not args.open_only or row["status"] == "open":
                print(
                    f'{row["port"]:<8} {row["status"]:<9} {row["detail"]}'
                )

        counts = {
            status: sum(row["status"] == status for row in results)
            for status in ("open", "closed", "timeout", "error")
        }
        print("Summary: " + ", ".join(
            f"{count} {status}" for status, count in counts.items()
        ))
        print(f"Elapsed: {time.monotonic() - started:.2f}s")

        if args.csv:
            with open(args.csv, "w", newline="", encoding="utf-8") as file:
                writer = csv.DictWriter(
                    file,
                    fieldnames=["target", "address", "port", "status", "detail"]
                )
                writer.writeheader()
                writer.writerows(results)
            print(f"CSV saved: {args.csv}")

        return 1 if counts["error"] else 0
    except (OSError, UnicodeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
