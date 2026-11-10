# Network Security Port Scanner

## Problem and objective
Identify reachable TCP ports on an authorized target while learning sockets,
DNS resolution, timeouts, concurrency, and network error handling.

## Technologies
Python 3.10+ and its standard library. No external dependencies.

## Features
- Hostname, IPv4, or IPv6 target input.
- Individual ports and inclusive port ranges.
- Concurrent TCP connection scanning.
- Open, closed, timeout, and error identification.
- Clear table, summary counts, and elapsed time.
- Configurable timeout and worker count.
- CSV export and optional open-only terminal output.
- Input, DNS, network, and export error handling.

## Windows setup
Install Python from https://www.python.org/downloads/
Open PowerShell in this folder and run:

    py scanner.py --help
    py scanner.py 127.0.0.1 -p 7999-8001 --csv results.csv

## Local demonstration
In one terminal, start a local web server:

    py -m http.server 8000 --bind 127.0.0.1

In another terminal:

    py scanner.py 127.0.0.1 -p 7999-8001 --csv results.csv

Port 8000 should be open. Other ports should be closed if unused.
Stop the server with Ctrl+C and scan again to observe the change.

## How it works
The scanner validates ports, resolves the target once, and attempts TCP
connections using a bounded thread pool. Each socket closes after its probe.
Results appear in port order and can be exported to CSV.

Open: connection succeeded.
Closed: connection refused.
Timeout: deadline exceeded; this does not prove the port is closed.
Error: another network or operating-system failure.

Hostnames use the first address returned by the operating system.
Supply an IP address to choose an exact destination.
The timeout applies to TCP connections, not DNS resolution.

## Tests
    py -m unittest -v

Tests use local sockets and simulated timeouts, not external targets.

## Security considerations
Only scan systems you own or have explicit permission to test.
TCP connections may be logged. An open port is not proof of a vulnerability.
This prototype does not perform exploitation, UDP scanning, host discovery,
or service-version detection. Default concurrency is 50; maximum is 200.
Interruption may wait for queued connection attempts to complete.

## Screenshots and demo
Capture your local terminal output and optionally record the demonstration.
Screenshots and a hosted demo link have not been added.
This CLI can be demonstrated locally without public deployment.

## Future improvements
Progress reporting, improved cancellation, JSON export, address-family
selection, and comparison of previous authorized scans.

## Submission
Roll Number: <your roll number>
Project Name: Network Security Port Scanner
GitHub Repository: <your repository URL>
Live/Demo Link: <demo video URL or local-run instructions>
