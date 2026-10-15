# ProxyDash Server and Traffic Monitor

A read-only server and proxy dashboard with explicit measurement limits and stale-data handling.

**Project status:** Implemented; deployment validation recorded

## Published contents

Project documentation plus the generic local dashboard source and its browser UI. Server installers, operational configuration and credential fixtures are excluded.

This repository distinguishes the overall project record from the files published here. It is a curated portfolio release, not a dump of the original workspace.

## Technologies

Python, psutil, HTTP API, Linux, systemd, SSH

## Recorded achievements

- Samples CPU, memory, disk, TCP connections and throughput every two seconds; retains ten minutes of in-memory traffic history.
- Preserves the last snapshot on sampling failure and marks stale readings, errors and insufficient permissions.
- Supports systemd deployment, loopback-only listening, SSH forwarding and desktop/mobile layouts.

## Evidence limits

Client counts estimate unique remote TCP IPs, not physical devices. Interface throughput is not per-user billing. Existing deployment evidence is historical; no server was changed during publication.

Test and deployment statements above describe the local project record. No new research experiment, cloud inference or production change was made for this publication.

## Source availability

Run the generic dashboard locally:

```sh
python -m pip install -r requirements.txt
python dashboard.py
```

The default listener is loopback-only. Supply your own environment configuration for other usage. The local full-project review passed five tests; those operational fixtures are not published here.

## Portfolio

[All projects](https://github.com/Y77qs/felix-projects)
