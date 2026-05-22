# TrafficLens
Network Traffic Visualization and Analysis Tool

## Architecture

TrafficLens is a Django web application for uploading and analyzing PCAP files. The codebase is split into two layers:

- **[`trafficlens_core`](./trafficlens_core)** — pure Python packet analysis library. No Django or Scapy dependency. Handles Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP, and DNS.
- **[`TrafficLensFrontend`](./TrafficLensFrontend)** — Django web UI. User authentication (register, email activation, password reset), per-user PCAP upload, and paginated packet analysis view.

## Development

### Setup

1. Install dependencies:
   ```
   uv sync
   ```

2. Copy the example env file and fill in values:
   ```
   cp TrafficLensFrontend/.env.example TrafficLensFrontend/.env
   ```

3. Run migrations:
   ```
   uv run python TrafficLensFrontend/manage.py migrate
   ```

4. Start the development server:
   ```
   uv run python TrafficLensFrontend/manage.py runserver
   ```

### Tests

```
uv run pytest
```

Django app tests:
```
uv run python TrafficLensFrontend/manage.py test main
```

## Features

- **PCAP upload** — per-user sandboxed file storage with magic-byte validation
- **Packet analysis** — Ethernet / IPv4 / IPv6 / ARP / TCP / UDP / ICMP / DNS parsed and displayed in a paginated table
- **Authentication** — registration with email activation, login, password reset
- **Admin** — Django admin interface at `/admin/` for managing users and uploads

## Environment variables

See [`TrafficLensFrontend/.env.example`](./TrafficLensFrontend/.env.example) for all required and optional variables.

## Resources

- [Django docs](https://docs.djangoproject.com/en/6.0/)
- [Sample PCAP files](https://wiki.wireshark.org/SampleCaptures)
