# C2 Command & Control Framework

A modern, distributed Command & Control (C2) framework designed for secure remote administration and red team operations. Built with Go for the backend services and Python for the operator interface.

## Overview

This C2 framework provides a robust platform for managing remote agents through a scalable, microservices-based architecture. It features real-time bidirectional communication, dynamic payload generation, and comprehensive operational security features.

## Architecture

### Core Components

- **WebSocket Service** - Real-time communication hub for operator clients
- **Agent Handler** - Manages agent connections and HTTP/HTTPS listeners  
- **PostgreSQL Database** - Persistent storage for all operational data
- **Docker Builder** - On-demand payload generation for multiple platforms
- **Python GUI Client** - Feature-rich operator interface

### Communication Flow

1. Operators connect to the WebSocket service via TLS-encrypted connections
2. Commands are routed through a gRPC bidirectional stream to the Agent Handler
3. Agents callback to HTTP/HTTPS listeners managed by the Agent Handler
4. Results flow back through the system to operators in real-time

## Key Features

### Agent Capabilities
- Cross-platform support (Windows, Linux, macOS)
- Multiple persistence mechanisms
- File transfer (upload/download with chunking)
- Process manipulation and injection
- Network pivoting and SOCKS proxy
- Screenshot capture
- Keylogging capabilities
- Anti-forensics and evasion techniques

### Operational Features
- Dynamic listener management (HTTP/HTTPS)
- Encrypted agent communications
- Asynchronous task processing
- Real-time agent status updates
- Session management with duplicate prevention
- Comprehensive logging and audit trails

### Security Features
- TLS encryption for all external communications
- Per-agent encryption keys
- Certificate-based authentication
- Secure secret generation and rotation
- Code signing for payloads

## Installation

### Automated Setup (Recommended)

The framework includes a modular setup script that handles all dependencies and configuration:

```bash
cd scripts
sudo ./setup.sh
```

This will install and configure:
- System packages
- Go programming language
- Protocol Buffers compiler
- Docker and Docker Compose
- TLS certificates
- Database secrets
- Server binaries
- Python client environment

**For detailed installation options and troubleshooting, see [SETUP.md](docs/SETUP.md)**

The setup script supports modular execution for recovery scenarios:
```bash
# Re-run specific components if something fails
sudo ./setup.sh --build      # Only rebuild binaries
sudo ./setup.sh --certs      # Only regenerate certificates
sudo ./setup.sh --help       # See all available options
```

### Manual Setup

If you prefer manual installation or need to customize specific steps:

## Quick Start

### Prerequisites
- Docker and Docker Compose
- PostgreSQL
- Go 1.19+
- Python 3.8+
- Valid TLS certificates

### Server Deployment

1. Clone the repository
2. Run the setup script:
```bash
cd scripts
sudo ./setup.sh
```

3. Start the services:
```bash
cd ../server/docker
docker compose up -d
```

### Client Connection

1. If not done during setup, create Python virtual environment:
```bash
cd client
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Configure certificates (automatically handled by setup script)

3. Launch the GUI:
```bash
source venv/bin/activate
cd src
python main.py
```

## Project Structure

```
.
├── scripts/
│   ├── setup.sh           # Modular setup script
│   └── gen_default_certs.sh
├── docs/
│   ├── SETUP.md           # Detailed installation guide
│   ├── LOGVIEWER.md       # Details for logviewer executable
│   └── c2-architecture.html
├── server/
│   ├── cmd/               # Service entry points
│   ├── internal/          # Core C2 services logic
│   ├── docker/            # Docker configurations
│   │    └── payloads/     # Agent source code
│   └── configs/           # Service configurations
├── client/
│   ├── src/               # Python GUI source
│   └── certs/             # Client certificates
```

## Services

### WebSocket Service (Port 3131)
- Handles operator authentication
- Manages real-time bidirectional communication
- Invokes payload builder on demand
- Routes commands to appropriate handlers

### Agent Handler (Port 50051 - gRPC)
- Manages HTTP/HTTPS listeners
- Processes agent callbacks
- Handles asynchronous task execution
- Maintains agent state

### Database
- PostgreSQL for persistent storage
- Stores agents, tasks, sessions, and audit logs
- Connection pooling for performance

## Troubleshooting

### Setup Issues

If you encounter issues during installation:

1. **Check the setup summary** - The script provides detailed feedback about what succeeded or failed
2. **Re-run specific components** - Use flags to retry failed steps:
   ```bash
   sudo ./setup.sh --build    # Retry binary build
   sudo ./setup.sh --certs    # Regenerate certificates
   ```
3. **Consult the setup guide** - See [SETUP.md](docs/SETUP.md) for detailed troubleshooting

### Common Issues

- **Docker permission errors**: Log out and back in after running setup (Docker group membership)
- **Build failures**: Ensure Go is properly installed with `go version`
- **Certificate errors**: Verify certificates were generated in `scripts/certs/`
- **Database connection**: Check that secrets were generated properly

For more details, see the [Setup Guide](docs/SETUP.md).

## License

MIT

## Disclaimer

This software is provided for authorized security testing purposes only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this software.

---

## Additional Resources

- **[Setup Guide](docs/SETUP.md)** - Comprehensive installation and configuration guide
- **[Log Viewer](docs/LOGVIEWER.md)** - Command log analysis tool documentation
- **[Docker Documentation](server/docker/README.md)** - Container deployment details

**Quick Start Command:**
```bash
cd scripts
sudo ./setup.sh
```