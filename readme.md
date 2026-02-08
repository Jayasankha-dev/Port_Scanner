# Bug Bounty Automation Suite

A multi-language security testing suite for bug bounty hunters and penetration testers.

## Features

- **Port Scanner (C++)**: Fast, multi-threaded TCP port scanning
- **HTTP Fuzzer (Rust)**: Directory and parameter fuzzing with vulnerability detection
- **Recon Tool (Go)**: Subdomain enumeration, technology fingerprinting, sensitive info discovery
- **Orchestrator (Python)**: Coordinate all tools and generate reports

## Installation

### 1. Install Dependencies

**Linux (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install g++ golang cargo python3 python3-pip