# Fog-Driven-EHS
# Authentication Protocol Testbed for Fog-Driven e-Healthcare

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This repository contains a comprehensive Python testbed for benchmarking the lightweight authentication protocol described in the paper *"A Verifiably Secure and Lightweight Authentication Scheme for Fog-Driven e-Healthcare"*. The testbed measures cryptographic primitive performance, end-to-end authentication latency, energy consumption, and scalability under concurrent loads.

## Features

- 🔐 **Complete Protocol Implementation**: Full implementation of registration, authentication, and key agreement phases
- ⚡ **Performance Benchmarking**: Measures execution time for hash functions, HMAC, and XOR operations
- 🔋 **Energy Estimation**: Calculates energy consumption based on device-specific power models
- 📊 **Scalability Testing**: Evaluates performance under concurrent authentication requests
- 📈 **Results Export**: CSV and JSON output for further analysis
- 🔄 **Multiple Hash Algorithms**: Supports SHA-256, SHA3-256, BLAKE2b, and BLAKE2s for comparison

## Requirements

- Python 3.8 or higher
- No external dependencies (uses only standard library)

## Installation

```bash
git clone https://github.com/yourusername/auth-protocol-testbed.git
cd auth-protocol-testbed
python auth_protocol_testbed.py --help
