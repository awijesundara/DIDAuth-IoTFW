# DIDAuth-IoTFW2

Second-iteration working copy of [DIDAuth-IoTFW](https://github.com/awijesundara/DIDAuth-IoTFW): decentralized firmware authentication for smart-home IoT devices using W3C DIDs and Verifiable Credentials anchored on an Arbitrum smart contract with IPFS storage.

[![CI](https://github.com/awijesundara/DIDAuth-IoTFW2/actions/workflows/ci.yml/badge.svg)](https://github.com/awijesundara/DIDAuth-IoTFW2/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.12-3776AB?logo=python&logoColor=white)](did-api-gateway/requirements.txt)
[![FastAPI](https://img.shields.io/badge/FastAPI-vendor%20%2B%20gateway-009688?logo=fastapi&logoColor=white)](did-api-vendor)
[![ESP32](https://img.shields.io/badge/ESP32-firmware-E7352C?logo=espressif&logoColor=white)](did-iot-firmware)
[![Arbitrum](https://img.shields.io/badge/Arbitrum-L2%20registry-28A0F0)](did-api-vendor/blockchain)

## Components

| Directory | Purpose |
|---|---|
| `did-api-vendor` | FastAPI vendor service that issues and revokes firmware credentials, with the Hardhat registry contract |
| `did-api-gateway` | FastAPI gateway that verifies verifiable presentations before a device installs firmware |
| `did-iot-firmware` | ESP32 example firmware (the PlatformIO project file is kept in the public repository) |
| `performance-analysis` | Latency, heap and payload measurements with result charts |
| `security-analysis` | Threat-model test suite (`run_threat_model_tests.sh`) |
| `esp32-analyisis` | Device-side analysis notes |

## Run the tests

```bash
pip install -r did-api-gateway/requirements.txt -r did-api-vendor/backend/requirements.txt pytest
(cd did-api-gateway && python -m pytest -q)
(cd did-api-vendor && python -m pytest -q)
```

## License

MIT © 2025 Anushka Wijesundara

## Project statistics

| Metric | Value |
|---|---|
| Tracked files | 76 |
| Lines of code (non-blank) | 2,747 |
| Languages | Python 1,651, C++ (Arduino) 670, Shell 357, Solidity 45, JavaScript 24 |
| Automated tests | 7 |
| Commits | 11 |

CI compiles both FastAPI services and runs the gateway and vendor test suites on each push to `main`.
