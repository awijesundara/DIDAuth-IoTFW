# DIDAuth-IoTFW

DIDAuth-IoTFW explores decentralized firmware verification for IoT devices. The project combines two FastAPI backends and an ESP32 example that demonstrate how verifiable credentials can secure firmware updates

- **did-api-vendor** – issues firmware credentials
- **did-api-gateway** – verifies credentials
- **did-iot-firmware** – ESP32 example
- **performance-analysis** – latency scripts
- **security-analysis** – security tests (includes `run_threat_model_tests.sh`)

## Threat model evaluation
The `security-analysis/run_threat_model_tests.sh` script exercises three attack scenarios. After improving error handling, all attacks are detected and the gateway responds with HTTP 200 and a clear status message:

| Scenario | HTTP | Status |
| --- | --- | --- |
| credential_forgery | 200 | ❌ Failed to fetch DID: did:local:attacker |
| replay_attack | 200 | ❌ VC is revoked |
| gateway_compromise | 200 | ❌ Failed to fetch DID: did:local:attacker |

MIT License
© 2025 Anushka Wijesundara
