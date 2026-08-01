# DIDAuth-IoTFW

DIDAuth-IoTFW explores decentralized firmware verification for IoT devices. The project combines two FastAPI backends and an ESP32 example that demonstrate how verifiable credentials can secure firmware updates

- **did-api-vendor** – issues firmware credentials
- **did-api-gateway** – verifies credentials
- **did-iot-firmware** – ESP32 example (PlatformIO project, see its [README](did-iot-firmware/README.md) for build/flash instructions and an architecture diagram)
- **performance-analysis** – latency scripts
- **security-analysis** – security tests (includes `run_threat_model_tests.sh`)

Publication: 
DIDAuth-IoTFW: Decentralized firmware authentication for smart home IoT devices using verifiable credentials
Internet of Things,
Volume 34,
2025,
101788,
ISSN 2542-6605,
https://doi.org/10.1016/j.iot.2025.101788. (https://www.sciencedirect.com/science/article/pii/S2542660525003026)

Abstract: Rapid proliferation of smart home IoT devices has intensified the demand for secure, scalable, and autonomous firmware authentication mechanisms. Traditional centralized solutions face challenges related to privacy concerns, limited scalability, and vulnerability to single point of failure. In this paper, we propose DIDAuth-IoTFW, a novel decentralized identity and firmware authentication framework that uniquely integrates Ethereum Layer-2 Arbitrum, InterPlanetary File System (IPFS), and W3C-compliant Decentralized Identifiers (DIDs) and Verifiable Credentials (VCs). DIDAuth-IoTFW provides a complete firmware authentication life cycle, from decentralized identity registration to real-time, on-chain verifiable revocation. While enabling autonomous, cryptographic verification directly on resource-constrained IoT devices and ensuring reliable performance even when gateways are compromised or unavailable. Our proof-of-concept implementation on ESP32 and Raspberry Pi achieved complete resistance to replay, forgery, and revocation threats with verification consistently under 1.2 s. Compared to prior work, DIDAuth-IoTFW uniquely combines firmware–VC hash binding, contract binding that prevents cross-registry replay, and device-side enforcement resilient to gateway compromise. Experimental results indicate a robust, privacy-preserving, and scalable alternative to centralized firmware-update pipelines for smart-home IoT.

Keywords: Decentralized identity; Distributed ledger technologies; Ethereum Layer-2; Arbitrum; Verifiable credentials; Information security; Communication systems; IPFS

MIT License
© 2025 Anushka Wijesundara
