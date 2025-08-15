#!/bin/bash

VENDOR_URL="${VENDOR_URL:-https://did.wijesundara.com}"
GATEWAY_URL="${GATEWAY_URL:-http://homegateway.local:8000}"
ITERATIONS="${ITERATIONS:-5}"
LOG_FILE="threat_model_log.csv"

if [ ! -f "$LOG_FILE" ]; then
  echo "\"timestamp\",\"iteration\",\"scenario\",\"result\",\"latency\",\"http_code\",\"status\"" > "$LOG_FILE"
fi

for ((i=1;i<=ITERATIONS;i++)); do
  TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
  VENDOR="Threat_${i}_$(date +%s)"
  FIRMWARE=$(head -c 24 /dev/urandom | base64)

  # Register DID
  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o reg.json -X POST "$VENDOR_URL/did/register" \
    -H "Content-Type: application/json" -d "{\"name\":\"$VENDOR\"}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  API_KEY=$(jq -r .api_key reg.json 2>/dev/null)
  STATUS=$(jq -r .status reg.json 2>/dev/null)
  if [[ -z "$API_KEY" || "$API_KEY" == "null" ]]; then
    rm -f reg.json
    continue
  fi

  # Issue VC
  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o vc.json -X POST "$VENDOR_URL/vc/issue" -H "Content-Type: application/json" -H "x-api-key: $API_KEY" \
    -d "{\"did_name\":\"$VENDOR\",\"firmware_version\":\"1.0.0\",\"device_model\":\"ESP32\",\"firmware_content\":\"$FIRMWARE\"}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  VC=$(jq -c .vc vc.json 2>/dev/null)
  STATUS=$(jq -r .status vc.json 2>/dev/null)
  if [[ -z "$VC" || "$VC" == "null" ]]; then
    rm -f reg.json vc.json
    continue
  fi

  # Create VP
  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o vp.json -X POST "$VENDOR_URL/vp/create" -H "Content-Type: application/json" -H "x-api-key: $API_KEY" \
    -d "{\"did_name\":\"$VENDOR\",\"firmware_version\":\"1.0.0\"}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  VP=$(jq -c .vp vp.json 2>/dev/null)
  STATUS=$(jq -r .status vp.json 2>/dev/null)
  if [[ -z "$VP" || "$VP" == "null" ]]; then
    rm -f reg.json vc.json vp.json
    continue
  fi

  # Scenario A1: Credential Forgery
  TAMP_VC=$(echo "$VC" | jq '.issuer = "did:example:attacker"')
  TAMP_VP=$(echo "$VP" | jq --argjson v "$TAMP_VC" '.verifiableCredential[0]=$v')
  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o forgery.json -X POST "$GATEWAY_URL/vp/verify" -H "Content-Type: application/json" -d "{\"vp\":$TAMP_VP}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  STATUS=$(jq -r .status forgery.json 2>/dev/null)
  [[ "$STATUS" == *"Invalid"* || "$STATUS" == *"Tampered"* || "$STATUS" == *"❌"* ]] && RES="success" || RES="failure"
  echo "\"$TIMESTAMP\",\"$i\",\"credential_forgery\",\"$RES\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"

  # Scenario A2: Replay Attack
  curl -s -X POST "$VENDOR_URL/vc/revoke" -H "Content-Type: application/json" -H "x-api-key: $API_KEY" \
    -d "{\"did_name\":\"$VENDOR\",\"vc_id\":\"vc:$VENDOR:1.0.0\"}" >/dev/null
  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o replay.json -X POST "$GATEWAY_URL/vp/verify" -H "Content-Type: application/json" -d "{\"vp\":$VP}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  STATUS=$(jq -r .status replay.json 2>/dev/null)
  [[ "$STATUS" == *"Revoked"* || "$STATUS" == *"Rejected"* ]] && RES="success" || RES="failure"
  echo "\"$TIMESTAMP\",\"$i\",\"replay_attack\",\"$RES\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"

  # Scenario A3: Gateway Compromise
  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o device.json -X POST "$VENDOR_URL/vc/verify" -H "Content-Type: application/json" -d "{\"vc\":$TAMP_VC}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  STATUS=$(jq -r .status device.json 2>/dev/null)
  [[ "$STATUS" == *"Invalid"* || "$STATUS" == *"Tampered"* || "$STATUS" == *"❌"* ]] && RES="success" || RES="failure"
  echo "\"$TIMESTAMP\",\"$i\",\"gateway_compromise\",\"$RES\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"

  rm -f reg.json vc.json vp.json forgery.json replay.json device.json

done

echo "✅ Threat model results written to $LOG_FILE"
