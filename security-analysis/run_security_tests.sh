#!/bin/bash

VENDOR_URL="${VENDOR_URL:-https://did.wijesundara.com}"
GATEWAY_URL="${GATEWAY_URL:-http://homegateway.local:8000}"
ITERATIONS="${ITERATIONS:-100}"
LOG_FILE="security_log.csv"

if [ ! -f "$LOG_FILE" ]; then
  echo "\"timestamp\",\"iteration\",\"scenario\",\"result\",\"latency\",\"http_code\",\"status\"" > "$LOG_FILE"
fi

for ((i=1;i<=ITERATIONS;i++)); do
  TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
  VENDOR="SecVendor_${i}_$(date +%s)"
  FIRMWARE=$(head -c 24 /dev/urandom | base64)

  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o reg.json -X POST "$VENDOR_URL/did/register" \
    -H "Content-Type: application/json" -d "{\"name\":\"$VENDOR\"}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  API_KEY=$(jq -r .api_key reg.json 2>/dev/null)
  STATUS=$(jq -r .status reg.json 2>/dev/null)
  if [[ -z "$API_KEY" || "$API_KEY" == "null" ]]; then
    echo "\"$TIMESTAMP\",\"$i\",\"register_did\",\"failure\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"
    rm -f reg.json
    continue
  else
    echo "\"$TIMESTAMP\",\"$i\",\"register_did\",\"success\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"
  fi

  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o vc.json -X POST "$VENDOR_URL/vc/issue" -H "Content-Type: application/json" -H "x-api-key: $API_KEY" \
    -d "{\"did_name\":\"$VENDOR\",\"firmware_version\":\"1.0.0\",\"device_model\":\"ESP32\",\"firmware_content\":\"$FIRMWARE\"}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  VC=$(jq -c .vc vc.json 2>/dev/null)
  STATUS=$(jq -r .status vc.json 2>/dev/null)
  if [[ -z "$VC" || "$VC" == "null" ]]; then
    echo "\"$TIMESTAMP\",\"$i\",\"issue_vc\",\"failure\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"
    rm -f vc.json reg.json
    continue
  else
    echo "\"$TIMESTAMP\",\"$i\",\"issue_vc\",\"success\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"
  fi

  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o vp.json -X POST "$VENDOR_URL/vp/create" -H "Content-Type: application/json" -H "x-api-key: $API_KEY" \
    -d "{\"did_name\":\"$VENDOR\",\"firmware_version\":\"1.0.0\"}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  VP=$(jq -c .vp vp.json 2>/dev/null)
  STATUS=$(jq -r .status vp.json 2>/dev/null)
  if [[ -z "$VP" || "$VP" == "null" ]]; then
    echo "\"$TIMESTAMP\",\"$i\",\"create_vp\",\"failure\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"
    rm -f reg.json vc.json vp.json
    continue
  else
    echo "\"$TIMESTAMP\",\"$i\",\"create_vp\",\"success\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"
  fi

  sleep 0.5

  for attempt in 1 2; do
    START=$(date +%s.%N)
    HTTP=$(curl -s -w "%{http_code}" -o verify.json -X POST "$GATEWAY_URL/vp/verify" \
      -H "Content-Type: application/json" -d "{\"vp\":$VP}")
    END=$(date +%s.%N)
    LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
    STATUS=$(jq -r .status verify.json 2>/dev/null)
    if [[ "$HTTP" == "500" && "$attempt" == "1" ]]; then
      sleep 1
      continue
    fi
    if [[ "$STATUS" == *"Verified"* || "$STATUS" == *"Valid"* || "$STATUS" == *"Success"* ]]; then
      echo "\"$TIMESTAMP\",\"$i\",\"valid_vc\",\"success\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"
    else
      echo "\"$TIMESTAMP\",\"$i\",\"valid_vc\",\"failure\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"
    fi
    break
  done

  TAMP_VC=$(echo "$VC" | jq '.proof.jws += "tamper"')
  TAMP_VP=$(echo "$VP" | jq --argjson v "$TAMP_VC" '.verifiableCredential[0]=$v')
  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o tamp.json -X POST "$GATEWAY_URL/vp/verify" -H "Content-Type: application/json" -d "{\"vp\":$TAMP_VP}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  STATUS=$(jq -r .status tamp.json 2>/dev/null)
  [[ "$STATUS" == *"Invalid"* || "$STATUS" == *"Tampered"* || "$STATUS" == *"❌"* ]] && RES="success" || RES="failure"
  echo "\"$TIMESTAMP\",\"$i\",\"tampered_vc\",\"$RES\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"

  curl -s -X POST "$VENDOR_URL/vc/revoke" -H "Content-Type: application/json" -H "x-api-key: $API_KEY" \
    -d "{\"did_name\":\"$VENDOR\",\"vc_id\":\"vc:$VENDOR:1.0.0\"}" >/dev/null
  START=$(date +%s.%N)
  HTTP=$(curl -s -w "%{http_code}" -o replay.json -X POST "$GATEWAY_URL/vp/verify" \
    -H "Content-Type: application/json" -d "{\"vp\":$VP}")
  END=$(date +%s.%N)
  LAT=$(awk -v s=$START -v e=$END 'BEGIN{printf "%.6f", e-s}')
  STATUS=$(jq -r .status replay.json 2>/dev/null)
  [[ "$STATUS" == *"Revoked"* || "$STATUS" == *"Rejected"* ]] && RES="success" || RES="failure"
  echo "\"$TIMESTAMP\",\"$i\",\"replay_revoked\",\"$RES\",\"$LAT\",\"$HTTP\",\"$STATUS\"" >> "$LOG_FILE"

  rm -f reg.json vc.json vp.json verify.json tamp.json replay.json

done

echo "✅ Results written to $LOG_FILE"
