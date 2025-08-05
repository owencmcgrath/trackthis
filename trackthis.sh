#!/bin/zsh

# --- CONFIGURATION ---
INTERFACE="en0"
CREDENTIALS_FILE="$HOME/.nordvpn_auth"
VPN_DIR="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Home/Personal/Scripts/vpns"
LOG_FILE="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Home/Personal/Scripts/trackthis.log"
LAST_USED_FILE="$HOME/.last_vpn_config.txt"
SPOOF_CMD="/opt/homebrew/bin/spoof"
HARDWARE_MAC_FILE="/var/lib/mac_spoof_hardware_address"

# Error handling
set -eE  # Exit on error, including in functions
trap 'cleanup_on_error $? $LINENO' ERR

cleanup_on_error() {
  local exit_code=$1
  local line_number=$2
  log "❌ ERROR: Script failed with exit code $exit_code at line $line_number"
  # Re-enable WiFi if it was disabled
  if ! networksetup -getairportpower "$INTERFACE" | grep -q "On"; then
    log "Re-enabling WiFi due to error..."
    networksetup -setairportpower "$INTERFACE" on
  fi
  exit $exit_code
}

log() {
  echo "[$(date)] $1" | tee -a "$LOG_FILE"
}

# Check dependencies
check_dependencies() {
  local missing_deps=()
  
  if ! command -v jq >/dev/null 2>&1; then
    missing_deps+=("jq")
  fi
  
  if ! command -v openvpn >/dev/null 2>&1; then
    missing_deps+=("openvpn")
  fi
  
  if [[ ! -x "$SPOOF_CMD" ]]; then
    missing_deps+=("spoof (at $SPOOF_CMD)")
  fi
  
  if ! command -v curl >/dev/null 2>&1; then
    missing_deps+=("curl")
  fi
  
  if [[ ! -f "$CREDENTIALS_FILE" ]]; then
    log "❌ ERROR: Credentials file not found at $CREDENTIALS_FILE"
    exit 1
  fi
  
  if [[ ${#missing_deps[@]} -gt 0 ]]; then
    log "❌ ERROR: Missing dependencies: ${missing_deps[*]}"
    log "Please install missing dependencies and try again."
    exit 1
  fi
  
  log "✅ All dependencies check passed"
}

# Verify network connectivity with timeout
check_network() {
  if ! curl --connect-timeout 10 -s http://ip-api.com/json >/dev/null; then
    log "❌ ERROR: No internet connectivity"
    return 1
  fi
  return 0
}

PF_CONF="/etc/pf.anon.conf"

enable_pf() {
  echo "block all" | sudo tee "$PF_CONF" > /dev/null
  echo "pass quick on utun0 all" | sudo tee -a "$PF_CONF" > /dev/null
  echo "pass quick on lo0 all" | sudo tee -a "$PF_CONF" > /dev/null
  sudo pfctl -f "$PF_CONF"
  sudo pfctl -e -f "$PF_CONF"
  log "✅ pf firewall enabled — all traffic forced through VPN."
}

get_mac() {
  ifconfig "$INTERFACE" | grep ether | awk '{print $2}'
}

store_hardware_mac() {
  if [ ! -f "$HARDWARE_MAC_FILE" ]; then
    sudo mkdir -p "$(dirname "$HARDWARE_MAC_FILE")"
    echo "$(get_mac)" | sudo tee "$HARDWARE_MAC_FILE" >/dev/null
    sudo chmod 600 "$HARDWARE_MAC_FILE"
    log "Stored hardware MAC: $(cat "$HARDWARE_MAC_FILE")"
  fi
}

disable_wifi() {
  log "Disabling Wi-Fi on $INTERFACE..."
  networksetup -setairportpower "$INTERFACE" off
  log "sleeping for five"
  sleep 5
}

enable_wifi() {
  log "Enabling Wi-Fi on $INTERFACE..."
  networksetup -setairportpower "$INTERFACE" on
  log "sleeping for five"
  sleep 5
}

spoof_mac() {
  log "INFO: Mac spoofing started"
  store_hardware_mac
  disable_wifi
  ORIGINAL_MAC=$(get_mac)
  log "Original MAC: $ORIGINAL_MAC"
  
  # Capture and log spoof output
  if SPOOF_OUTPUT=$(sudo "$SPOOF_CMD" randomize "$INTERFACE" 2>&1); then
    log "Spoof command output: $SPOOF_OUTPUT"
  else
    log "❌ ERROR: MAC spoofing command failed: $SPOOF_OUTPUT"
    enable_wifi
    return 1
  fi
  
  log "Waiting 15 seconds before enabling Wi-Fi" 
  sleep 15
  enable_wifi
  log "Waiting 15 seconds for interface to stabilize"
  sleep 15 
  
  NEW_MAC=$(get_mac) 
  if [[ "$ORIGINAL_MAC" == "$NEW_MAC" ]]; then
    log "❌ ERROR: MAC did not change (still $NEW_MAC)"
    return 1
  else
    log "✅ MAC spoofed successfully: $ORIGINAL_MAC → $NEW_MAC"
    return 0
  fi
}

# Get IP with timeout and retry
get_ip_info() {
  local max_attempts=3
  local attempt=1
  
  while [[ $attempt -le $max_attempts ]]; do
    if IP_INFO=$(curl --connect-timeout 10 --max-time 15 -s http://ip-api.com/json 2>/dev/null); then
      echo "$IP_INFO"
      return 0
    fi
    log "Attempt $attempt failed to get IP info, retrying..."
    ((attempt++))
    sleep 5
  done
  
  log "❌ ERROR: Failed to get IP information after $max_attempts attempts"
  return 1
}

# Verify VPN connection is established
verify_vpn_connection() {
  local max_wait=60  # Maximum wait time in seconds
  local wait_time=0
  
  log "Verifying VPN connection..."
  
  while [[ $wait_time -lt $max_wait ]]; do
    if ip route | grep -q "utun0\|tun0"; then
      log "✅ VPN interface detected"
      return 0
    fi
    sleep 5
    ((wait_time += 5))
    log "Waiting for VPN connection... (${wait_time}s/${max_wait}s)"
  done
  
  log "❌ ERROR: VPN connection not established within ${max_wait} seconds"
  return 1
}

# Main execution starts here
log "🚀 Starting VPN rotation script"

# Check dependencies first
check_dependencies

# Check network connectivity
if ! check_network; then
  log "❌ ERROR: No network connectivity, cannot proceed"
  exit 1
fi

# Temporarily disable error exit for MAC spoofing
set +e
if ! spoof_mac; then
  log "⚠️ WARNING: MAC spoofing failed, continuing anyway..."
fi
set -e

log "Waiting 15 seconds for network to stabilize"
sleep 15

# Get original IP with improved error handling
if ! IP_INFO=$(get_ip_info); then
  log "❌ ERROR: Cannot determine original IP"
  exit 1
fi

ORIGINAL_IP=$(echo "$IP_INFO" | jq -r '.query // "unknown"')
ORIGINAL_LOC=$(echo "$IP_INFO" | jq -r '"\(.city // "unknown"), \(.country // "unknown")"')
log "INFO: Original IP: $ORIGINAL_IP"
log "You are leaving $ORIGINAL_LOC"

log "INFO: Killing current OpenVPN session..."
sudo killall openvpn 2>/dev/null && log "INFO: OpenVPN killed." || log "INFO: No OpenVPN process found."

# Wait for processes to fully terminate
sleep 3

log "INFO: Selecting new VPN config..."

LAST_USED_OVPN=""
if [[ -s "$LAST_USED_FILE" ]]; then
  read -r LAST_USED_OVPN < "$LAST_USED_FILE"
  if [[ ! -f "$LAST_USED_OVPN" ]]; then
    log "Previous config file no longer exists: $LAST_USED_OVPN"
    LAST_USED_OVPN=""
  fi
fi

ALL_OVPN_FILES=("${(@f)$(find "$VPN_DIR" -type f -name "*.ovpn")}")
if [[ ${#ALL_OVPN_FILES[@]} -eq 0 ]]; then
  log "❌ ERROR: No .ovpn files found in $VPN_DIR"
  exit 1
fi

if [[ -n "$LAST_USED_OVPN" ]]; then
  VPN_CANDIDATES=()
  for f in "${ALL_OVPN_FILES[@]}"; do
    [[ "$f" != "$LAST_USED_OVPN" ]] && VPN_CANDIDATES+=("$f")
  done
else
  VPN_CANDIDATES=("${ALL_OVPN_FILES[@]}")
fi

if [[ ${#VPN_CANDIDATES[@]} -eq 0 ]]; then
  log "Only one config available. Reusing: $LAST_USED_OVPN"
  SELECTED_OVPN="$LAST_USED_OVPN"
else
  SELECTED_OVPN=$(printf "%s\n" "${VPN_CANDIDATES[@]}" | sort -R | head -n 1)
fi

if [[ -z "$SELECTED_OVPN" ]] || [[ ! -f "$SELECTED_OVPN" ]]; then
  log "❌ ERROR: No valid .ovpn config selected."
  exit 1
fi

log "INFO: Selected VPN config: $(basename "$SELECTED_OVPN")"
log "INFO: Starting OpenVPN connection..."

# Start OpenVPN with better error handling
if ! sudo openvpn --config "$SELECTED_OVPN" --auth-user-pass "$CREDENTIALS_FILE" --daemon; then
  log "❌ ERROR: Failed to start OpenVPN"
  exit 1
fi

# Verify VPN connection is established
if ! verify_vpn_connection; then
  log "❌ ERROR: VPN connection verification failed"
  sudo killall openvpn 2>/dev/null
  exit 1
fi

# Get new IP information
log "Checking new IP address..."
if ! NEW_IP_INFO=$(get_ip_info); then
  log "❌ ERROR: Cannot determine new IP after VPN connection"
  sudo killall openvpn 2>/dev/null
  exit 1
fi

NEW_IP=$(echo "$NEW_IP_INFO" | jq -r '.query // "unknown"')
NEW_LOC=$(echo "$NEW_IP_INFO" | jq -r '"\(.city // "unknown"), \(.country // "unknown")"')

if [[ "$NEW_IP" == "$ORIGINAL_IP" ]] || [[ "$NEW_IP" == "unknown" ]]; then
  log "⚠️ WARNING: IP did not change or is unknown. VPN might have failed."
  log "Original IP: $ORIGINAL_IP, New IP: $NEW_IP"
  sudo killall openvpn 2>/dev/null
  exit 1
else
  enable_pf
  log "✅ VPN connection successful!"
  log "INFO: IP changed: $ORIGINAL_IP → $NEW_IP"
  log "Welcome to $NEW_LOC!"
  log "Your pf status is: $(sudo pfctl -s info)"
  echo "$SELECTED_OVPN" > "$LAST_USED_FILE"
  log "🎉 Script completed successfully!"
fi