#!/bin/zsh

# --- CONFIGURATION ---
INTERFACE="en0"
CREDENTIALS_FILE="$HOME/.nordvpn_auth"
VPN_DIR="$/Users/owenmcgrath/Library/Mobile Documents/com~apple~CloudDocs/Home/Personal/Scripts/vpns"
LOG_FILE="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Home/Personal/Scripts/trackthis.log"
LAST_USED_FILE="$HOME/.last_vpn_config.txt"
SPOOF_CMD="/opt/homebrew/bin/spoof"
HARDWARE_MAC_FILE="/var/lib/mac_spoof_hardware_address"

# Error handling
set -eE  # Exit on error, including in functions
trap 'cleanup_on_error $? $LINENO' ERR
trap 'cleanup_on_signal' SIGINT SIGTERM

# Track script state for cleanup
SCRIPT_STATE="starting"
WIFI_WAS_DISABLED=false
VPN_WAS_STARTED=false
PF_WAS_ENABLED=false

cleanup_on_error() {
  local exit_code=$1
  local line_number=$2
  log "❌ ERROR: Script failed with exit code $exit_code at line $line_number"
  cleanup_and_exit $exit_code
}

cleanup_on_signal() {
  log "🛑 Script interrupted by user - cleaning up..."
  cleanup_and_exit 130
}

cleanup_and_exit() {
  local exit_code=${1:-0}
  
  log "🧹 Starting cleanup process..."
  
  # Kill any OpenVPN processes we might have started
  if [[ "$VPN_WAS_STARTED" == true ]]; then
    log "Killing OpenVPN processes..."
    sudo killall openvpn 2>/dev/null && log "OpenVPN killed" || log "No OpenVPN process found"
  fi
  
  # Disable pf firewall if we enabled it
  if [[ "$PF_WAS_ENABLED" == true ]]; then
    log "Disabling pf firewall..."
    sudo pfctl -d 2>/dev/null && log "pf firewall disabled" || log "pf firewall was not enabled"
  fi
  
  # Re-enable WiFi if it was disabled
  if [[ "$WIFI_WAS_DISABLED" == true ]] || ! networksetup -getairportpower "$INTERFACE" | grep -q "On"; then
    log "Re-enabling WiFi on $INTERFACE..."
    networksetup -setairportpower "$INTERFACE" on
    sleep 3
    log "WiFi re-enabled"
  fi
  
  # Restore original MAC if we have it stored
  if [[ -f "$HARDWARE_MAC_FILE" ]] && [[ "$SCRIPT_STATE" != "starting" ]]; then
    ORIGINAL_HW_MAC=$(sudo cat "$HARDWARE_MAC_FILE" 2>/dev/null || echo "")
    if [[ -n "$ORIGINAL_HW_MAC" ]]; then
      CURRENT_MAC=$(get_mac)
      if [[ "$CURRENT_MAC" != "$ORIGINAL_HW_MAC" ]]; then
        log "Attempting to restore original MAC address: $ORIGINAL_HW_MAC"
        networksetup -setairportpower "$INTERFACE" off
        sleep 3
        # Try to restore original MAC (this might not work on all systems)
        sudo ifconfig "$INTERFACE" ether "$ORIGINAL_HW_MAC" 2>/dev/null || log "⚠️ Could not restore original MAC automatically"
        networksetup -setairportpower "$INTERFACE" on
        sleep 5
        NEW_MAC=$(get_mac)
        if [[ "$NEW_MAC" == "$ORIGINAL_HW_MAC" ]]; then
          log "✅ Original MAC address restored: $ORIGINAL_HW_MAC"
        else
          log "⚠️ MAC restoration may have failed. You may need to restart your network interface or reboot."
          log "   Original MAC was: $ORIGINAL_HW_MAC"
          log "   Current MAC is: $NEW_MAC"
        fi
      fi
    fi
  fi
  
  if [[ $exit_code -eq 130 ]]; then
    log "✅ Cleanup completed - script was cancelled by user"
  elif [[ $exit_code -eq 0 ]]; then
    log "✅ Cleanup completed - script finished normally"
  else
    log "✅ Cleanup completed - script exited with error code $exit_code"
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
  sudo pfctl -e
  PF_WAS_ENABLED=true
  log "✅ pf firewall enabled — all traffic forced through VPN."
}

get_mac() {
  # More robust MAC address detection
  ifconfig "$INTERFACE" 2>/dev/null | awk '/ether/ {print $2}' || echo ""
}

store_hardware_mac() {
  if [[ ! -f "$HARDWARE_MAC_FILE" ]]; then
    local current_mac=$(get_mac)
    if [[ -n "$current_mac" ]]; then
      sudo mkdir -p "$(dirname "$HARDWARE_MAC_FILE")"
      echo "$current_mac" | sudo tee "$HARDWARE_MAC_FILE" >/dev/null
      sudo chmod 600 "$HARDWARE_MAC_FILE"
      log "Stored hardware MAC: $current_mac"
    else
      log "⚠️ WARNING: Could not detect MAC address to store"
    fi
  fi
}

disable_wifi() {
  log "Disabling Wi-Fi on $INTERFACE..."
  WIFI_WAS_DISABLED=true
  networksetup -setairportpower "$INTERFACE" off
  log "Waiting 30 seconds for WiFi to disable"
  sleep 30
}

enable_wifi() {
  log "Enabling Wi-Fi on $INTERFACE..."
  networksetup -setairportpower "$INTERFACE" on
  WIFI_WAS_DISABLED=false
  log "Waiting 30 seconds for WiFi to enable"
  sleep 30
}

# Native MAC spoofing function that should work better
spoof_mac_native() {
  log "INFO: Native Mac spoofing started"
  store_hardware_mac
  disable_wifi
  
  ORIGINAL_MAC=$(get_mac)
  log "Original MAC: $ORIGINAL_MAC"
  
  if [[ -z "$ORIGINAL_MAC" ]]; then
    log "❌ ERROR: Could not detect current MAC address"
    enable_wifi
    return 1
  fi
  
  # Generate a random MAC address
  NEW_MAC=$(printf '%02x:%02x:%02x:%02x:%02x:%02x\n' \
    $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) \
    $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)))
  
  # Ensure the first octet is even (unicast) and locally administered
  FIRST_OCTET=$(printf '%02x' $(( (0x${NEW_MAC:0:2} & 0xFE) | 0x02 )))
  NEW_MAC="${FIRST_OCTET}${NEW_MAC:2}"
  
  log "Attempting to set MAC to: $NEW_MAC"
  
  # Try to set the new MAC address
  if sudo ifconfig "$INTERFACE" ether "$NEW_MAC" 2>/dev/null; then
    log "MAC address set successfully"
  else
    log "❌ ERROR: Failed to set MAC address using ifconfig"
    enable_wifi
    return 1
  fi
  
  enable_wifi
  
  ACTUAL_MAC=$(get_mac) 
  if [[ -z "$ACTUAL_MAC" ]]; then
    log "❌ ERROR: Could not detect MAC address after spoofing"
    return 1
  elif [[ "$ORIGINAL_MAC" == "$ACTUAL_MAC" ]]; then
    log "❌ ERROR: MAC did not change (still $ACTUAL_MAC)"
    return 1
  else
    log "✅ MAC spoofed successfully: $ORIGINAL_MAC → $ACTUAL_MAC"
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

# Enhanced VPN verification for macOS
verify_vpn_connection() {
  local max_wait=60
  local wait_time=0
  
  log "Verifying VPN connection..."
  
  while [[ $wait_time -lt $max_wait ]]; do
    # Check for VPN interface
    if ifconfig | grep -q "utun\|tun"; then
      # Also check that traffic is actually routing through VPN
      if route -n get default 2>/dev/null | grep -q "interface.*utun\|interface.*tun"; then
        log "✅ VPN interface and routing detected"
        return 0
      fi
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

# Try native MAC spoofing first, fall back if it fails
set +e
log "Attempting native MAC spoofing..."
if ! spoof_mac_native; then
  log "⚠️ WARNING: Native MAC spoofing failed"
  log "💡 TIP: MAC spoofing often requires a reboot to work properly on modern macOS"
  log "⚠️ Continuing without MAC spoofing..."
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

SCRIPT_STATE="killing_existing_vpn"

log "INFO: Killing current OpenVPN session..."
sudo killall openvpn 2>/dev/null && log "INFO: OpenVPN killed." || log "INFO: No OpenVPN process found."

# Wait for processes to fully terminate
sleep 3

SCRIPT_STATE="selecting_vpn_config"
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

# Start OpenVPN with better error handling and routing
if ! sudo openvpn --config "$SELECTED_OVPN" --auth-user-pass "$CREDENTIALS_FILE" --daemon --route-noexec; then
  log "❌ ERROR: Failed to start OpenVPN"
  exit 1
fi

VPN_WAS_STARTED=true
SCRIPT_STATE="verifying_vpn"

# Wait a bit longer for VPN to establish
log "Waiting 15 seconds for VPN to establish..."
sleep 15

# Verify VPN connection is established
if ! verify_vpn_connection; then
  log "❌ ERROR: VPN connection verification failed"
  sudo killall openvpn 2>/dev/null
  exit 1
fi

# Add default route through VPN
log "Setting up routing through VPN..."
VPN_INTERFACE=$(ifconfig | grep -E "^(utun|tun)" | cut -d: -f1 | head -1)
if [[ -n "$VPN_INTERFACE" ]]; then
  log "Found VPN interface: $VPN_INTERFACE"
  # Remove existing default route and add through VPN
  sudo route delete default &>/dev/null || true
  VPN_GATEWAY=$(route -n get default 2>/dev/null | grep gateway | awk '{print $2}' | head -1)
  if [[ -n "$VPN_GATEWAY" ]]; then
    sudo route add default "$VPN_GATEWAY" &>/dev/null || log "Could not set VPN as default route"
  fi
else
  log "⚠️ WARNING: Could not find VPN interface"
fi

SCRIPT_STATE="checking_new_ip"

# Wait for routing to take effect
log "Waiting 10 seconds for routing to stabilize..."
sleep 10

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
  log "This could be due to:"
  log "  - VPN server connectivity issues"
  log "  - Routing not properly configured"
  log "  - DNS leaks"
  log "Let's check VPN status..."
  ifconfig | grep -A5 -B5 "utun\|tun" || log "No VPN interfaces found"
  sudo killall openvpn 2>/dev/null
  exit 1
else
  SCRIPT_STATE="enabling_firewall"
  enable_pf
  SCRIPT_STATE="completed"
  log "✅ VPN connection successful!"
  log "INFO: IP changed: $ORIGINAL_IP → $NEW_IP"
  log "Welcome to $NEW_LOC!"
  echo "$SELECTED_OVPN" > "$LAST_USED_FILE"
  log "🎉 Script completed successfully!"
  log ""
  log "💡 To cancel and restore everything to normal, press Ctrl+C"
  
  # Keep the script running so user can cancel
  log "VPN is active. Press Ctrl+C to disconnect and cleanup."
  while true; do
    sleep 30
    # Optionally check if VPN is still connected
    if ! pgrep openvpn >/dev/null; then
      log "⚠️ OpenVPN process died unexpectedly"
      break
    fi
  done
fi