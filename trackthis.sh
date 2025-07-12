#!/bin/zsh

# --- CONFIGURATION ---
INTERFACE="en0"
CREDENTIALS_FILE="$HOME/.nordvpn_auth"
VPN_DIR="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Home/Personal/Scripts/vpns"
LOG_FILE="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Home/Personal/Scripts/trackthis.log"
LAST_USED_FILE="$HOME/.last_vpn_config.txt"
SPOOF_CMD="/opt/homebrew/bin/spoof"
HARDWARE_MAC_FILE="/var/lib/mac_spoof_hardware_address"

log() {
  echo "[$(date)] $1" | tee -a "$LOG_FILE"
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
  SPOOF_OUTPUT=$(sudo "$SPOOF_CMD" randomize "$INTERFACE" 2>&1)
  log "sleeping for fifteen before enabling Wi-Fi" 
  sleep 15
  enable_wifi
  log "sleeping for fifteen"
  sleep 15 
  NEW_MAC=$(get_mac) 
  if [ "$ORIGINAL_MAC" = "$NEW_MAC" ]; then
    log "❌ ERROR: MAC did not change."
  else
    log "✅ MAC spoofed to: $NEW_MAC"
  fi
}

spoof_mac

log "sleeping for fifteen"
sleep 15

ORIGINAL_IP=$(curl -s http://ip-api.com/json | jq -r .query)
ORIGINAL_LOC=$(curl -s http://ip-api.com/json | jq -r '"\(.city), \(.country)"')
log "INFO: Original IP: $ORIGINAL_IP"
log "You are leaving $ORIGINAL_LOC"

log "INFO: Killing current OpenVPN session..."
sudo killall openvpn 2>/dev/null && log "INFO: OpenVPN killed." || log "INFO: No OpenVPN process found."

log "INFO: Selecting new VPN config..."

LAST_USED_OVPN=""
if [ -s "$LAST_USED_FILE" ]; then
  read -r LAST_USED_OVPN < "$LAST_USED_FILE"
  if [ ! -f "$LAST_USED_OVPN" ]; then
    LAST_USED_OVPN=""
  fi
fi

ALL_OVPN_FILES=("${(@f)$(find "$VPN_DIR" -type f -name "*.ovpn")}")
if [ ${#ALL_OVPN_FILES[@]} -eq 0 ]; then
  log "❌ ERROR: No .ovpn files found in $VPN_DIR"
  exit 1
fi

if [ -n "$LAST_USED_OVPN" ]; then
  VPN_CANDIDATES=()
  for f in "${ALL_OVPN_FILES[@]}"; do
    [[ "$f" != "$LAST_USED_OVPN" ]] && VPN_CANDIDATES+=("$f")
  done
else
  VPN_CANDIDATES=("${ALL_OVPN_FILES[@]}")
fi

if [ ${#VPN_CANDIDATES[@]} -eq 0 ]; then
  log "Only one config available. Reusing: $LAST_USED_OVPN"
  SELECTED_OVPN="$LAST_USED_OVPN"
else
  SELECTED_OVPN=$(printf "%s\n" "${VPN_CANDIDATES[@]}" | sort -R | head -n 1)
fi

if [ -z "$SELECTED_OVPN" ] || [ ! -f "$SELECTED_OVPN" ]; then
  log "❌ ERROR: No valid .ovpn config selected."
exit 1
fi

log "INFO: Starting a new OpenVPN session..."
sudo openvpn --config "$SELECTED_OVPN" --auth-user-pass "$CREDENTIALS_FILE" --daemon
sleep 15

NEW_IP=$(curl -s http://ip-api.com/json | jq -r .query)
NEW_LOC=$(curl -s http://ip-api.com/json | jq -r '"\(.city), \(.country)"')

if [ "$NEW_IP" = "$ORIGINAL_IP" ]; then
  log "⚠️ WARNING: IP did not change. VPN might have failed."
else
  log "INFO: IP changed successfully!"
  log "INFO: New IP: $NEW_IP"
  log "Welcome to $NEW_LOC"
  echo "$SELECTED_OVPN" > "$LAST_USED_FILE"
fi