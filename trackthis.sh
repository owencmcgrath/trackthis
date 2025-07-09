#!/bin/zsh

INTERFACE="en0"
CREDENTIALS_FILE="$HOME/.nordvpn_auth"
VPN_DIR="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Home/Personal/Scripts/vpns"
LOG_FILE="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Home/Personal/Scripts/trackthis.log"
LAST_USED_FILE="$HOME/.last_vpn_config.txt"


log() {
  echo "[$(date)] $1" | tee -a "$LOG_FILE"
}

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