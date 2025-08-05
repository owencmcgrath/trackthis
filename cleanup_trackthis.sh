#!/bin/zsh

# Manual cleanup script for trackthis.sh
# Run this if you need to manually restore your system to normal state

LOG_FILE="$HOME/Library/Mobile Documents/com~apple~CloudDocs/Home/Personal/Scripts/trackthis.log"
INTERFACE="en0"
HARDWARE_MAC_FILE="/var/lib/mac_spoof_hardware_address"

log() {
  echo "[$(date)] CLEANUP: $1" | tee -a "$LOG_FILE"
}

log "🧹 Manual cleanup started..."

echo "🛑 This script will restore your system to normal state by:"
echo "   1. Killing any OpenVPN processes"
echo "   2. Disabling pf firewall"
echo "   3. Re-enabling WiFi"
echo "   4. Optionally restoring original MAC address"
echo ""
read -p "Continue? (y/N): " confirm

if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Cleanup cancelled."
  exit 0
fi

# Kill OpenVPN
log "Killing OpenVPN processes..."
if sudo killall openvpn 2>/dev/null; then
  log "✅ OpenVPN processes killed"
else
  log "ℹ️ No OpenVPN processes found"
fi

# Disable pf firewall
log "Disabling pf firewall..."
if sudo pfctl -d 2>/dev/null; then
  log "✅ pf firewall disabled"
else
  log "ℹ️ pf firewall was not enabled"
fi

# Re-enable WiFi
log "Re-enabling WiFi..."
if networksetup -getairportpower "$INTERFACE" | grep -q "Off"; then
  networksetup -setairportpower "$INTERFACE" on
  sleep 3
  log "✅ WiFi re-enabled"
else
  log "ℹ️ WiFi was already enabled"
fi

# Check if we should restore MAC
if [[ -f "$HARDWARE_MAC_FILE" ]]; then
  ORIGINAL_MAC=$(sudo cat "$HARDWARE_MAC_FILE" 2>/dev/null || echo "")
  CURRENT_MAC=$(ifconfig "$INTERFACE" | grep ether | awk '{print $2}')
  
  if [[ -n "$ORIGINAL_MAC" && "$ORIGINAL_MAC" != "$CURRENT_MAC" ]]; then
    echo ""
    echo "Original MAC address found: $ORIGINAL_MAC"
    echo "Current MAC address: $CURRENT_MAC"
    read -p "Restore original MAC address? (y/N): " restore_mac
    
    if [[ "$restore_mac" == "y" || "$restore_mac" == "Y" ]]; then
      log "Attempting to restore original MAC..."
      networksetup -setairportpower "$INTERFACE" off
      sleep 3
      
      # Try different methods to restore MAC
      if sudo ifconfig "$INTERFACE" ether "$ORIGINAL_MAC" 2>/dev/null; then
        log "MAC restoration command executed"
      else
        log "⚠️ ifconfig method failed, trying alternative..."
        # Alternative method using spoof if available
        if command -v spoof >/dev/null 2>&1; then
          sudo spoof set "$INTERFACE" "$ORIGINAL_MAC" 2>/dev/null || log "⚠️ spoof method also failed"
        fi
      fi
      
      networksetup -setairportpower "$INTERFACE" on
      sleep 5
      
      NEW_MAC=$(ifconfig "$INTERFACE" | grep ether | awk '{print $2}')
      if [[ "$NEW_MAC" == "$ORIGINAL_MAC" ]]; then
        log "✅ Original MAC address restored successfully"
      else
        log "⚠️ MAC restoration may have failed. Current: $NEW_MAC, Expected: $ORIGINAL_MAC"
        log "   You may need to reboot to fully restore the original MAC address"
      fi
    fi
  else
    log "ℹ️ MAC address restoration not needed"
  fi
fi

# Check current IP
log "Checking current IP..."
if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
  if IP_INFO=$(curl --connect-timeout 10 -s http://ip-api.com/json 2>/dev/null); then
    CURRENT_IP=$(echo "$IP_INFO" | jq -r '.query // "unknown"')
    CURRENT_LOC=$(echo "$IP_INFO" | jq -r '"\(.city // "unknown"), \(.country // "unknown")"')
    log "Current IP: $CURRENT_IP ($CURRENT_LOC)"
  fi
fi

echo ""
log "✅ Cleanup completed!"
echo "Your system should now be restored to normal state."
echo "If you're still having issues, try restarting your network interface:"
echo "  sudo ifconfig $INTERFACE down && sudo ifconfig $INTERFACE up"
echo "Or reboot your system if necessary."
