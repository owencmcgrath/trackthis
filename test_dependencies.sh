#!/bin/zsh

# Simple dependency test script
echo "🔍 Checking dependencies for trackthis.sh..."

SPOOF_CMD="/opt/homebrew/bin/spoof"
CREDENTIALS_FILE="$HOME/.nordvpn_auth"

# Check jq
if command -v jq >/dev/null 2>&1; then
    echo "✅ jq is installed"
else
    echo "❌ jq is missing - install with: brew install jq"
fi

# Check openvpn
if command -v openvpn >/dev/null 2>&1; then
    echo "✅ openvpn is installed"
else
    echo "❌ openvpn is missing - install with: brew install openvpn"
fi

# Check spoof
if [[ -x "$SPOOF_CMD" ]]; then
    echo "✅ spoof is installed at $SPOOF_CMD"
else
    echo "❌ spoof is missing - install with: npm install -g spoof"
fi

# Check curl
if command -v curl >/dev/null 2>&1; then
    echo "✅ curl is installed"
else
    echo "❌ curl is missing"
fi

# Check credentials file
if [[ -f "$CREDENTIALS_FILE" ]]; then
    echo "✅ Credentials file exists at $CREDENTIALS_FILE"
else
    echo "❌ Credentials file missing at $CREDENTIALS_FILE"
    echo "   Create this file with your NordVPN username on line 1 and password on line 2"
fi

echo ""
echo "📝 To fix missing dependencies:"
echo "   brew install jq openvpn"
echo "   npm install -g spoof"
echo ""
echo "📝 To create credentials file:"
echo "   echo 'your_username' > ~/.nordvpn_auth"
echo "   echo 'your_password' >> ~/.nordvpn_auth"
echo "   chmod 600 ~/.nordvpn_auth"
