#!/bin/bash

if [ -z "$SS_PASSWORD" ]; then
    echo "Error: SS_PASSWORD environment variable is not set."
    exit 1
fi

# Check if a screen session named "shadowsocks" is already running
if screen -list | grep -q "shadowsocks"; then
    echo "A screen session named 'shadowsocks' is already running."
    echo "Joining the existing session..."
    screen -r shadowsocks
    exit 0
fi

# Start the Shadowsocks server in a new screen session
# screen -dmS shadowsocks ~/go/bin/go-shadowsocks2 -s "ss://AEAD_CHACHA20_POLY1305:$SS_PASSWORD@:8488" -verbose

screen -dmS shadowsocks ~/go/bin/go-shadowsocks2 -s "ss://AEAD_AES_256_GCM:$SS_PASSWORD@:8488" -verbose

echo "Shadowsocks server started in a new screen session named 'shadowsocks'."
# echo "To view or join the output, run: screen -r shadowsocks"
screen -x shadowsocks
