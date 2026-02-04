#!/bin/bash

# This script helps manage the shadowsocks systemd service

case "${1:-status}" in
    start)
        sudo systemctl start shadowsocks
        sudo systemctl status shadowsocks
        ;;
    stop)
        sudo systemctl stop shadowsocks
        ;;
    restart)
        sudo systemctl restart shadowsocks
        ;;
    status)
        sudo systemctl status shadowsocks
        ;;
    logs)
        sudo journalctl -u shadowsocks -f
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs}"
        exit 1
        ;;
esac