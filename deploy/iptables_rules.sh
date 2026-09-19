#!/usr/bin/env bash
set -euo pipefail

iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 2121 -j ACCEPT
iptables -A INPUT -p tcp --dport 2525 -j ACCEPT
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -s 127.0.0.1 -j ACCEPT
