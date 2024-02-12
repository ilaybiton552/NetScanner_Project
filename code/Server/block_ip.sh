#!/usr/bin/env bash
IP=${1?Error: no ip given}
sudo iptables -A INPUT -s $IP -j DROP
