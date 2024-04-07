#!/usr/bin/env bash
IP=${1?Error: no ip given}
sudo iptables -D INPUT -s $IP -j DROP
