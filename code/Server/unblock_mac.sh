#!/usr/bin/env bash
MAC=${1?Error: no mac given}
sudo iptables -D INPUT -m mac --mac-source $MAC -j DROP
