#this script to automate the connection and defining the network interface and start the monitoring mode 

#!/bin/bash
sudo iw dev wlan0 interface add wlan0mon type monitor
sudo ip link set wlan0 name wlan0mon
sudo ip link set wlan0mon up
sudo airmon-ng check kill
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
sudo ip link set wlan0mon up
iwconfig
