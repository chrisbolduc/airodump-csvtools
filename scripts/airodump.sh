#!/bin/bash

while [ 1 ]; do
	airodump-ng mon0 --output-format=csv -w /mnt/ramdisk/packets
	NOW=$(date +"%Y-%m-%d-%H-%M")
	cp /mnt/ramdisk/packets-01.csv /home/pi/apinfo/chapman/${NOW}.csv
	cp /mnt/ramdisk/alert2-printed.csv /home/pi/apinfo/chapman/alert2-printed.csv
	cp /mnt/ramdisk/alert3-printed.csv /home/pi/apinfo/chapman/alert3-printed.csv
	rm /mnt/ramdisk/packets-01.csv
done
