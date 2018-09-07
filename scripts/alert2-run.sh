#!/bin/bash

#/home/chris/code/ad-csvtools/csvtools -u 10.212.36.27 4000 -d 10 -P -2 -e -t -T -b -to -w /mnt/ramdisk/alert2 -k /home/chris/phonescps.csv /mnt/ramdisk/packets-01-old2.csv -l /mnt/ramdisk/packets-01.csv
/home/chris/code/ad-csvtools/csvtools -vv -d 10 -P -2 -e -t -T -b -w /mnt/ramdisk/alert2 -k /home/chris/knownmacs.csv /mnt/ramdisk/packets-01-old2.csv -l /mnt/ramdisk/packets-01.csv
