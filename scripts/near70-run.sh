#!/bin/bash

FILE="packets-01"
CSVPATH="/mnt/ramdisk"
OUTPUT="near70"

/home/chris/code/ad-csvtools/csvtools -p -70 -P -2 -e -b -T -to -w ${CSVPATH}/${OUTPUT} -k /home/chris/knownmacs.csv -m ${CSVPATH}/${FILE}.csv

