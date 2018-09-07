#!/bin/bash

FILE="packets-01"
CSVPATH="/mnt/ramdisk"
OUTPUT="near50"

/home/chris/code/ad-csvtools/csvtools -p -50 -P -2 -T -e -b -to -w ${CSVPATH}/${OUTPUT} -m -k /home/chris/knownmacs.csv ${CSVPATH}/${FILE}.csv

