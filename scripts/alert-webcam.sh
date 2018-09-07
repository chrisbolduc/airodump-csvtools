#!/bin/bash

# Snaps a webcam picture when a device approaches your laptop
# Filters: Delta > 5, -40 < power < -2

FILE_PREFIX="packets-01"
CAP_DIR="/mnt/ramdisk"
CSVCMD="/home/chris/code/ad-csvtools/csvtools -d 5 -e -p -40 -P -2 -b -to -w ${CAP_DIR}/approaching -k /home/chris/knownmacs.csv ${CAP_DIR}/${FILE_PREFIX}-old.csv -l ${CAP_DIR}/${FILE_PREFIX}.csv"
while [ 1 ]; do
  cp ${CAP_DIR}/${FILE_PREFIX}.csv ${CAP_DIR}/${FILE_PREFIX}-old.csv
  sleep 5
# note: add -m
  RES=`$CSVCMD`
  NOW=`date +"%Y-%m-%d-%H-%M-%S"`
 if [[ $RES ]]; then
    streamer -f jpeg -s1280x720 -o $NOW.jpeg -c /dev/video1
  echo $RES
 fi

#  /home/chris/code/ad-csvtools/csvtools -d 5 -e -p -60 -P -2 -b -to -w ${CAP_DIR}/approaching -k /home/chris/phones.csv ${CAP_DIR}/${FILE_PREFIX}-old.csv -l ${CAP_DIR}/${FILE_PREFIX}.csv
#  /home/chris/code/ad-csvtools/csvtools -e -p -40 -P -2 -b -w ${CAP_DIR}/near40 -k /home/chris/phones.csv ${CAP_DIR}/${FILE_PREFIX}.csv
#  /home/chris/code/ad-csvtools/csvtools -e -p -50 -P -2 -b -w ${CAP_DIR}/near50 -k /home/chris/phones.csv ${CAP_DIR}/${FILE_PREFIX}.csv
done
