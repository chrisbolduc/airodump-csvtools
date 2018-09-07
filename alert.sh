#!/bin/bash
# Alerts you when a device increases in signal strength by 5 or more (-d 5)
# Such as a device approaching you would
# Filters devices with signal less than -70 or greater than -2

FILE="packets-01"
CAPPATH="/tmp"

while [ 1 ]; do
  ./csvtools -d 5 -p -70 -P -2 -b -to -w ${CAPPATH}/test -k devices.csv ${CAPPATH}/${FILE}-old.csv -l ${CAPPATH}/${FILE}.csv
  cp ${CAPPATH}/${FILE}.csv ${CAPPATH}/${FILE}-old.csv
  sleep 5
done
