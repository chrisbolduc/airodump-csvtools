#!/bin/bash
COUNTER=0
COUNTER2=0
OUTPATH="/mnt/ramdisk"
NOW=$(date +"%Y-%m-%d-%H-%M")
cp /home/chris/alert2-printed.csv $OUTPATH
while [ 1 ]; do
  # Runs every 5s, so 12*60*24=17280 or once per day
  if [ $COUNTER -eq 17280 ]; then
    COUNTER=0
    cp /mnt/ramdisk/alert2-printed.csv /home/chris/apinfo/backup/alert2-printed-${NOW}.csv
  fi
  COUNTER=$((COUNTER+1))
  # Every 5 min
  if [ $COUNTER2 -eq 60 ]; then
    COUNTER=0
    cp /mnt/ramdisk/alert2-printed.csv /home/chris/
  fi
  COUNTER2=$((COUNTER2+1))
  cp $OUTPATH/packets-01.csv $OUTPATH/packets-01-old2.csv
  sleep 5
  rm $OUTPATH/alert2.log
  cat $OUTPATH/alert2.txt >> $OUTPATH/alert2.history
  ./alert2-run.sh >> $OUTPATH/alert2.log 2>> $OUTPATH/alert2.log
#  ./alert2a-run.sh >> $OUTPATH/alert2a.log 2>> $OUTPATH/alert2a.err
#  ./near50-run.sh > $OUTPATH/near50.log 2>> $OUTPATH/near50.err
#  ./near70-run.sh > $OUTPATH/near70.log 2>> $OUTPATH/near70.err
done
