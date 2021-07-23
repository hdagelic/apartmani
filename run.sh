#!/bin/bash

pkill -f tele232
>log.txt

source env3/bin/activate
python3 api.py tele232 > log.txt 2> log.txt &
sleep 2
tail -30 log.txt

echo
echo "Use tail -f log.txt to monitor the log, ./stop.sh to stop the dev server."
