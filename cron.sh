#!/bin/bash

cd "$(dirname "$0")"

source env3/bin/activate
python3 cron.py
