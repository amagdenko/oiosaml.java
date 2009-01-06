#!/bin/sh

tail -500 $1 | awk -F, '{ t+=$2} END { print t/NR }'
