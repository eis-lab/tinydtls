#!bin/sh

sudo make TARGET=openmote-cc2538 PORT=/dev/ttyUSB1 serial_dump sensor.upload login
