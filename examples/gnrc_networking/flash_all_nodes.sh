#!/bin/bash

board=samr21-xpro

serials=$(make BOARD=$board list-ttys |grep -o "serial: [^ ,]\+'" |sed -e "s/serial: //g") 

#SERIAL='ATML2127031800001861' BOARD=samr21-xpro make flash
#SERIAL='ATML2127031800002115' BOARD=samr21-xpro make flash
#SERIAL='ATML2127031800002158' BOARD=samr21-xpro make flash
#SERIAL='ATML2127031800002161' BOARD=samr21-xpro make flash
#SERIAL='ATML2127031800002171' BOARD=samr21-xpro make flash

for serial in $serials; do
    eval SERIAL=$serial BOARD=$board make flash
done

