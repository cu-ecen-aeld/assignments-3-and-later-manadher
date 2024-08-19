#!/bin/sh

if [ "$#" -ne 2 ] ; then
  echo "Usage : $0 <file> <str>"
  exit 1
fi
mkdir -p "$(dirname "$1")"
echo "$2" > "$1" 

if [ $? -eq 0 ] ; then 
 echo "Successful write of $1" 
else 
  echo "Could not write $1"
  exit 1
fi
