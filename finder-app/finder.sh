#!/bin/sh

if [ "$#" -ne 2 ] ; then
  echo "Usage : $0 <filesdir> <searchstr>"
  exit 1
fi

if [ -d "$1" ]; then 
 #echo "the argument is a directory"
 #st=`grep -r "$2" "$1"`
 #echo "$st"
 lines=`find "$1" -type f | xargs grep "$2" | wc -l`
 files=`find "$1" -type f | xargs grep "$2" -l | wc -l`
 echo "The number of files are $files and the number of matching lines are $lines"
else 
  echo "$1 does not represent a directory on the filesystem"
  exit 1
fi
