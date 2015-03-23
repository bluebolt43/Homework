#!/bin/bash
# Brute force is possible if we know the algorithm
# We can generate all possible keys and try it.
# Assume that we know target file format is PDF
# and the key is between 0000~9999 in our test for this case.
# Try "./a.out 2345 hw.pdf encrypt.pdf" to encrypt hw.pdf

CIPHER=a.out
INPUT="encrypt.PDF"
OUTPUT_NAME=".pdf"
TARGET_FORMAT="PDF"
max=10000

if [ "X" != "X$1" ]
then
	INPUT=$1
fi

COUNT=0
timestamp=`date +%s`
for ((i=0; i<=$max; ++i )) ; 
do
    key=`printf "%04d" $i`
	./$CIPHER 1 $key $INPUT OUTPUT$COUNT 0
	file OUTPUT$COUNT | grep $TARGET_FORMAT > /dev/null
	if [ $? == 0 ]
	then
		echo "$key might be a key."
		echo "Open OUTPUT$COUNT to check the result."
		COUNT=$((COUNT+1))
		#echo "Takes "$((`date +%s`-timestamp))"secs"
	fi
done

echo "Takes "$((`date +%s`-timestamp))"secs"
exit 0

