#! /bin/bash

PATCHES="\
cae72dcc3b21 \
7cfc5c653b07 \
ef8b4b720368 \
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	echo ${j}_${i}.patch
	git format-patch --stdout $i^..$i > ${j}_${i}.patch
done
