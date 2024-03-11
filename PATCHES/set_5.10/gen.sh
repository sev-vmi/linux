#! /bin/bash

PATCHES="\
f6426ab9c957e97418ac5b0466538792767b1738 \
"

j=0
for i in $PATCHES
do
	j=$((j+1))
	echo ${j}_${i}.patch
	git format-patch --stdout $i^..$i > ${j}_${i}.patch
done
