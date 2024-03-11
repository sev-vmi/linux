#! /bin/bash

PATCHES="\
778a136e48be \
28a4aa1160d7 \
02ffbe6351f5 \
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	echo ${j}_${i}.patch
	git format-patch --stdout $i^..$i > ${j}_${i}.patch
done
