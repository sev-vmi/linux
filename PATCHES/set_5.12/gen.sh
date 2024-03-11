#! /bin/bash

PATCHES="\
e6c804a848d6 \
6f7a343987fa \
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	echo ${j}_${i}.patch
	git format-patch --stdout $i^..$i > ${j}_${i}.patch
done
