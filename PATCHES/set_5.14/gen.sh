#! /bin/bash

PATCHES="\
fdf513e37a3b \
a01b45e9d34d \
5868b8225ece \
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	echo ${j}_${i}.patch
	git format-patch --stdout $i^..$i > ${j}_${i}.patch
done
