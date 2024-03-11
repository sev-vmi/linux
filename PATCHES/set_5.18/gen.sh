#! /bin/bash

PATCHES="\
db6e7adf8de9 \
ed60920efe73 \
b51818afdc1d \
b652de1e3dfb \
4a204f789587 \
a80ced6ea514 \
4a9e7b9ea252 \
7491b7b2e1c5 \
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	echo ${j}_${i}.patch
	git format-patch --stdout $i^..$i > ${j}_${i}.patch
done
