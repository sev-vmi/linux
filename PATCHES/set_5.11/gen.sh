#! /bin/bash

PATCHES="\
4165bf015ba9 \
5ae9a046a452 \
872f36eb0b0f \
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	var=$(printf '%02d_%s' ${j} ${i})
	echo ${var}.patch
	git format-patch --stdout $i^..$i > tmp.patch
	sed '1,/^\(---\).*/ s/^\(---\).*/'"Original-commit: $i"'\n\1/' tmp.patch > ${var}.patch
	rm tmp.patch
done
