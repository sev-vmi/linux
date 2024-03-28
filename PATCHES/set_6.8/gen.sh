#! /bin/bash

PATCHES="\
57cdb720eaa5 \
04c3024560d3a14acd18d0a51a1d0a89d29b7eb5 \
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
