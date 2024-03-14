#! /bin/bash

PATCHES="\
2cf9af0b5668 
ff90afa75573 
27cbe7d61898 
1a686237d94b 
49d654d85f85 
7ee30bc132c6 
9a2ae9f6b6bb 
5637f60b6828
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	var=$(printf '%04d_%s' ${j} ${i})
	echo ${var}.patch
        git format-patch --stdout $i^..$i > tmp.patch
        sed '1,/^\(---\).*/ s/^\(---\).*/'"Original-commit: $i"'\n\1/' tmp.patch > ${var}.patch
        rm tmp.patch
	git format-patch --stdout $i^..$i > ${var}.patch
done
