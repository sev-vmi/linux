#! /bin/bash

PATCHES="\
c20f36534666 
098accf2da94 
045a70426067 
72acd9df18f1 
5375e874c763 
b74aa02d7a30 
ae74c19faa7d 
eb791aa70b90 
5b8a9a047b6c 
f44a4d7e4f1c 
19c6978fba68 
119b2b2c3e25 
e461b8c991b9 
ea90228c7b2a 
bd421264ed30 
7cc31613734c
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
