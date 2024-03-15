#! /bin/bash

PATCHES="\
37ec8eb851c1 
781ca2de89ba 
be62dbf554c5 
ae5e6c6439c3 
4c7c171f85b2 
fa83433c92e3 
e5c0bd7f2206 
808be0aae53a 
470eb3b31134 
3057fb9377eb 
a5bbbf37c6f8 
3332364e4ebc 
3c124435e8dd 
4c80ba392bf6 
d360211524be 
7d4e6ccd1fb0 
8c17bbf6c8f7 
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
