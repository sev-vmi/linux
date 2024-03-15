#! /bin/bash

PATCHES="\
09298542cd89 
a7ba5c3d008d 
25f003de987a 
4312cf7f16c8 
387caf0b759a 
813071438e83 
966b753cf396 
f9f6971ebb75 
55c2564a6852 
2ca6b6dc8512 
858defad2ae2 
bde9e6b9ba75 
62dcee716085 
96466748780d 
154e3a65f404 
3dfee47b215e 
730ad0ede130
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
