#! /bin/bash

PATCHES="\
24647e0a39b6
eeeb4f67a6cd
a4148b7ca2a5
a9ab13ff6e84
56083bdf67c7
9c3d370a8efa
8081ad06b68a
88c604b66eb6
a9fa7cb6aa99
bbdad0b5a708
55714cddbf10
cae96af18452
fc6f7c03ad80 
3b82b8d7fdf7
c300ab9f08df
5a9f54435a48
404d5d7bff0d
199a8b84c455
ae95f566b3d2
e14b7786cb1c
de182481629c
c6b22f59d694
c9d40913ac5a
7c86663b68ba
bd279629f73f
d8e4e58f4bd4
31031098feb9
ffdf7f9e80ac
36e2e98363e6
e9fd761a46b8
08245e6d2e58
fb7333dfd812
e649b3f0188f
af28dfacbe00
44d527170731
bf10bd0be532
d2286ba7d574
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
