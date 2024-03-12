#! /bin/bash

PATCHES="\
edf721238576 \
d89d04a \
ee49a89 \
d5fa597ed870 \
320af55 \
f44509f849fe \
7223fd2d5338 \
9f084f7c2ed7 \
a9603ae0e4ee \
3743c2f02517 \
f5f9089f76dd \
603ccef42ce9 \
187c883 \
66c768d30e64 \
30c9434717fd \
91b99ea \
f6c60d081e2c \
fac426889439 \
18869f26df1a \
ba8ec273240a \
\
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	var=$(printf '%02d_%s' ${j} ${i})
	echo ${var}.patch
	git format-patch --stdout $i^..$i > ${var}.patch
done
