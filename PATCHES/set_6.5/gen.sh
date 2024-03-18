#! /bin/bash

PATCHES="\
a42f0c7a4118 \
c4649a4 \
74a37817bd15 \
66419036f68a \
98aeb4ea5599 \
c69d89aff393 \
2818de6e87de \
54ce12e02e44 \
bccc37a8a2fb \
1ce018df8764 \
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
