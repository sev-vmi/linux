#! /bin/bash

#fd6fa73 \

PATCHES="\
aae99a7c9ab3 \
bf348f667ed3 \
4bdec12aa8d6 \
d2fe6bf5b881 \
c514d3a348ac \
ab1b1dc131cd \
5c127c85472c \
8fc9c7a3079e \
05c4fe8c1bd9 \
7a8f7c1f3434 \
4d1d7942e36a \
c0caeee65af3 \
0e311d33bfbe \
f8d8ac215919 \
8c9e639da435 \
39b6b8c35cf3 \
091abbf578f9 \
01e69cef63f8 \
0a8735a6acf3 \
\
b5ede3d \
b031f10 \
5413bcb \
1bd9dfec9fd4 \
5429478d03 \
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
