#! /bin/bash

#fd6fa73 \

PATCHES="\
0ccf3e7cb95a \
dd4589ee \
5aede752a839 \
e0bead97e759 \
c482f2cebe2d \
2008fab34530 \
f628a34a9d52 \
a879a88e05f3 \
da3fb46d226a \
f9829c907661 \
8578e4512d87 \
1d22a597b3e9 \
f651a00 \
5063c41bebac \
9a364857ab4f \
1ba59a445467 \
4f160b7bd481 \
1808c950955d \
bbfc7aa62a4a \
a790e338c7c4 \
e2ed3e64a2bd \
b3f257a84696 \
3536690 \
1459f5c6b \
ff5a983 \
5999715922c5 \
c281794eaa5c \
5b84b0291702 \
ef40757743 \
d471bd853d38117 \
72c70ceeaf59330 \
76e527509d37a15 \
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
