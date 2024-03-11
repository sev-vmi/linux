#! /bin/bash

PATCHES="\
7e582ccbbd73 \
df63202fe52b \
36222b117e36 \
4651fc56bad0 \
\
bca66db \
\
b0a1637f64b0 \
4628efcd4e89 \
0f250a646382 \
30eed56a7e1c \
06ef813466c6 \
bf5f6b9d7ad6 \
df7e4827c549 \
73143035c214 \
\
61e5f69ef083 \
074c82c8f7cf \
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	echo ${j}_${i}.patch
	git format-patch --stdout $i^..$i > ${j}_${i}.patch
done
