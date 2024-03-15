#! /bin/bash

PATCHES="\
ff2a08b39bce 
4cbf38511a00 
bdf4a7c4c77d 
c0da9b9f5afd 
57bd2c24ba16 
a6a4c7e2c5b8 
6e1aa2049154 
41df6dcc0a3f 
cf193888bfbd 
deac0b3bed26 
ce574c27ae27 
5012c3968537 
57f9842e4884 
dce8d6964ebd 
3eeeb45c6d04 
4e8906f0d84d 
1b032ec1ecbc 
cfcccbe8879f 
f38338cf0691 
555fb5ae0f39 
69cf44916698 
70b8170e55d3 
79659190ee97 
7a441b211052 
edcc40d2ab5f 
fb1b6955bbf3 
1226c3707446 
a71730e225be 
75b27745097d 
301441a09946 
e1980df36c5c 
786dfe496e3b 
05a0542b456e 
736c3333e397 
431275afdc71 
ad8694bac410 
9ac8545199a1
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
