#! /bin/bash

PATCHES="\
999eabcc89b0 
cc7f5577adfc 
4abaffce4d25 
a1c77abb8d93 
b5ec2e020b70
64b5bd270426 
b518ba9fa691 
78f2145c4d93 
ab56f8e62daf 
8e205a6b2a06 
8a1038de11a5 
d5361678e63c 
46a010dd6896 
4064a4c6a1f9 
7289fdb5dcdb 
8be8f932e3db 
54163a346d4a 
7d611233b016 
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
