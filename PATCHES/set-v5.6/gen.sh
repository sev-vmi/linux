#! /bin/bash

PATCHES="\
b4b2963616bb 
c96001c5702e 
ac8ef992cd02 
59508b303e4e
5c69d5c113f1 
150a84fee84f 
dfd146fcae89 
cad23e72b774 
8c86405f606c 
670564559ca3 
4bf79cb089f6 
767b839afa5d 
3ce4dc17e0c1 
17ac43a894ed 
b26a695a1d78 
4e19c36f2df8 
7e3e67a98701 
8df14af42f00 
24bbf74c0c36 
8937d762396d 
dcbcfa287e96 
ef8efd7a15bb 
2de9d0ccd0fe 
6c3e4422dd20 
f4fdc0a2edf4 
9a0bf0543069 
f3515dc3bef8 
e2ed4078a6ef 
1ec2405c7cbf 
f458d039db7e 
e8ef2a19a051 
a06230b62b89 
20796447a1ab 
331ca0f89fc2 
7455a8327674 
93fd9666c269 
91a5f413af59 
23520b2def95 
7943f4acea3c 
0c22056f8c43 
edec6e015a02 
94be4b85d895 
e1be9ac8e601
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
