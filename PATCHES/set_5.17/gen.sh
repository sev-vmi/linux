#! /bin/bash

PATCHES="\
91b018950717 \
\
31f251d4ddfa \
202470d536b2 \
e422b8896948 \
af52f5aa5c1b \
782f64558de7 \
\
935a7333958e \
54744e17f031 \
a3c19d5beaad \
\
755c2bf87860 \
391503528257 \
\
0a5f784273aa \
57dfd7b \
30811174f0db \
66fa226c131f \
\
1460179dcd76 \
d92a5d1c6c75 \
"

rm *.patch
j=0
for i in $PATCHES
do
	j=$((j+1))
	echo ${j}_${i}.patch
	git format-patch --stdout $i^..$i > ${j}_${i}.patch
done
