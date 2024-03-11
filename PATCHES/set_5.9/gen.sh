#! /bin/bash

PATCHES="\
26e495f341075c09023ba16dee9a7f37a021e745 \
cbe94c6e1a7d11050050c4d5b89bb278c163e8d6 \
ab65ba57e3acb55920999f96a6152228b52a2f49 \
e52d58d54a321d4fe9d0ecdabe4f8774449f0d6e \
e97685abd5d711c885053d4949178f7ab9acbaef \
06e7852c0ffb30bb7cac1686db2f5d6458039b44 \
"

j=0
for i in $PATCHES
do
	j=$((j+1))
	echo ${j}_${i}.patch
	git format-patch --stdout $i^..$i > ${j}_${i}.patch
done
