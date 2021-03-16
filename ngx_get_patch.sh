#!/bin/bash

set -e

dest_dir='./patches'
feature_name='unknown'
basename=`git branch | head -n1 | cut -d ' ' -f5 | sed 's/)//g'`

for o in "$@"; do
    case $o in
        --fn=*)
        feature_name=`expr "x$o" : "x--fn=\(.*\)"`
        ;;
    esac
done

mkdir -p $dest_dir > /dev/null

#
# Appling:
# 1.      $> patch -p1 < NAME.patch
# 2 (or). $> git apply NAME.patch
#
git diff > $dest_dir/$feature_name-$basename.patch

