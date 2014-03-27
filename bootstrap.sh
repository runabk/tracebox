#!/bin/sh

if [ ! -d "m4" ]; then 
		mkdir m4
fi

git submodule init || git clone --depth=1 https://github.com/gdetal/libcrafter.git || exit 1
git submodule update || git clone --depth=1 https://github.com/bhesmans/click.git || exit 1

AUTOHEADER=true autoreconf --install || exit 1

./configure $@
