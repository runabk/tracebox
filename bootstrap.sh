#!/bin/sh

git submodule init || exit 1
git submodule update || exit 1

# TD: Added command, to ensure that submodules (particularly: libcrafter) are up-to-date.
git submodule update --remote --merge

autoreconf --force --install --verbose || exit 1
