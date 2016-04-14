#!/bin/sh

find . -name '*.new' -print0 | xargs -0 rm -rvf
find . -name '*.bak' -print0 | xargs -0 rm -rvf
find . -name '*.hide' -print0 | xargs -0 rm -rvf
find . -name '*.good' -print0 | xargs -0 rm -rvf
find . -name '*.orig' -print0 | xargs -0 rm -rvf
find . -name '*.del' -print0 | xargs -0 rm -rvf
