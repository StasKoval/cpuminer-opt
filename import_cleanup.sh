#!/bin/sh

find . -name '*.new' -print0 | xargs -0 git rm -r
find . -name '*.bak' -print0 | xargs -0 git rm -r
find . -name '*.good' -print0 | xargs -0 git rm -r
find . -name '*.orig' -print0 | xargs -0 git rm -r
find . -name '*.del' -print0 | xargs -0 git rm -r
