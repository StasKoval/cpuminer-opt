#!/bin/sh

find . -name '*.new' -print0 | xargs -0 git rm
find . -name '*.bak' -print0 | xargs -0 git rm
find . -name '*.good' -print0 | xargs -0 git rm
find . -name '*.orig' -print0 | xargs -0 git rm
find . -name '*.del' -print0 | xargs -0 git rm
