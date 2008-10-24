#
# This script is for the maintainer to release rpm, dist and 
# tag with the version found in the configure file the cvs
# repository
#
#!/bin/bash

NAME=$1
MAJOR=$2
MINOR=$3
MICRO=$4
VERSION=$MAJOR\_$MINOR\_$MICRO
TAG=$NAME\_$VERSION
echo
echo -n "Ready to tag $TAG [Y/n] "
read

test -z "$REPLY" || echo $REPLY | egrep "y|Y|Yes" && \
    cvs tag $TAG
test ! -z "$REPLY" && echo "Aborted"
exit 0