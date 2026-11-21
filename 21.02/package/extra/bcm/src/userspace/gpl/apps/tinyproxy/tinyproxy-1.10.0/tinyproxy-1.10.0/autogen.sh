#!/bin/sh

srcdir=`dirname $0`
test -z "$srcdir" && srcdir=.
ORIGDIR=`pwd`

set -x

cd $srcdir

aclocal -I m4macros \
  && autoheader \
  && automake --gnu --add-missing \
  && autoconf

cd $ORIGDIR
