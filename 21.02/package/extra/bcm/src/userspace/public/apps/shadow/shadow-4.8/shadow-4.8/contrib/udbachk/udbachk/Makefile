#
# Makefile for Udbachk version 0.11
#
# PREFIX tells under which tree the program is to be installed
#

PREFIX=/usr/local

default:
	gcc udbachk.c -O2 -lm -Wall -pedantic -o udbachk;
	strip udbachk;
clean:
	rm -f udbachk;
install:
	if test -x udbachk;\
	then\
	    install -d $(PREFIX)/sbin;\
	    install -d $(PREFIX)/man/man8;\
	    install -d $(PREFIX)/etc;\
	    install -m 755 udbachk $(PREFIX)/sbin;\
	    install -m 644 udbachk.8 $(PREFIX)/man/man8;\
	    install -m 644 udbachk.conf $(PREFIX)/etc;\
	    make note;\
	else\
	    make default;\
	    make install;\
	fi;
note:
	@echo
	@echo Please check that $(PREFIX)/sbin is in your path. 
	@echo
uninstall:
	rm -f $(PREFIX)/sbin/udbachk;
	rm -f $(PREFIX)/man/man8/udbachk.8;
	rm -f $(PREFIX)/etc/udbach.conf;
