# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025, Google
# Author: Maciej Żenczykowski

.PHONY: all start stop status dump hint macs install clean

# Default target: runs all other build targets
all: colatrld.o send-udp0.clang send-udp0.gcc send-udp0 colatrlutil.clang colatrlutil.g++ colatrlutil

CFLAGS=-O2 -Wall -Werror
LIBBPF_CFLAGS = -I/usr/include/bpf -I/usr/include/libbpf
LIBBPF_LIBS = -lbpf
CLANG ?= $(shell command -v clang-19 || command -v clang)
CLANGXX ?= $(shell command -v clang++-19 || command -v clang++)

send-udp0.clang: send-udp0.c
	$(CLANG) $(CFLAGS) $< -o $@

send-udp0.gcc: send-udp0.c
	$(CLANG) $(CFLAGS) $< -o $@

send-udp0: send-udp0.clang
	ln -sf send-udp0.clang send-udp0

colatrld.o: colatrld.c colatrld.h
	$(CLANG) -target bpf $(CFLAGS) -I/usr/include/x86_64-linux-gnu -g -c $< -o $@

colatrlutil.clang: colatrlutil.cpp colatrld.h BpfMap.h
	$(CLANGXX) $(CFLAGS) -Wno-unknown-warning-option -Wno-vla-cxx-extension -Wno-non-c-typedef-for-linkage -ftrivial-auto-var-init=zero $< -o $@

colatrlutil.g++: colatrlutil.cpp colatrld.h BpfMap.h
	g++ $(CFLAGS) -Wno-template-id-cdtor -Wno-attributes -Wno-non-c-typedef-for-linkage $< -o $@

colatrlutil: colatrlutil.clang
	ln -sf colatrlutil.clang colatrlutil

hint: colatrlutil
	sudo ./colatrlutil get $(shell ip -6 route get 2001:4860:3860::8888 | sed -rn 's@^.* dev ([^ ]+) .*@\1@p') 192.0.0.1

macs:
	sed -rn 's@^4 +enp1s0 +@@p' </proc/net/dev_mcast

install: colatrld.o colatrlutil colatrl
	install colatrld.o -D $(DESTDIR)/usr/lib/colatrl/colatrld.o
	install colatrlutil $(DESTDIR)/usr/sbin
	install colatrl $(DESTDIR)/usr/sbin

clean:
	rm -f send-udp0.clang send-udp0.gcc send-udp0 colatrld.o colatrlutil.clang colatrlutil.g++ colatrlutil
