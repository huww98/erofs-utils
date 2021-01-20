# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS	= foreign
check_PROGRAMS		= fssum

fssum_SOURCES = md5.c md5.h fssum.c

if ENABLE_LZ4
check_PROGRAMS += badlz4
badlz4_SOURCES = badlz4.c
badlz4_LDADD = ${liblz4_LIBS}
endif

