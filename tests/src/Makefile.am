# SPDX-License-Identifier: GPL-2.0+
# Makefile.am

AUTOMAKE_OPTIONS	= foreign
noinst_PROGRAMS		= fssum

fssum_SOURCES = md5.c fssum.c

if ENABLE_LZ4
noinst_PROGRAMS += badlz4
badlz4_SOURCES = badlz4.c
badlz4_LDADD = ${liblz4_LIBS}
endif

