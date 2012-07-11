AUTOMAKE_OPTIONS = foreign

ACLOCAL_AMFLAGS = -I m4

pkglib_LTLIBRARIES = daq_endace.la
daq_endace_la_SOURCES = daq_endace.c
daq_endace_la_CFLAGS = -DBUILDING_SO
daq_endace_la_LDFLAGS = -module -export-dynamic -avoid-version -shared
