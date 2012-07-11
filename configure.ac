#												-*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([endace-daq-module], [0.1], [your@email.address])
AM_INIT_AUTOMAKE([daq], [0.1])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([daq_endace.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

# Enable visibility if we can
AC_ENABLE_VISIBILITY()
# Special compiler flags for ICC, etc.
AC_SF_COMPILER_SETUP()

# Checks for the DAQ API headers and the SFBPF headers/library.
AC_CHECK_DAQ_API
AC_CHECK_SFBPF

# Checks for other dependencies of your DAQ module go here.
# Checks for DAG
AC_ARG_WITH(libdag_includes,
                        [  --with-libdag-includes=DIR        libdag include directory],
                        [with_dag_includes="$withval"], [with_dag_includes="no"])

AC_ARG_WITH(libdag_libraries,
                        [  --with-libdag-libraries=DIR       libdag library directory],
                        [with_dag_libraries="$withval"], [with_dag_libraries="no"])

if test "x$with_dag_includes" != "xno"; then
        CPPFLAGS="${CPPFLAGS} -I${with_dag_includes}"
fi

if test "x$with_dag_libraries" != "xno"; then
        LDFLAGS="${LDFLAGS} -L${with_dag_libraries}"
fi

AC_CHECK_HEADER([dagapi.h], [], [AC_MSG_ERROR([Could not find dagapi.h!])])
AC_CHECK_LIB([dag], [dag_open], [], [AC_MSG_ERROR([Could not link against the DAG library!])])


# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strchr strdup strerror strtol])

# Substitutions

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
