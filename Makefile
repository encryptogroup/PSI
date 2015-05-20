
BIN=bin
SRC=src
EXT=${SRC}/externals


# compiler settings
CC=g++
COMPILER_OPTIONS=-O2
DEBUG_OPTIONS=-g3
BATCH=

ARCHITECTURE = $(shell uname -m)
ifeq (${ARCHITECTURE},x86_64)
MIRACL_MAKE:=linux64
GNU_LIB_PATH:=x86_64
else
MIRACL_MAKE:=linux
GNU_LIB_PATH:=i386
endif

INCLUDE=-I..  -I/usr/include/glib-2.0/ -I/usr/lib/${GNU_LIB_PATH}-linux-gnu/glib-2.0/include


LIBRARIES=-lgmp -lgmpxx -lpthread ${EXT}/miracl_lib/miracl.a -L /usr/lib  -lssl -lcrypto -lglib-2.0
CFLAGS=

# directory for PSI related sources
SOURCES_UTIL=${SRC}/util/*.cpp
OBJECTS_UTIL=${SRC}/util/*.o
SOURCES_OT=${SRC}/util/ot/*.cpp
OBJECTS_OT=${SRC}/util/ot/*.o
SOURCES_CRYPTO=${SRC}/util/crypto/*.cpp
OBJECTS_CRYPTO=${SRC}/util/crypto/*.o
SOURCES_HASHING=${SRC}/hashing/*.cpp
OBJECTS_HASHING=${SRC}/hashing/*.o
# naive hashing-based solution
SOURCES_NAIVE=${SRC}/naive-hashing/*.cpp
OBJECTS_NAIVE=${SRC}/naive-hashing/*.o
# public-key-based PSI
SOURCES_DHPSI=${SRC}/pk-based/*.cpp
OBJECTS_DHPSI=${SRC}/pk-based/*.o
# third-party-based PSI
SOURCES_THIRDPARTY=${SRC}/thirdparty-based/*.cpp
OBJECTS_THIRDPARTY=${SRC}/thirdparty-based/*.o
# OT-based PSI
SOURCES_OTPSI=${SRC}/ot-based/*.cpp
OBJECTS_OTPSI=${SRC}/ot-based/*.o
#OBJECTS_BENCH=${SRC}/bench_psi.cpp
# directory for the Miracl submodule and library
MIRACL_LIB_DIR=${EXT}/miracl_lib
SOURCES_MIRACL=${EXT}/Miracl/*
OBJECTS_MIRACL=${MIRACL_LIB_DIR}/*.o

all: miracl bench
	@echo "make all done."

bench: ${OBJECTS_BENCH} ${OBJECTS_DHPSI} ${OBJECTS_OTPSI} ${OBJECTS_NAIVE} ${OBJECTS_THIRDPARTY} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_MIRACL} 
	${CC} -o psi.exe ${SRC}/bench_psi.cpp ${CFLAGS} ${DEBUG_OPTIONS} ${OBJECTS_BENCH} ${OBJECTS_DHPSI} ${OBJECTS_OTPSI} ${OBJECTS_NAIVE} ${OBJECTS_THIRDPARTY} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT} ${OBJECTS_MIRACL} ${MIRACL_PATH} ${LIBRARIES} ${INCLUDE} ${COMPILER_OPTIONS}

# Compile options for the naive-hashing-based solution
${OBJECTS_NAIVE}: ${SOURCES_NAIVE} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO}
	${CC} -c -o ${INCLUDE} ${SOURCES_NAIVE} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${DEBUG_OPTIONS}

# Compile options for the public-key-based solution
${OBJECTS_DHPSI}: ${SOURCES_DHPSI} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO}
	${CC} -c -o ${INCLUDE} ${SOURCES_DHPSI} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${DEBUG_OPTIONS}

# Compile options for the third-party-based solution
${OBJECTS_THIRDPARTY}: ${SOURCES_THIRDPARTY} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO}
	${CC} -c -o ${INCLUDE} ${SOURCES_THIRDPARTY}  ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${DEBUG_OPTIONS} 

# Compile options for the ot-based solution
${OBJECTS_OTPSI}: ${SOURCES_OTPSI} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${OBJECTS_OT}
	${CC} -c -o ${INCLUDE} ${SOURCES_OTPSI} ${DEBUG_OPTIONS} ${OBJECTS_UTIL} ${OBJECTS_HASHING} ${OBJECTS_CRYPTO} ${OBJECTS_OT}




# core files for PSI
${OBJECTS_OT}: ${OBJECTS_UTIL} ${OBJECTS_CRYPTO}
	@cd ${BIN}; ${CC} -c ${INCLUDE} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${DEBUG_OPTIONS} ${SOURCES_OT}

${OBJECTS_HASHING}: ${SOURCES_HASHING}
	${CC} -c ${INCLUDE} ${SOURCES_HASHING} ${DEBUG_OPTIONS}

${OBJECTS_UTIL}: ${SOURCES_UTIL}
	${CC} -c ${INCLUDE} ${SOURCES_UTIL} ${DEBUG_OPTIONS}

${OBJECTS_CRYPTO}: ${SOURCES_CRYPTO}
	${CC} -c ${INCLUDE} ${SOURCES_CRYPTO} ${DEBUG_OPTIONS} 




# this will create a copy of the files in ${SOURCES_MIRACL} and its sub-directories and put them into ${MIRACL_LIB_DIR} without sub-directories, then compile it
miracl:	${MIRACL_LIB_DIR}/miracl.a

# copy Miracl files to a new directory (${CORE}/util/miracl_lib/), call the build script and delete everything except the archive, header and object files.
${MIRACL_LIB_DIR}/miracl.a: ${SOURCES_MIRACL}
	@find ${EXT}/Miracl/ -type f -exec cp '{}' ${EXT}/miracl_lib \;
	@cd ${EXT}/miracl_lib/; bash ${MIRACL_MAKE}; find . -type f -not -name '*.a' -not -name '*.h' -not -name '*.o' -not -name '.git*'| xargs rm

# only clean example objects, test object and binaries
clean:
	rm -f ${OBJECTS_EXAMPLE} ${OBJECTS_TEST} ${BIN}/*.exe ${OBJECTS_DHPSI} ${OBJECTS_OTPSI} ${OBJECTS_NAIVE} ${OBJECTS_THIRDPARTY} ${OBJECTS_UTIL} ${OBJECTS_CRYPTO} ${OBJECTS_OT}

# this will clean everything: example objects, test object and binaries and the Miracl library
cleanall: cleanmore
	rm -f ${OBJECTS_MIRACL} ${MIRACL_LIB_DIR}/*.a
