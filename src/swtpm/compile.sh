#!/bin/bash
set -x
gcc -I../../../libtpms/sgx-libtpms/Include  -I../../include -I../../include -I../../include/swtpm -I../../src/utils -g -O0 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall  -Wformat -Wformat-security -fstack-protector-strong -Wstack-protector -D_FORTIFY_SOURCE=2 -DENCLAVE_UNTRUSTED -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse -DHAVE_SWTPM_CUSE_MAIN -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall  -Wformat -Wformat-security -c sgx_ecalls.c -I../../../libtpms/sgx-libtpms/App/ -I/opt/intel/sgxsdk/include/ -I../../../libtpms/include/libtpms -I../../../libtpms/sgx-libtpms/Include -Werror && \
\
gcc -I../../../libtpms/sgx-libtpms/Include -I../../include -I../../include -I../../include/swtpm -I../../src/utils -g -O0 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall  -Wformat -Wformat-security -fstack-protector-strong -Wstack-protector -D_FORTIFY_SOURCE=2 -DENCLAVE_UNTRUSTED -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -D_FILE_OFFSET_BITS=64 -I/usr/include/fuse -DHAVE_SWTPM_CUSE_MAIN -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall  -Wformat -Wformat-security -c sgx_ocall.c -I../../../libtpms/sgx-libtpms/App/ -I/opt/intel/sgxsdk/include/ -I../../../libtpms/include/libtpms -I../../../libtpms/sgx-libtpms/Include -Werror && \
\
gcc -I../../include -I../../include -I../../include/swtpm -I../../src/utils -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security -fstack-protector-strong -Wstack-protector -D_FORTIFY_SOURCE=2 -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -D_FILE_OFFSET_BITS=64 -DENCLAVE_UNTRUSTED -I/usr/include/fuse -DHAVE_SWTPM_CUSE_MAIN -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security -Wl,-z -Wl,relro -Wl,-z -Wl,now -o .libs/swtpm swtpm-main.o swtpm-daemonize.o swtpm-swtpm.o swtpm-swtpm_chardev.o swtpm-cuse_tpm.o -pthread -lfuse -lgthread-2.0 -lglib-2.0    \
../../../libtpms/sgx-libtpms/App/Enclave_u.o \
./.libs/libswtpm_libtpms_la-mainloop.o     \
./.libs/libswtpm_libtpms_la-logging.o  \
./.libs/libswtpm_libtpms_la-pidfile.o  \
./.libs/libswtpm_libtpms_la-ctrlchannel.o  \
./.libs/libswtpm_libtpms_la-utils.o  \
./.libs/libswtpm_libtpms_la-common.o  \
./.libs/libswtpm_libtpms_la-options.o  \
./.libs/libswtpm_libtpms_la-server.o  \
./.libs/libswtpm_libtpms_la-tpmstate.o  \
./.libs/libswtpm_libtpms_la-capabilities.o  \
./.libs/libswtpm_libtpms_la-tpmlib.o  \
./.libs/libswtpm_libtpms_la-threadpool.o  \
./.libs/libswtpm_libtpms_la-key.o  \
./.libs/libswtpm_libtpms_la-seccomp_profile.o \
./.libs/libswtpm_libtpms_la-swtpm_nvstore.o \
./.libs/libswtpm_libtpms_la-swtpm_io.o \
./.libs/libswtpm_libtpms_la-swtpm_debug.o \
./.libs/libswtpm_libtpms_la-swtpm_aes.o \
./.libs/libswtpm_libtpms_la-tlv.o \
./.libs/libswtpm_libtpms_la-swtpm_nvstore_linear.o \
./.libs/libswtpm_libtpms_la-swtpm_nvstore_linear_file.o \
    ./.libs/libswtpm_libtpms_la-swtpm_nvstore_dir.o \
    ./sgx_ocall.o \
./sgx_ecalls.o \
-L/usr/lib/x86_64-linux-gnu  -lsgx_urts -lpthread  -lseccomp -lcrypto -L/opt/intel/sgxsdk/lib64 -lsgx_uprotected_fs





# ./.libs/libswtpm_libtpms.a 

# following need to be in enclave
#libswtpm_libtpms_la-key.o \
#libswtpm_libtpms_la-swtpm_nvstore.o \



# libtool: link: ar cr .libs/libswtpm_libtpms.a  libswtpm_libtpms_la-capabilities.o libswtpm_libtpms_la-common.o libswtpm_libtpms_la-ctrlchannel.o libswtpm_libtpms_la-key.o libswtpm_libtpms_la-logging.o libswtpm_libtpms_la-mainloop.o libswtpm_libtpms_la-options.o libswtpm_libtpms_la-pidfile.o libswtpm_libtpms_la-seccomp_profile.o libswtpm_libtpms_la-server.o libswtpm_libtpms_la-swtpm_aes.o libswtpm_libtpms_la-swtpm_debug.o libswtpm_libtpms_la-swtpm_io.o libswtpm_libtpms_la-swtpm_nvstore.o libswtpm_libtpms_la-swtpm_nvstore_dir.o libswtpm_libtpms_la-swtpm_nvstore_linear.o libswtpm_libtpms_la-swtpm_nvstore_linear_file.o libswtpm_libtpms_la-tlv.o libswtpm_libtpms_la-tpmlib.o libswtpm_libtpms_la-tpmstate.o libswtpm_libtpms_la-utils.o libswtpm_libtpms_la-threadpool.o



# libtool: compile:  gcc -DHAVE_CONFIG_H -I. -I../.. -I../../include -I../../include -I../../include/swtpm -I../../src/utils -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security -fstack-protector-strong -Wstack-protector -D_FORTIFY_SOURCE=2 -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security -MT libswtpm_libtpms_la-mainloop.lo -MD -MP -MF .deps/libswtpm_libtpms_la-mainloop.Tpo -c mainloop.c  -fPIC -DPIC -o .libs/libswtpm_libtpms_la-mainloop.o


# libtool: compile:  gcc -DHAVE_CONFIG_H -I. -I../.. -I../../include -I../../include -I../../include/swtpm -I../../src/utils -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security -fstack-protector-strong -Wstack-protector -D_FORTIFY_SOURCE=2 -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -g -O2 -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security -MT libswtpm_libtpms_la-mainloop.lo -MD -MP -MF .deps/libswtpm_libtpms_la-mainloop.Tpo -c mainloop.c -o libswtpm_libtpms_la-mainloop.o >/dev/null 2>&1


# /bin/bash ../../libtool  --tag=CC   --mode=compile gcc -DHAVE_CONFIG_H -I. -I../..    -I../../include -I../../include -I../../include/swtpm -I../../src/utils -g -O2  -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security    -g -O2  -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security    -fstack-protector-strong -Wstack-protector -D_FORTIFY_SOURCE=2 -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include  -g -O2  -Wreturn-type -Wsign-compare -Wswitch-enum -Wmissing-prototypes -Wall -Werror -Wformat -Wformat-security    -MT libswtpm_libtpms_la-key.lo -MD -MP -MF .deps/libswtpm_libtpms_la-key.Tpo -c -o libswtpm_libtpms_la-key.lo `test -f 'key.c' || echo './'`key.c
