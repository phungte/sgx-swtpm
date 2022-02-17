#ifndef _SGX_OCALL_H_
#define _SGX_OCALL_H_

#include <stdio.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include "sgx_error.h"

int swtpm_create_enclave(void);
void print_error_message(sgx_status_t ret);
int swtpm_destroy_enclave(void);
#endif
