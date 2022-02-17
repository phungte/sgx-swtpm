#include <stdio.h>
#include "sgx_error.h"
#include "Enclave_u.h"
#include "tpm_types.h"
#include "tpm_error.h"
// #include "tpm_library.h"

// in #include "tpm_library_conf.h"
#define TPM_BUFFER_MAX             4096

extern sgx_enclave_id_t global_eid;
TPM_RESULT  TPMLIB_ChooseTPMVersion(enum TPMLIB_TPMVersion ver);
void  TPMLIB_Terminate(void);
TPM_RESULT  TPMLIB_Process(unsigned char **respbuffer, uint32_t *resp_size,
                          uint32_t *respbufsize,
		          unsigned char *command, uint32_t command_size);
uint32_t  TPMLIB_SetBufferSize(uint32_t wanted_size,
                               uint32_t *min_size,
                               uint32_t *max_size);
TPM_RESULT  TPM_IO_TpmEstablished_Get(TPM_BOOL *tpmEstablished);
TPM_RESULT  TPM_IO_Hash_Start(void);
TPM_RESULT  TPM_IO_Hash_End(void);
TPM_RESULT  TPMLIB_CancelCommand(void);
char * TPMLIB_GetInfo(enum TPMLIB_InfoFlags flags);
TPM_RESULT  TPM_IO_Hash_Data( const unsigned char *data, uint32_t data_length);
void  TPMLIB_SetDebugFD(int fd);
void  TPMLIB_SetDebugLevel(unsigned level);
TPM_RESULT  TPMLIB_SetDebugPrefix( const char *prefix);
// TPM_RESULT  TPMLIB_RegisterCallbacks( struct libtpms_callbacks *callbacks);
TPM_RESULT  TPMLIB_GetTPMProperty(enum TPMLIB_TPMProperty prop, int *result);
TPM_RESULT  TPMLIB_MainInit(void);
TPM_RESULT  TPMLIB_VolatileAll_Store_Size(uint32_t *buflen);
TPM_RESULT  TPMLIB_VolatileAll_Store_ecall( unsigned char *buffer,
					    uint32_t buflen);
TPM_RESULT  TPMLIB_SetState(enum TPMLIB_StateType st,
                            const unsigned char *buffer, uint32_t buflen);
TPM_RESULT TPM_IO_TpmEstablished_Reset(void);

TPM_RESULT  TPMLIB_ChooseTPMVersion(enum TPMLIB_TPMVersion ver)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPMLIB_ChooseTPMVersion(global_eid, &rv, ver);
    return (status != SGX_SUCCESS) ? TPM_FAIL : rv;
}

void  TPMLIB_Terminate(void)
{
    ecall_TPMLIB_Terminate(global_eid);
}

TPM_RESULT  TPMLIB_Process(unsigned char **respbuffer, uint32_t *resp_size,
                          uint32_t *respbufsize,
		          unsigned char *command, uint32_t command_size)
{
    TPM_RESULT rv;
    sgx_status_t status;
    unsigned char *tmp;

    if (*resp_size < TPM_BUFFER_MAX || !*respbuffer) {
        tmp = realloc(*respbuffer, TPM_BUFFER_MAX);
        if (!tmp) {
            printf("Could not allocated %u bytes.\n",
                                TPM_BUFFER_MAX);
            return TPM_SIZE;
        }
        *respbuffer = tmp;
        *respbufsize = TPM_BUFFER_MAX;
    }
    status = ecall_TPMLIB_Process(global_eid, &rv, respbuffer, resp_size, respbufsize, command, command_size);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

uint32_t  TPMLIB_SetBufferSize(uint32_t wanted_size,
                               uint32_t *min_size,
                               uint32_t *max_size)
{
    uint32_t rv;
    sgx_status_t status;

    status = ecall_TPMLIB_SetBufferSize(global_eid, &rv, wanted_size, min_size, max_size);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT  TPM_IO_TpmEstablished_Get(TPM_BOOL *tpmEstablished)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPM_IO_TpmEstablished_Get(global_eid, &rv, tpmEstablished);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT TPM_IO_TpmEstablished_Reset(void)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPM_IO_TpmEstablished_Reset(global_eid, &rv);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT  TPM_IO_Hash_Start(void)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPM_IO_Hash_Start(global_eid, &rv);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT  TPM_IO_Hash_End(void)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPM_IO_Hash_End(global_eid, &rv);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT  TPMLIB_CancelCommand(void)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPMLIB_CancelCommand(global_eid, &rv);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

char *TPMLIB_GetInfo(enum TPMLIB_InfoFlags flags)
{
    char* rv;
    sgx_status_t status;

    status = ecall_TPMLIB_GetInfo(global_eid, &rv, flags);
    if (status != SGX_SUCCESS)
	return NULL;
    else
	return rv;
}

TPM_RESULT  TPM_IO_Hash_Data( const unsigned char *data, uint32_t data_length)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPM_IO_Hash_Data(global_eid, &rv, data, data_length);
    if (status != SGX_SUCCESS)
	return TPM_FAIL;
    else
	return rv;
}

void  TPMLIB_SetDebugFD(int fd)
{
    ecall_TPMLIB_SetDebugFD(global_eid, fd);
}

void  TPMLIB_SetDebugLevel(unsigned level)
{
    ecall_TPMLIB_SetDebugLevel(global_eid, level);
}

TPM_RESULT  TPMLIB_SetDebugPrefix( const char *prefix)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPMLIB_SetDebugPrefix(global_eid, &rv, prefix);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

#if 0
TPM_RESULT  TPMLIB_RegisterCallbacks( struct libtpms_callbacks *callbacks)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPMLIB_RegisterCallbacks(global_eid, &rv, callbacks);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}
#endif

TPM_RESULT  TPMLIB_GetTPMProperty(enum TPMLIB_TPMProperty prop,
				  int *result)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPMLIB_GetTPMProperty(global_eid, &rv, prop, result);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT  TPMLIB_MainInit(void)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPMLIB_MainInit(global_eid, &rv);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT  TPMLIB_VolatileAll_Store_Size(uint32_t *buflen)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPMLIB_VolatileAll_Store_Size(global_eid, &rv, buflen);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT  TPMLIB_VolatileAll_Store_ecall( unsigned char *buffer,
                                     uint32_t buflen)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPMLIB_VolatileAll_Store_ecall(global_eid, &rv, buffer, buflen);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT  TPMLIB_SetState(enum TPMLIB_StateType st,
                            const unsigned char *buffer, uint32_t buflen)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_TPMLIB_SetState(global_eid, &rv, st, buffer, buflen);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}

TPM_RESULT tpmlib_register_callbacks(struct libtpms_callbacks *cbs);
TPM_RESULT tpmlib_register_callbacks(struct libtpms_callbacks *cbs)
{
    TPM_RESULT rv;
    sgx_status_t status;

    status = ecall_tpmlib_register_callbacks(global_eid, &rv, (uint64_t)cbs);
    if (status != SGX_SUCCESS)
	return 0;
    else
	return rv;
}
