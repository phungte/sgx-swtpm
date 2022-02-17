#include "sgx_ocall.h"
#include "sgx_urts.h"
#include "Enclave_u.h"
#include <sys/types.h>
#include <pwd.h>

int  ocall_clock_gettime(clockid_t clk_id, struct timespec *tp) {
    return clock_gettime(clk_id, tp);
}

TPM_RESULT SWTPM_NVRAM_Init(void);
TPM_RESULT SWTPM_NVRAM_LoadData_ocall(unsigned char *data, uint32_t length, uint32_t tpm_number, const char *name);
TPM_RESULT SWTPM_NVRAM_DataSize(uint32_t *length, uint32_t tpm_number, const char *name);

TPM_RESULT SWTPM_NVRAM_StoreData(const unsigned char *data, uint32_t length, uint32_t tpm_number, const char *name);
TPM_RESULT SWTPM_NVRAM_DeleteName(uint32_t tpm_number, const char *name, TPM_BOOL mustExist);
TPM_RESULT SWTPM_IO_Init(void);
TPM_RESULT mainloop_cb_get_locality(TPM_MODIFIER_INDICATOR *loc, uint32_t tpmnum);

TPM_RESULT ocall_SWTPM_NVRAM_Init(void) {
    return SWTPM_NVRAM_Init();
}

TPM_RESULT ocall_SWTPM_NVRAM_LoadData(unsigned char *data, uint32_t length, uint32_t tpm_number, const char *name) {
    return SWTPM_NVRAM_LoadData_ocall(data, length, tpm_number, name);
}

TPM_RESULT ocall_SWTPM_NVRAM_DataSize(uint32_t *length, uint32_t tpm_number, const char *name) {
    return SWTPM_NVRAM_DataSize(length, tpm_number, name);
}

TPM_RESULT ocall_SWTPM_NVRAM_StoreData(const unsigned char *data, uint32_t length, uint32_t tpm_number, const char *name){
    return SWTPM_NVRAM_StoreData(data, length, tpm_number, name);
}

TPM_RESULT ocall_SWTPM_NVRAM_DeleteName(uint32_t tpm_number, const char *name, TPM_BOOL mustExist){
    return SWTPM_NVRAM_DeleteName(tpm_number, name, mustExist);
}
TPM_RESULT ocall_SWTPM_IO_Init(void){
    return SWTPM_IO_Init();
}
TPM_RESULT ocall_mainloop_cb_get_locality(TPM_MODIFIER_INDICATOR *loc, uint32_t tpmnum){
    return mainloop_cb_get_locality(loc, tpmnum);
}

#define ENCLAVE_FILENAME "/home/vm-admin/ws/libtpms/sgx-libtpms/libenclave_tpms.signed.so"
#define TOKEN_FILENAME   "enclave.token"
#define MAX_PATH FILENAME_MAX
#define MAX_BUF_LEN 100

#define swtpm_log printf

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
    {
        SGX_ERROR_NDEBUG_ENCLAVE,
        "The enclave is signed as product enclave, and can not be created as debuggable enclave.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
	if(ret == sgx_errlist[idx].err) {
	    if(NULL != sgx_errlist[idx].sug)
		printf("Info: %s\n", sgx_errlist[idx].sug);
	    printf("Error: %s\n", sgx_errlist[idx].msg);
	    break;
	}
    }

    if (idx == ttl)
	printf("Error: Unexpected error occurred.\n");
    
}

int swtpm_create_enclave()
{
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
#if 0    
    /* Step 1: try to retrieve the launch token saved by last transaction 
     *         if there is no token, then create a new one.
     */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strlen(home_dir)+strlen("/")+strlen(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strlen(home_dir)+1);
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, strlen(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, strlen(TOKEN_FILENAME)+1);
    }
#else
        strncpy(token_path, TOKEN_FILENAME, strlen(TOKEN_FILENAME)+1);
#endif

    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }

    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        if (fp != NULL){
			fclose(fp);   	
        } 
		swtpm_log("[*] failed to create enclave.\n");
		printf("[*] failed to create enclave.\n");
		abort();
        // return -1;
    }else{
		swtpm_log("[*]  successed to create enclave.\n");
		printf("[*]  successed to create enclave.\n");    	
    }

    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }

    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    return 0;
} 

int swtpm_destroy_enclave()
{
	if(global_eid){
		if(SGX_SUCCESS != sgx_destroy_enclave(global_eid)){
			swtpm_log("[*] failed to destory enclave.\n");
			printf("[*] failed to destory enclave.\n");
		}else{
			swtpm_log("[*] successed to destory enclave.\n");
			printf("[*] successed to destory enclave.\n");
		}
	}

	return 0;
} 
  
