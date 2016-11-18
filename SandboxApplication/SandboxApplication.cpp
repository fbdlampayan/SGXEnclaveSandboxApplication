// SandboxApplication.cpp : Defines the entry point for the console application.

#include "stdafx.h"
#include "sgx_defs.h"
#include "sgx_capable.h"
#include "sgx_uae_service.h" // has sgx_enable_device method
#include "sgx_tseal.h" // for sgx_sealed_data_t

#include "SandboxEnclave_u.h" // for OCALL print
#include "SandboxApplication.h"

#include <ShlObj.h> // for SHGetFolderPathA used in getting path of launch token
#include <iostream>

using namespace std;

struct sealed_buf_t sealedDataBuffer;

//OCALL UTILITY: for printing out inside the enclave
void print(const char *str) {
	cout << str;
}

void releaseResources()
{
    for(int i = 0; i < BUF_NUM; i++)
    {
        if(sealedDataBuffer.sealed_buf_ptr[i] != NULL)
        {
            free(sealedDataBuffer.sealed_buf_ptr[i]);
            sealedDataBuffer.sealed_buf_ptr[i] = NULL;
        }
    }
    return;
}


/* placing this here makes it a global EID to be used by multiple threads. */
/* this variable is a holder of the global EID to be assigned by sgx_create_enclave */
sgx_enclave_id_t globalEid = 0;

// UTILITY: for knowing what error occurred in enclave creation
typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* UTILITY: Error code returned by sgx_create_enclave */
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

/* UTILITY: method just to be able to log error conditions of sgx_status_t */
void printErrorMessageFromSgxStatus(sgx_status_t ret) {
	size_t idx = 0;
	size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

	for (idx = 0; idx < ttl; idx++) {
		if (ret == sgx_errlist[idx].err) {
			if (NULL != sgx_errlist[idx].sug)
				printf("Info: %s\n", sgx_errlist[idx].sug);
			printf("Error: %s\n", sgx_errlist[idx].msg);
			break;
		}
	}

	if (idx == ttl)
		cout << "Unexpected error occurred" << endl;

}


/* for checking and enabling SGX capability in the device */
int querySgxStatus() {
	
	cout << "doing querySgxStatus" << endl;
	sgx_device_status_t sgxDeviceStatus;
	sgx_status_t sgxResult = sgx_enable_device(&sgxDeviceStatus); // sgx sdk provided method to do it.

	// all sgx methods has this status report, if it is successful or not
	if (sgxResult != SGX_SUCCESS) {
		cout << "Failed to get the SGX device status! Exiting now..." << endl;
		return -1;
	}
	else {
	// in the case where sgx call has been successfully executed, check the resulting status
		switch (sgxDeviceStatus) {
		case SGX_ENABLED:
			cout << "SGX is already enabled!" << endl;
			return 0;
		case SGX_DISABLED_REBOOT_REQUIRED:
			cout << "SGX device has been enabled. Reboot required. \n" << endl;
			return -1;
		case SGX_DISABLED_LEGACY_OS:
			cout << "SGX device can't be enabled on current OS, doesn't support EFI interface." << endl;
			return -1;
		case SGX_DISABLED:
			cout << "SGX device not found." << endl;
			return -1;
		default:
			cout << "Unexpected error occurred." << endl;
			return -1;
		}
	}
}

/* 
 * As advised by the documentation, we should save the launch token object and re-use it in future create calls
 * to be able to create the same instance of the enclave.
 * step 1: retrieve launch token saved by last transaction (if any).
 * step 2: call sgx_create_enclave to initialize an enclave instance.
 * step 3: save the launch token used.
 *
 */
int createEnclave(void) {
	
	char tokenPath[MAX_PATH] = {'\0'};
	sgx_launch_token_t launchToken = {0};
	sgx_status_t sgxResult = SGX_ERROR_UNEXPECTED;
	int isTokenUpdated = 0;

	// FBDL 2.1: retrieving launch token saved by last transaction, else create new one.
	// building tokenPath
	if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, tokenPath)) {
		cout << "S_OK is not equal to SHGetFolderPathA result" << endl;
		strncpy_s(tokenPath, _countof(tokenPath), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	} 
	else {
		cout << "S_OK else" << endl;
		strncat_s(tokenPath, _countof(tokenPath), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+2);
	}

	//opening file token path, or create if non existent.
	cout << "attempting to open file" << endl;
	printf("token path is: %s", tokenPath);
	HANDLE tokenHandler = CreateFileA(tokenPath, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);

	if (tokenHandler == INVALID_HANDLE_VALUE) {
		printf("WARNING: Failed to create/open the launch token file \"%s\".\n", tokenPath);
	}
	else {
		// read token from saved file
		cout << "extracting token from saved file" << endl;
		DWORD readNum = 0;
		ReadFile(tokenHandler, launchToken, sizeof(sgx_launch_token_t), &readNum, NULL);
		if (readNum != 0 && readNum != sizeof(sgx_launch_token_t)) {
			memset(&launchToken, 0x0, sizeof(sgx_launch_token_t));
			cout << "WARNING: invalid launch token, cleared the launchToken, value to be used now is 0" << endl;
			printf("token path is: \"%s\".\n", tokenPath);
		}
	}

	// FBDL 2.2: call the sgx_create_enclave to initialize an enclave instance.
	int debugFlag = 1; // 1 ON, 0 OFF
	// NOTE: in project properties, we set Character Set to "Use Multi-Byte Character Set" from "use Unicode Character Set"
	sgxResult = sgx_create_enclave(ENCLAVE_FILENAME, debugFlag, &launchToken, &isTokenUpdated, &globalEid, NULL);

	if (sgxResult != SGX_SUCCESS) {
		cout << "error occurred in sgx_create_enclave" << endl;
		printErrorMessageFromSgxStatus(sgxResult);

		if (tokenHandler != INVALID_HANDLE_VALUE)
			CloseHandle(tokenHandler);

		return -1;
	}

	// FBDL 2.3: everything has been fine so save the launch token if it was updated.
	cout << "checking if launch token is to be saved" << endl;
	if (isTokenUpdated == FALSE || tokenHandler == INVALID_HANDLE_VALUE) {
		cout << "token is not updated or file handler was invalid, no saving will occur" << endl;
		if (tokenHandler != INVALID_HANDLE_VALUE)
			CloseHandle(tokenHandler);
		return 0;
	}

	cout << "Attempting saving" << endl;
	//flushing file cache
	FlushFileBuffers(tokenHandler);
	//setting access offset back to begin of file
	SetFilePointer(tokenHandler, 0, NULL, FILE_BEGIN);

	//writing back the token
	DWORD writeNum = 0;
	WriteFile(tokenHandler, launchToken, sizeof(sgx_launch_token_t), &writeNum, NULL);
	
	if(writeNum != sizeof(sgx_launch_token_t))
		cout << "WARNING: failed to save launch token" << endl;
	CloseHandle(tokenHandler);

	cout << "Launch token successfully stored" << endl;
	printf("%s\n", tokenPath);
	return 0;
}

void releaseBufferResources() {
	for (int i = 0; i < BUF_NUM; i++) {
		if(sealedDataBuffer.sealed_buf_ptr[i] != NULL) {
			free(sealedDataBuffer.sealed_buf_ptr[i]);
			sealedDataBuffer.sealed_buf_ptr[i] = NULL;
		}
	}
}

int SGX_CDECL main(int argc, char *argv[])
{
	// FBDL 1: check the instruction status if SGX is enabled in the device.
	if (querySgxStatus() < 0) {
		cout << "Press any key to exit" << endl;
		getchar();
		return -1;
	}

	// FBDL 2: intialize/create the enclave
	if (createEnclave() < 0) {
		cout << "Failed createEnclave()" << endl;
		getchar();
		return -1;
	}

	// FBDL 3: initialize the data holder for the sealed data
	cout << "Enclave created, initializing sealed data buffer" << endl;
	uint32_t sealedBufferItemLen = sizeof(sgx_sealed_data_t) + sizeof(uint32_t);
	for (int i = 0; i < BUF_NUM; i++)
	{
		//allocate memory for each buffer element that will be used later.
		sealedDataBuffer.sealed_buf_ptr[i] = (uint8_t *)malloc(sealedBufferItemLen);
		if(sealedDataBuffer.sealed_buf_ptr[i] == NULL) 
		{
			cout << "Out of Memory" << endl;
			//do clearing of ALL resources
			releaseBufferResources();
			//then exit since there's no point in continuing anymore.
			return -1;
		}
		//when an array index has been memory allocated, clean its contents
		memset(sealedDataBuffer.sealed_buf_ptr[i], 0, sealedBufferItemLen);
	}
	sealedDataBuffer.index = 0;


	// FBDL 4: Generate secret inside an enclave call and seal it
	int result = 0;
	enclave_generateRandomNumberAndSeal(globalEid, &result, &sealedDataBuffer);

	// FBDL 5: Save the contents
	cout << "printing muna dito sa labas" << endl;
	printf("Outside: %d\n", sealedDataBuffer.sealed_buf_ptr[0]);
	printf("Outside: %d\n", sealedDataBuffer.sealed_buf_ptr[1]);

	cout << "Cleaning up" << endl;
	releaseResources();

	cout << "destroying enclave" << endl;
	sgx_destroy_enclave(globalEid);
	
	cout << "Main run completed successfully!" << endl;
	getchar();
	return 0;
}