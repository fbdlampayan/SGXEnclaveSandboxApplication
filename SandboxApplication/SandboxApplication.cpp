#include "stdafx.h"
#include "sgx_defs.h"
#include "sgx_capable.h"
#include "sgx_uae_service.h" // has sgx_enable_device method
#include "sgx_tseal.h" // for sgx_sealed_data_t

#include "SandboxEnclave_u.h" // for OCALL print
#include "SandboxApplication.h"

#include <ShlObj.h> // for SHGetFolderPathA used in getting path of launch token
#include <iostream>
#include <io.h>

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
	sgx_status_t sgxResult = sgx_enable_device(&sgxDeviceStatus); // sgx-sdk-provided method to do it.

	if (sgxResult != SGX_SUCCESS) { // all sgx-methods has this status report, if it is successful or not
		cout << "Failed to get the SGX device status! Exiting now..." << endl;
		return -1;
	}
	else {
		switch (sgxDeviceStatus) { // in the case where sgx call has been successfully executed, check the resulting status
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
	if (S_OK != SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, tokenPath)) { //TODO: use SHGetKnownFolderPath  instead
		cout << "S_OK is not equal to SHGetFolderPathA result" << endl;
		strncpy_s(tokenPath, _countof(tokenPath), TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
	} 
	else {
		cout << "S_OK else" << endl;
		strncat_s(tokenPath, _countof(tokenPath), "\\" TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+2);
	}

	//opening file token path, or create if non existent.
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
	if (isTokenUpdated == FALSE || tokenHandler == INVALID_HANDLE_VALUE) {
		cout << "token is not updated or file handler was invalid, no saving will occur" << endl;
		if (tokenHandler != INVALID_HANDLE_VALUE)
			CloseHandle(tokenHandler);
		return 0;
	}

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

int file_exist (char *filename)
{
	if((_access(filename, 0)) != -1)
		return 1;
	else
		return 0;
}

long loadFile(const char* path, unsigned char *buf) {

	long dataLength;
	FILE *f = fopen(path, "rb");
	if (!f) {
		return -1;
	}
	fseek(f, 0, SEEK_END);
	dataLength = ftell(f);
	fseek(f, 0, SEEK_SET);

	unsigned char *buffer = new unsigned char[dataLength](); // alternative sa unsigned char buffer[length], kasi dapat si length ay const
	fread(buffer, sizeof(unsigned char), dataLength, f);
	fclose(f);

	memcpy(buf, buffer, dataLength);
	return dataLength;

}

int writeFile(char const *path, unsigned char *data, int length) {
	FILE *f = fopen(path, "w");
	int ret = fwrite(data, sizeof(unsigned char), length, f);
	if (ret != length) {
		printf("write_file error %d\n", ret);
	}
	fclose(f);
	return 0;
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
	const int SEALED_BLOB_MAX = 1024;
	sgx_status_t res = SGX_SUCCESS;
	uint32_t err;
	unsigned char blob[SEALED_BLOB_MAX] = {0};
	unsigned char sealedBlob[SEALED_BLOB_MAX] = {0};
	int blobLen, sealLen;
	sealLen = 0;
	blobLen = SEALED_BLOB_MAX;

	if(file_exist("fbdl.dat")) {
		cout << "file exists doing unsealing" << endl;
		
		// FBDL 4a: load file contents, and extract sealed contents
		long length = loadFile("fbdl.dat", sealedBlob);
		if(length == -1) {
			cout << "ERR: loading file error... exiting now" << endl;
			sgx_destroy_enclave(globalEid);
			return -1;
		}
		sealLen = length;
		cout << "loading successful" << endl;

		cout << "contents of sealedBlob from file" << endl;
		for (int i = 0; i < sealLen; i++)
			printf("%d", sealedBlob[i]);
		cout << endl;

		// FBDL 5a: feed the extracted sealed data unto the enclave for unsealing.
		cout << "sealLen value: " << sealLen << endl;
		res = enclave_UnsealBlob(globalEid, &err, sealedBlob, blobLen, &sealLen);
		if (res != SGX_SUCCESS) {
			cout << "unsealing failed" << endl;
			sgx_destroy_enclave(globalEid);
			return -1;
		}
	}
	else {
		cout << "file doesn't exist, creating enclave and secrets from scratch" << endl;
		
		res = enclave_generateAndSealBlob(globalEid, &err, blob, blobLen, &sealLen);
		if (res != SGX_SUCCESS) {
			cout << "enclave experiment failed" << endl;
			sgx_destroy_enclave(globalEid);
			return -1;
		}

		cout << "sealing done, preparing for save to file" << endl;
		memcpy(sealedBlob, blob, sealLen);

		cout << "contents of blob" << endl;
		for (int i = 0; i < sealLen; i++) {
			printf("%d", blob[i]);
		}
		cout << endl;
		cout << "contents of sealedBlob" << endl;
		for (int i = 0; i < sealLen; i++) {
			printf("%d", sealedBlob[i]);
		}
		cout << endl;

		cout << "attempting to save" << endl;
		if(writeFile("fbdl.dat", sealedBlob, sealLen))
			cout << "WARN: error occurred in saving, sealed data not saved" << endl;
	}


	cout << "destroying enclave" << endl;
	sgx_destroy_enclave(globalEid);
	
	cout << "Main run completed successfully!" << endl;
	getchar();
	return 0;
}