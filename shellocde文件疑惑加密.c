#include<windows.h>
#include<stdio.h>

inline void MYS_ecureZeroMemory(char* fuck, int number) {
	for (int i = 0; i < number; i++) {
		fuck[i] = 0;
	}
}

void FBXorCrypt(char* str, size_t len) {
	int intArr[100] = { 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1 };
	int i;
	for (i = 0; i < len; i++) {
		str[i] = intArr[i] ^ str[i];
	}
}
int main(int argc,char* argv[]) {
	const char* filePath = argv[1]; // Replace with your file path   // Open the file for reading
	HANDLE hFile = CreateFileA(
		filePath,                   // File path
		GENERIC_READ,               // Access mode (read)
		FILE_SHARE_READ,            // Share mode (allow others to read)
		NULL,                       // Security attributes (default)
		OPEN_EXISTING,              // Creation disposition (open only if it exists)
		FILE_ATTRIBUTE_NORMAL,      // File attributes (normal)
		NULL                        // Template file (not used)
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Error opening the file\n");
		return 1;
	}

	// Get the file size
	DWORD fileSize = GetFileSize(hFile, NULL);
	if (fileSize == INVALID_FILE_SIZE) {
		fprintf(stderr, "Error getting file size\n");
		CloseHandle(hFile);
		return 1;
	}

	// Allocate memory for the byte array
	BYTE* byteArray = (BYTE*)malloc(fileSize);
	if (byteArray == NULL) {
		fprintf(stderr, "Error allocating memory\n");
		CloseHandle(hFile);
		return 1;
	}

	// Read the binary data from the file into the byte array
	DWORD bytesRead;
	if (!ReadFile(hFile, byteArray, fileSize, &bytesRead, NULL)) {
		fprintf(stderr, "Error reading from the file\n");
		CloseHandle(hFile);
		free(byteArray);
		return 1;
	}

	// Close the file handle
	CloseHandle(hFile);

	// Now byteArray contains the binary data from the file

	printf("Successfully read %lu bytes from the file: %s\n", bytesRead, filePath);

	// Free the memory allocated for the byte array
	//free(byteArray);
	// 使用疑惑解密byteArray
	char _fuckingstring[100];
	// 加密密码  ironman
	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 104; _fuckingstring[1] = 115; _fuckingstring[2] = 110; _fuckingstring[3] = 111; _fuckingstring[4] = 108; _fuckingstring[5] = 96; _fuckingstring[6] = 111; _fuckingstring[7] = 0; FBXorCrypt(_fuckingstring, 8);
	for (int i = 0; i < fileSize; i++) {
		byteArray[i] = byteArray[i] ^ (_fuckingstring[i % 7]);
	}


	// 前面有60bytes是废的，我们可以可以损坏掉，这样他就不是一个合法的PE文件了，就算别人知道了我们的疑惑key，也还是需要进一步的分析
	MYS_ecureZeroMemory((char*)_fuckingstring, 100); _fuckingstring[0] = 76; _fuckingstring[1] = 88; _fuckingstring[2] = 82; _fuckingstring[3] = 94; _fuckingstring[4] = 100; _fuckingstring[5] = 98; _fuckingstring[6] = 116; _fuckingstring[7] = 115; _fuckingstring[8] = 100; _fuckingstring[9] = 91; _fuckingstring[10] = 100; _fuckingstring[11] = 115; _fuckingstring[12] = 110; _fuckingstring[13] = 76; _fuckingstring[14] = 100; _fuckingstring[15] = 108; _fuckingstring[16] = 110; _fuckingstring[17] = 115; _fuckingstring[18] = 120; _fuckingstring[19] = 41; _fuckingstring[20] = 41; _fuckingstring[21] = 98; _fuckingstring[22] = 105; _fuckingstring[23] = 96; _fuckingstring[24] = 115; _fuckingstring[25] = 43; _fuckingstring[26] = 40; _fuckingstring[27] = 94; _fuckingstring[28] = 103; _fuckingstring[29] = 116; _fuckingstring[30] = 98; _fuckingstring[31] = 106; _fuckingstring[32] = 104; _fuckingstring[33] = 111; _fuckingstring[34] = 102; _fuckingstring[35] = 114; _fuckingstring[36] = 117; _fuckingstring[37] = 115; _fuckingstring[38] = 104; _fuckingstring[39] = 111; _fuckingstring[40] = 102; _fuckingstring[41] = 45; _fuckingstring[42] = 48; _fuckingstring[43] = 49; _fuckingstring[44] = 49; _fuckingstring[45] = 40; _fuckingstring[46] = 58; _fuckingstring[47] = 94; _fuckingstring[48] = 103; _fuckingstring[49] = 116; _fuckingstring[50] = 98; _fuckingstring[51] = 106; _fuckingstring[52] = 104; _fuckingstring[53] = 111; _fuckingstring[54] = 102; _fuckingstring[55] = 114; _fuckingstring[56] = 117; _fuckingstring[57] = 115; _fuckingstring[58] = 104; _fuckingstring[59] = 111; _fuckingstring[60] = 0; FBXorCrypt(_fuckingstring, 61);
	for (int i = 0; i < 60; i++) {
		byteArray[i] = byteArray[i] ^ (_fuckingstring[i % 60]);
	}


	// Specify the file path
	filePath = argv[1]; // Replace with your desired file path

	// Create or open the file for writing
	hFile = CreateFileA(
		filePath,                   // File path
		GENERIC_WRITE,              // Access mode (write)
		0,                          // Share mode (no sharing)
		NULL,                       // Security attributes (default)
		CREATE_ALWAYS,              // Creation disposition (create or overwrite)
		FILE_ATTRIBUTE_NORMAL,      // File attributes (normal)
		NULL                        // Template file (not used)
	);

	if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Error creating/opening the file\n");
		return 1;
	}

	// Write the byte array to the file
	DWORD bytesWritten;
	if (!WriteFile(hFile, byteArray, fileSize, &bytesWritten, NULL)) {
		fprintf(stderr, "Error writing to the file\n");
		CloseHandle(hFile);
		return 1;
	}

	// Close the file handle
	CloseHandle(hFile);

	printf("Successfully wrote %lu bytes to the file: %s\n", bytesWritten, filePath);

}
