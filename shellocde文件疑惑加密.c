#include<windows.h>
#include<stdio.h>
int main() {
	const char* filePath = "data.bin"; // Replace with your file path

   // Open the file for reading
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
	for (int i = 0; i < fileSize; i++) {
		byteArray[i] = byteArray[i] ^ 'p';
	}


	// Specify the file path
	filePath = "data.bin"; // Replace with your desired file path

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
	if (!WriteFile(hFile, byteArray, fileSize , &bytesWritten, NULL)) {
		fprintf(stderr, "Error writing to the file\n");
		CloseHandle(hFile);
		return 1;
	}

	// Close the file handle
	CloseHandle(hFile);

	printf("Successfully wrote %lu bytes to the file: %s\n", bytesWritten, filePath);

}
