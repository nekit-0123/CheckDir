#include <windows.h>
#include <string.h>

// Добавить в автозагрузку
LONG InsertAutoRun()
{
	HKEY hKey = NULL;
	char szPath[256] = { NULL };
	if (GetModuleFileNameA(NULL, szPath, sizeof(szPath)) <= 0)
	{
		std::cout<<"Error GetModuleFileName";
		return -1;
	}

	RegCreateKeyEx(HKEY_LOCAL_MACHINE,
		"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
		NULL,
		0,
		REG_OPTION_NON_VOLATILE,
		KEY_SET_VALUE,
		NULL,
		&hKey,
		NULL);

	if (hKey != NULL)
	{
		RegSetValueEx(hKey, "Check Dir", NULL, REG_SZ, (LPBYTE)szPath, (DWORD)strlen(szPath));
		RegCloseKey(hKey);
	}
	else 
	{
		std::cout<<"Error RegCreateKeyEx";
		return -2;
	}

	return 0;
}

// Удалить из автозагрузки
LONG DeleteAutoRun()
{
	return RegDeleteKey(HKEY_LOCAL_MACHINE, "Check Dir");
}

// Проверка на существование файла
bool isFileExist(LPCSTR strFileName) {

	DWORD ret = GetFileAttributesA(strFileName);
	return ((ret == INVALID_FILE_ATTRIBUTES) && !(ret & FILE_ATTRIBUTE_DIRECTORY));
}

void CheckTempRath(const char* WinTemp, size_t size)
{
	HANDLE event_log = RegisterEventSource(NULL, "My Log");
	FILE_NOTIFY_INFORMATION strFileNotifyInfo;
	HANDLE hDir = CreateFile(
		WinTemp,
		FILE_LIST_DIRECTORY,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS,
		NULL);

	if (hDir == INVALID_HANDLE_VALUE)
	{
		std::cout<<"Error CreateFile";
		return;
	}

	char *CheckFile = new char[size + sizeof("stopme.txt")+1];
	ZeroMemory(CheckFile, size + sizeof("stopme.txt"));
	strcat_s(CheckFile, size, WinTemp);
	strcat_s(CheckFile, size + sizeof("stopme.txt"), "stopme.txt");

	while (true)
	{
		if (isFileExist(CheckFile))
		{
			if (DeleteAutoRun() != 0)
				std::cout<<"Error RegDeleteKey";
			break;
		}

		DWORD dwBytesReturned = 0;
		if (ReadDirectoryChangesW(hDir, (LPVOID)&strFileNotifyInfo, sizeof(strFileNotifyInfo), FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE, &dwBytesReturned, NULL, NULL) == 0)
		{
			std::cout<<"Error ReadDirectoryChangesW";
			break;
		}
		else
		{
			const char* Message = (char *)strFileNotifyInfo.FileName;	
			if (ReportEventA(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, &Message, NULL) == 0)
			{
				std::cout<<"Error ReportEventA";
				break;
			}
		}

		Sleep(20);
	}

	delete[] CheckFile;
	CheckFile = nullptr;
}

int main()
{
	const char * commandStr = GetCommandLineA();
	char WinTempStr[MAX_PATH + 1];
	if (GetTempPath(MAX_PATH + 1, WinTempStr) == 0)// Получение директории папки temp
	{
		std::cout<<"Error ReadDirectoryChangesW";
		return -1;
	}

	size_t lsize = strlen(WinTempStr) + 1;
	char OurDir[MAX_PATH + 1];
	if (GetCurrentDirectory(MAX_PATH + 1, OurDir) == 0)	// Получение директории откуда запущены
	{
		std::cout<<"Error GetCurrentDirectory";
		return -1;
	}

	// Если мы не в папке темп
	
	if (strcmp(WinTempStr, OurDir) != 0)
	{
		char *strPath = new char[lsize + sizeof("CheckDir.exe")];
		ZeroMemory(strPath, lsize);
		strcat_s(strPath, lsize, WinTempStr);
		strcat_s(strPath, lsize + sizeof("CheckDir.exe"), "CheckDir.exe");

		if (CopyFile(commandStr, strPath, 1) > 0)
			ShellExecute(NULL, "open", commandStr, strPath, NULL, SW_RESTORE);
		else 
			std::cout<<"Error CopyFile";

		delete[] strPath;
		strPath = nullptr;

		return 0;
	}
	else if (strcmp(WinTempStr, OurDir) == 0)
	{
		if (isFileExist(commandStr)) 
			DeleteFile(commandStr);

			if (InsertAutoRun() != 0)
			 return -1; 
	}

	CheckTempRath(WinTempStr, lsize);

	return 0;
}