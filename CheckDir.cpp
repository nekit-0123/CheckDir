#include <windows.h>

// Добавить в автозагрузку
LONG InsertAutoRun()
{
	HKEY hKey;
	char szPath[256];
	GetModuleFileNameA(NULL, szPath, sizeof(szPath));
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

	char *CheckFile = new char[size + sizeof("stopme.txt")+1];
	ZeroMemory(CheckFile, size + sizeof("stopme.txt"));
	strcat_s(CheckFile, size, WinTemp);
	strcat_s(CheckFile, size + sizeof("stopme.txt"), "stopme.txt");

	while (true)
	{
		if (isFileExist(CheckFile))
		{
			DeleteAutoRun();
			break;
		}

		DWORD dwBytesReturned = 0;
		if (ReadDirectoryChangesW(hDir, (LPVOID)&strFileNotifyInfo, sizeof(strFileNotifyInfo), FALSE, FILE_NOTIFY_CHANGE_LAST_WRITE, &dwBytesReturned, NULL, NULL) == 0)
			break;
		else
		{
			const char* Message = (char *)strFileNotifyInfo.FileName;	
			if (ReportEventA(event_log, EVENTLOG_SUCCESS, 0, 0, NULL, 1, 0, &Message, NULL) == 0)
				break;
		}

		Sleep(20);
	}
}

int main()
{
	const char * commandStr = GetCommandLineA();

	char WinTempStr[MAX_PATH + 1];
	GetTempPath(MAX_PATH + 1, WinTempStr); // Получение директории папки temp
	size_t lsize = strlen(WinTempStr) + 1;
	char *strPath = new char[lsize + sizeof("CheckDir.exe")];
	ZeroMemory(strPath, lsize);
	strcat_s(strPath, lsize, WinTempStr);
	strcat_s(strPath, lsize + sizeof("CheckDir.exe"), "CheckDir.exe");

	char OurDir[MAX_PATH + 1];
	GetCurrentDirectory(MAX_PATH + 1, OurDir);	// Получение директории откуда запущены

	// Если мы не в папке темп
	if (WinTempStr != OurDir)
	{
		if (CopyFile(commandStr, strPath, 1) > 0)
			ShellExecute(NULL, "open", commandStr, strPath, NULL, SW_RESTORE);

		delete[] strPath;
		strPath = nullptr;

		return 0;
	}
	else if (WinTempStr == OurDir)
	{
		if (isFileExist(commandStr)) 
			DeleteFile(commandStr);

			InsertAutoRun();
	}

	CheckTempRath(WinTempStr, lsize);

	return 0;
}