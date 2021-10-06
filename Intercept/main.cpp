
#include <ntifs.h>
#include <ntimage.h>

//ͨ��EPROCESS��ý�������
extern "C"
NTKERNELAPI UCHAR * PsGetProcessImageFileName(
	__in PEPROCESS pEProcess
);

//ȥ��д����
extern "C"
VOID DisableWriteProtect(PULONG pOldAttr);

//��ԭд����
extern "C"
VOID EnableWriteProtect(ULONG uOldAttr);



LARGE_INTEGER stCookie;							//ע��ע���֪ͨ�ص���״̬



//ע���֪ͨ�ص�����
NTSTATUS RegistryIntercept(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	UCHAR* ProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());
	
	switch ((REG_NOTIFY_CLASS)((DWORD64)Argument1))
	{

	case RegNtPreCreateKey:
		DbgPrint("[RegistryIntercept]RegidtryCreate��ProcessName is %s��CreateKey Path is %wZ", ProcessName, ((PREG_PRE_CREATE_KEY_INFORMATION)Argument2)->CompleteName);
		break;
	case RegNtPreCreateKeyEx:
		
		PREG_CREATE_KEY_INFORMATION CreateInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
		if (CreateInfo->CompleteName->Buffer[0] == L'\\')						//����Ǿ���·��
		{
			DbgPrint("[RegistryIntercept]RegidtryCreate��ProcessName is %s��CreateKey Path is %wZ", ProcessName, CreateInfo->CompleteName);
		}
		else																	//��������·��
		{
			CHAR strrRootPath[256] = { 0 };
			ULONG uReturnLength = 0;
			POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)strrRootPath;
			if (CreateInfo->RootObject != NULL)
				ObQueryNameString(CreateInfo->RootObject, pNameInfo, sizeof(strrRootPath), &uReturnLength);

			DbgPrint("[RegistryIntercept]RegidtryCreate��ProcessName is %s��CreateKey Path is %wZ\\%wZ", ProcessName, pNameInfo->Name, CreateInfo->CompleteName);

		}
		CreateInfo->CompleteName;
		break;
	}
	return STATUS_SUCCESS;														//��ʾ����ֹע���Ĳ���
}


//ж��ע���֪ͨ�ص�
void UnInstallRegistryHook()
{
	CmUnRegisterCallback(stCookie);
	DbgPrint("[RegistryIntercept]The Registry HOOK is UnInstall!");
}

//��װע���֪ͨ�ص�
void InstallRegistryHook()
{
	NTSTATUS	ntstatus;
	ntstatus = CmRegisterCallback(RegistryIntercept, NULL, &stCookie);

	if (NT_SUCCESS(ntstatus))
	{
		DbgPrint("[RegistryIntercept]The Registry HOOK is install successfully!");
	}
	else
	{
		DbgPrint("[RegistryIntercept]The Registry HOOK is install fail��NTSTATUS��%d", ntstatus);
	}

}







//����sysģ����ڵ�
PVOID64 ResolvingSysAddress(PVOID pImageAddress)
{
	PVOID pAddressOfEntryPoint = NULL;							//ָ�����ʵ�ʵ���ڵ�
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	PIMAGE_FILE_HEADER pFileHead = NULL;
	PIMAGE_OPTIONAL_HEADER pOptHead = NULL;

	//��ʼ����
	if (pImageAddress == NULL)
		return NULL;

	pDosHead = (PIMAGE_DOS_HEADER)pImageAddress;
	pNtHead = (PIMAGE_NT_HEADERS)(pDosHead->e_lfanew + (char*)pImageAddress);
	pFileHead = (PIMAGE_FILE_HEADER)&pNtHead->FileHeader;
	pOptHead = (PIMAGE_OPTIONAL_HEADER)&pNtHead->OptionalHeader;

	//�ж��Ƿ���PEͷ
	if (pDosHead->e_magic != 0x5A4D && pNtHead->Signature != 0x5045)
		return NULL;
	pAddressOfEntryPoint = pOptHead->AddressOfEntryPoint + (char*)pImageAddress;

	return pAddressOfEntryPoint;

}


//����DLLģ����ڵ�
PVOID64 ResolvingDllAddress(PVOID pImageAddress)
{
	PVOID pAddressOfEntryPoint = NULL;							//ָ��PEͷ�е�AddressOfEntryPoint
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	PIMAGE_FILE_HEADER pFileHead = NULL;
	PIMAGE_OPTIONAL_HEADER pOptHead = NULL;

	//��ʼ����
	if (pImageAddress == NULL)
		return NULL;

	pDosHead = (PIMAGE_DOS_HEADER)pImageAddress;
	pNtHead = (PIMAGE_NT_HEADERS)(pDosHead->e_lfanew + (char*)pImageAddress);
	pFileHead = (PIMAGE_FILE_HEADER)&pNtHead->FileHeader;
	pOptHead = (PIMAGE_OPTIONAL_HEADER)&pNtHead->OptionalHeader;

	//�ж��Ƿ���PEͷ
	if (pDosHead->e_magic != 0x5A4D && pNtHead->Signature != 0x5045)
		return NULL;

	pAddressOfEntryPoint = &pOptHead->AddressOfEntryPoint;
	return pAddressOfEntryPoint;

}



//��Unicode��ģ�����Ƹ�ΪANSI�����
void UnicodeToChar(PUNICODE_STRING stUnicodeString, UCHAR * szString)
{
	ANSI_STRING stAnsiString;
	RtlUnicodeStringToAnsiString(&stAnsiString, stUnicodeString, TRUE);
	strncpy((char*)szString, stAnsiString.Buffer, stAnsiString.Length);
	//RtlUnicodeStringToAnsiString�����ڲ���ʵ��
	//RtlUnicodeToMultiByteN((PCHAR)szString, 256, NULL, stUnicodeString->Buffer, 2 * RtlxUnicodeStringToOemSize(stUnicodeString));
	strcpy((char*)szString,strrchr((char*)szString,'\\') + 1);
	RtlFreeAnsiString(&stAnsiString);
}


//ģ�鹳�ӻص�����
void PloadImageNotifyRoutine(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo
)
{
	ULONG	OldAttr = 0;
	PVOID64 pEntryAddress = 0;											//ģ����ڵ��ַ
	PVOID64 pNewEntryAddress = 0;										//������DLL�µĳ�����ڵ�
	UCHAR	szInterceptModule[] = "AntiDll.dll";						//�����ص�ģ�������
	UCHAR szModuleName[256] = {0};										//���ص�ģ�������
	UCHAR szShellCode[] = "\xB8\x22\x00\x00\xC0\xC3";					//"mov eax,0xc0000022, ret"���ؾܾ����ʴ����������޷�����
	UCHAR szNewEntryRvaAddress[] = "\x00\x0a\x00\x00";					//������dll����ڵ�RVARΪ0x0a00

	UNREFERENCED_PARAMETER(ProcessId);
	UnicodeToChar(FullImageName, szModuleName);

	if (ImageInfo->SystemModeImage == 1)								//���ص�ģ��Ϊsys
	{
		if (strcmp((char*)szModuleName, (char*)szInterceptModule) == 0)
		{
			DbgPrint("[ModuleIntercept]the sys Module is Intercept��%wZ",FullImageName);
			pEntryAddress = ResolvingSysAddress(ImageInfo->ImageBase);	//�õ�ģ����ڵ��ַ
			if (MmIsAddressValid(pEntryAddress))
			{
				DisableWriteProtect(&OldAttr);
				memcpy(pEntryAddress, szShellCode, 6);
				EnableWriteProtect(OldAttr);
			}

		}
		else
		{
			DbgPrint("[ModuleIntercept]the sys Module is Load��%wZ", FullImageName);

		}
	}
	else if(ImageInfo->SystemModeImage == 0)							//���ص�ģ��Ϊdll
	{
		if (strcmp((char*)szModuleName, (char*)szInterceptModule) == 0)
		{
			DbgPrint("[ModuleIntercept]the dll Module is Intercept��%wZ", FullImageName);
			pEntryAddress = ResolvingDllAddress(ImageInfo->ImageBase);
			pNewEntryAddress = (UCHAR*)ImageInfo->ImageBase + 0x0a00;	//�µĳ�����ڵ�

			if (MmIsAddressValid(pEntryAddress))
			{
				DisableWriteProtect(&OldAttr);
				memcpy(pEntryAddress, szNewEntryRvaAddress, 4);			//��DLL�ļ���pe�ļ�ͷ��д���µĳ�����ڵ�Ϊ0x0a00
				memcpy(pNewEntryAddress, szShellCode, 6);				//���µĳ�����ڵ�д��shellcode
				EnableWriteProtect(OldAttr);
			}
		}
		else
		{
			DbgPrint("[ModuleIntercept]the dll Module is Load��%wZ", FullImageName);
		}
	}

	
}

//��װģ�鹳��
void InstallModuleHook()
{
	NTSTATUS ntstatus;

	ntstatus = PsSetLoadImageNotifyRoutine(PloadImageNotifyRoutine);
	if (NT_SUCCESS(ntstatus))
	{

		DbgPrint("[ModuleIntercept]the Module Hook is install successfully!");
	}
	else
	{
		DbgPrint("[ModuleIntercept]the Module Hook is install fail!:the NTSTATUS is %d", ntstatus);
	}

}

//ж��ģ�鹳��
void UnInstallModuleHook()
{
	PsRemoveLoadImageNotifyRoutine(PloadImageNotifyRoutine);
	DbgPrint("[ModuleIntercept]the Module Hook is UnInstall");
}






//�̹߳��ӻص�����
void ThreadIntercept(
	HANDLE ProcessID, 
	HANDLE ThreadID, 
	BOOLEAN Create
)
{
	NTSTATUS ntstatus;
	PEPROCESS Process = NULL;
	PETHREAD Thread = NULL;
	UCHAR* szImageFileName;
	UCHAR szInterceptProcessName[] = "";				//�����صĽ�������
	DWORD64 dwThreadAddress = 0;
	//PRKAPC_STATE stRkapcState = NULL;
	ULONG uOldAttr = 0;

	ntstatus = PsLookupProcessByProcessId(ProcessID, &Process);			//��ȡEPROCESS
	if (!NT_SUCCESS(ntstatus))
	{
		DbgPrint("[ThreadIntercept]the EPROCESS is not!");
		return;
	}

	ntstatus = PsLookupThreadByThreadId(ThreadID, &Thread);				//��ȡETHREAD
	if (!NT_SUCCESS(ntstatus))
	{
		DbgPrint("[ThreadIntercept]the ETHREAD is not!");
		ObDereferenceObject(Process);
		return;
	}

	szImageFileName = PsGetProcessImageFileName(Process);				//��ȡ��Ӧ��������

	if (Create)
	{
		if (strcmp((char*)szInterceptProcessName, (char*)szImageFileName) == 0)
		{
			//��Ϊ��������߳�����explorer.exe���̴߳����ģ������������������explorer.exe���߳���
			//KeStackAttachProcess(Process, stRkapcState);
			KeAttachProcess(Process);									//�л�����Ӧ���̿ռ���������
			dwThreadAddress = (*((DWORD64*)((UCHAR*)Thread + 0x410)));	//�õ��̻߳ص�������ڵ��ַ
			
			if (MmIsAddressValid((PVOID)dwThreadAddress))
			{
				//DbgBreakPoint();
				DbgPrint("[ThreadIntercept]the Thread is Intercept!��[PID��%d][TID��%d]",ProcessID, ThreadID);
				DisableWriteProtect(&uOldAttr);							//ȥ��д����
				*(DWORD32*)dwThreadAddress = 0xc3;
				EnableWriteProtect(uOldAttr);							//�ָ�д����

			}
			
			//KeUnstackDetachProcess(stRkapcState);
			KeDetachProcess();											//�ָ����̿ռ�������
			
		}
		else
		{
			DbgPrint("[ThreadIntercept]the Thread is Create��[TID:%d]", ThreadID);
		}

	}
	else
		DbgPrint("[ThreadIntercept]the Thread is Exit:[TID:%d]", ThreadID);

	if(Process!=NULL)
		ObDereferenceObject(Process);										//�������ü�����һ
	if (Thread!=NULL)
		ObDereferenceObject(Thread);

}


//��װ�̹߳���
void InstallThreadHook()
{
	NTSTATUS ntstatus;
	ntstatus = PsSetCreateThreadNotifyRoutine(ThreadIntercept);
	if (NT_SUCCESS(ntstatus))
	{
		DbgPrint("[ThreadIntercept]the Thread Hook is Install!");
	}
	else
	{
		DbgPrint("[ThreadIntercept]the Thread Hook is Install fail��the NTSTATUS is %d", ntstatus);
	}
}

//ж���̹߳���
void UnInstallThreadHook()
{
	PsRemoveCreateThreadNotifyRoutine(ThreadIntercept);
	DbgPrint("[ThreadIntercept]the Thread Hook is UnInstall!");
}






//���̹��ӻص�����
void ProcessIntercept(
	PEPROCESS pEprocess, 
	HANDLE ProcessID, 
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UCHAR stInterceptProcess[] = "";					//�����صĽ�������
	UCHAR* stProcessName;

	stProcessName = PsGetProcessImageFileName(pEprocess);

	if (CreateInfo != NULL)
	{
		if (strcmp((char*)stProcessName, (char*)stInterceptProcess)== 0)
		{
			DbgPrint("[processIntercept]the Process is Intercept!");
			CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;					//ʹ�˽��̴���ʧ��
		}
		else
		{
			DbgPrint("[processIntercept]the Process is Cteate��[PID��%d]", ProcessID);
		}
	}
	else
		DbgPrint("[processIntercept]the Process is Exit��[PID��%d]", ProcessID);
}

//��װ���̹���
void InstallProcessHook()
{
	NTSTATUS ntstatus;

	ntstatus = PsSetCreateProcessNotifyRoutineEx(ProcessIntercept, FALSE);
	if (NT_SUCCESS(ntstatus))
	{
		DbgPrint("[processIntercept]the Process HOOK is install successfully!");
	}
	else
	{
		DbgPrint("[processIntercept]the Process HOOK is install fail!��NTSTATUS is %d", ntstatus);
	}
}


//ж�ؽ��̹���
void UnInstallProcessHook()
{

	PsSetCreateProcessNotifyRoutineEx(ProcessIntercept, TRUE);
	DbgPrint("[processIntercept]the HOOK is Uninstall!");

}







//����ж�غ���
void DriverUnload(PDRIVER_OBJECT pDriver_Object)
{
	UNREFERENCED_PARAMETER(pDriver_Object);
	//UnInstallProcessHook();					//ж�ؽ��̹���
	//UnInstallThreadHook();					//ж���̹߳���
	//UnInstallModuleHook();					//ж��ģ�鹳��
	UnInstallRegistryHook();				//ж��ע�����
}




//������ں���
extern "C"
NTSTATUS DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = DriverUnload;
	

	DbgPrint("[Intercept]the Driver is Load!");
	//InstallProcessHook();					//��װ���̹���
	//InstallThreadHook();					//��װ�̹߳���
	//InstallModuleHook();					//��װģ�鹳��
	InstallRegistryHook();			//��װע�����
	return STATUS_SUCCESS;
}





