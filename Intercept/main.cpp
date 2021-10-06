
#include <ntifs.h>
#include <ntimage.h>

//通过EPROCESS获得进程名称
extern "C"
NTKERNELAPI UCHAR * PsGetProcessImageFileName(
	__in PEPROCESS pEProcess
);

//去除写保护
extern "C"
VOID DisableWriteProtect(PULONG pOldAttr);

//还原写保护
extern "C"
VOID EnableWriteProtect(ULONG uOldAttr);



LARGE_INTEGER stCookie;							//注册注册表通知回调的状态



//注册表通知回调函数
NTSTATUS RegistryIntercept(PVOID CallbackContext, PVOID Argument1, PVOID Argument2)
{
	UNREFERENCED_PARAMETER(CallbackContext);
	UCHAR* ProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());
	
	switch ((REG_NOTIFY_CLASS)((DWORD64)Argument1))
	{

	case RegNtPreCreateKey:
		DbgPrint("[RegistryIntercept]RegidtryCreate：ProcessName is %s，CreateKey Path is %wZ", ProcessName, ((PREG_PRE_CREATE_KEY_INFORMATION)Argument2)->CompleteName);
		break;
	case RegNtPreCreateKeyEx:
		
		PREG_CREATE_KEY_INFORMATION CreateInfo = (PREG_CREATE_KEY_INFORMATION)Argument2;
		if (CreateInfo->CompleteName->Buffer[0] == L'\\')						//如果是绝对路径
		{
			DbgPrint("[RegistryIntercept]RegidtryCreate：ProcessName is %s，CreateKey Path is %wZ", ProcessName, CreateInfo->CompleteName);
		}
		else																	//如果是相对路径
		{
			CHAR strrRootPath[256] = { 0 };
			ULONG uReturnLength = 0;
			POBJECT_NAME_INFORMATION pNameInfo = (POBJECT_NAME_INFORMATION)strrRootPath;
			if (CreateInfo->RootObject != NULL)
				ObQueryNameString(CreateInfo->RootObject, pNameInfo, sizeof(strrRootPath), &uReturnLength);

			DbgPrint("[RegistryIntercept]RegidtryCreate：ProcessName is %s，CreateKey Path is %wZ\\%wZ", ProcessName, pNameInfo->Name, CreateInfo->CompleteName);

		}
		CreateInfo->CompleteName;
		break;
	}
	return STATUS_SUCCESS;														//表示不阻止注册表的操作
}


//卸载注册表通知回调
void UnInstallRegistryHook()
{
	CmUnRegisterCallback(stCookie);
	DbgPrint("[RegistryIntercept]The Registry HOOK is UnInstall!");
}

//安装注册表通知回调
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
		DbgPrint("[RegistryIntercept]The Registry HOOK is install fail：NTSTATUS：%d", ntstatus);
	}

}







//解析sys模块入口点
PVOID64 ResolvingSysAddress(PVOID pImageAddress)
{
	PVOID pAddressOfEntryPoint = NULL;							//指向程序实际的入口点
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	PIMAGE_FILE_HEADER pFileHead = NULL;
	PIMAGE_OPTIONAL_HEADER pOptHead = NULL;

	//开始解析
	if (pImageAddress == NULL)
		return NULL;

	pDosHead = (PIMAGE_DOS_HEADER)pImageAddress;
	pNtHead = (PIMAGE_NT_HEADERS)(pDosHead->e_lfanew + (char*)pImageAddress);
	pFileHead = (PIMAGE_FILE_HEADER)&pNtHead->FileHeader;
	pOptHead = (PIMAGE_OPTIONAL_HEADER)&pNtHead->OptionalHeader;

	//判断是否是PE头
	if (pDosHead->e_magic != 0x5A4D && pNtHead->Signature != 0x5045)
		return NULL;
	pAddressOfEntryPoint = pOptHead->AddressOfEntryPoint + (char*)pImageAddress;

	return pAddressOfEntryPoint;

}


//解析DLL模块入口点
PVOID64 ResolvingDllAddress(PVOID pImageAddress)
{
	PVOID pAddressOfEntryPoint = NULL;							//指向PE头中的AddressOfEntryPoint
	PIMAGE_DOS_HEADER pDosHead = NULL;
	PIMAGE_NT_HEADERS pNtHead = NULL;
	PIMAGE_FILE_HEADER pFileHead = NULL;
	PIMAGE_OPTIONAL_HEADER pOptHead = NULL;

	//开始解析
	if (pImageAddress == NULL)
		return NULL;

	pDosHead = (PIMAGE_DOS_HEADER)pImageAddress;
	pNtHead = (PIMAGE_NT_HEADERS)(pDosHead->e_lfanew + (char*)pImageAddress);
	pFileHead = (PIMAGE_FILE_HEADER)&pNtHead->FileHeader;
	pOptHead = (PIMAGE_OPTIONAL_HEADER)&pNtHead->OptionalHeader;

	//判断是否是PE头
	if (pDosHead->e_magic != 0x5A4D && pNtHead->Signature != 0x5045)
		return NULL;

	pAddressOfEntryPoint = &pOptHead->AddressOfEntryPoint;
	return pAddressOfEntryPoint;

}



//将Unicode的模块名称改为ANSI编码的
void UnicodeToChar(PUNICODE_STRING stUnicodeString, UCHAR * szString)
{
	ANSI_STRING stAnsiString;
	RtlUnicodeStringToAnsiString(&stAnsiString, stUnicodeString, TRUE);
	strncpy((char*)szString, stAnsiString.Buffer, stAnsiString.Length);
	//RtlUnicodeStringToAnsiString函数内部的实现
	//RtlUnicodeToMultiByteN((PCHAR)szString, 256, NULL, stUnicodeString->Buffer, 2 * RtlxUnicodeStringToOemSize(stUnicodeString));
	strcpy((char*)szString,strrchr((char*)szString,'\\') + 1);
	RtlFreeAnsiString(&stAnsiString);
}


//模块钩子回调函数
void PloadImageNotifyRoutine(
	PUNICODE_STRING FullImageName,
	HANDLE ProcessId,
	PIMAGE_INFO ImageInfo
)
{
	ULONG	OldAttr = 0;
	PVOID64 pEntryAddress = 0;											//模块入口点地址
	PVOID64 pNewEntryAddress = 0;										//被拦截DLL新的程序入口点
	UCHAR	szInterceptModule[] = "AntiDll.dll";						//待拦截的模块的名称
	UCHAR szModuleName[256] = {0};										//加载的模块的名称
	UCHAR szShellCode[] = "\xB8\x22\x00\x00\xC0\xC3";					//"mov eax,0xc0000022, ret"返回拒绝访问错误码让其无法加载
	UCHAR szNewEntryRvaAddress[] = "\x00\x0a\x00\x00";					//被拦截dll新入口的RVAR为0x0a00

	UNREFERENCED_PARAMETER(ProcessId);
	UnicodeToChar(FullImageName, szModuleName);

	if (ImageInfo->SystemModeImage == 1)								//加载的模块为sys
	{
		if (strcmp((char*)szModuleName, (char*)szInterceptModule) == 0)
		{
			DbgPrint("[ModuleIntercept]the sys Module is Intercept：%wZ",FullImageName);
			pEntryAddress = ResolvingSysAddress(ImageInfo->ImageBase);	//得到模块入口点地址
			if (MmIsAddressValid(pEntryAddress))
			{
				DisableWriteProtect(&OldAttr);
				memcpy(pEntryAddress, szShellCode, 6);
				EnableWriteProtect(OldAttr);
			}

		}
		else
		{
			DbgPrint("[ModuleIntercept]the sys Module is Load：%wZ", FullImageName);

		}
	}
	else if(ImageInfo->SystemModeImage == 0)							//加载的模块为dll
	{
		if (strcmp((char*)szModuleName, (char*)szInterceptModule) == 0)
		{
			DbgPrint("[ModuleIntercept]the dll Module is Intercept：%wZ", FullImageName);
			pEntryAddress = ResolvingDllAddress(ImageInfo->ImageBase);
			pNewEntryAddress = (UCHAR*)ImageInfo->ImageBase + 0x0a00;	//新的程序入口点

			if (MmIsAddressValid(pEntryAddress))
			{
				DisableWriteProtect(&OldAttr);
				memcpy(pEntryAddress, szNewEntryRvaAddress, 4);			//向DLL文件的pe文件头中写入新的程序入口点为0x0a00
				memcpy(pNewEntryAddress, szShellCode, 6);				//向新的程序入口点写入shellcode
				EnableWriteProtect(OldAttr);
			}
		}
		else
		{
			DbgPrint("[ModuleIntercept]the dll Module is Load：%wZ", FullImageName);
		}
	}

	
}

//安装模块钩子
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

//卸载模块钩子
void UnInstallModuleHook()
{
	PsRemoveLoadImageNotifyRoutine(PloadImageNotifyRoutine);
	DbgPrint("[ModuleIntercept]the Module Hook is UnInstall");
}






//线程钩子回调函数
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
	UCHAR szInterceptProcessName[] = "";				//待拦截的进程名称
	DWORD64 dwThreadAddress = 0;
	//PRKAPC_STATE stRkapcState = NULL;
	ULONG uOldAttr = 0;

	ntstatus = PsLookupProcessByProcessId(ProcessID, &Process);			//获取EPROCESS
	if (!NT_SUCCESS(ntstatus))
	{
		DbgPrint("[ThreadIntercept]the EPROCESS is not!");
		return;
	}

	ntstatus = PsLookupThreadByThreadId(ThreadID, &Thread);				//获取ETHREAD
	if (!NT_SUCCESS(ntstatus))
	{
		DbgPrint("[ThreadIntercept]the ETHREAD is not!");
		ObDereferenceObject(Process);
		return;
	}

	szImageFileName = PsGetProcessImageFileName(Process);				//获取对应进程名称

	if (Create)
	{
		if (strcmp((char*)szInterceptProcessName, (char*)szImageFileName) == 0)
		{
			//因为程序的主线程是由explorer.exe的线程创建的，所以其进程上下文在explorer.exe的线程中
			//KeStackAttachProcess(Process, stRkapcState);
			KeAttachProcess(Process);									//切换到对应进程空间上下文中
			dwThreadAddress = (*((DWORD64*)((UCHAR*)Thread + 0x410)));	//得到线程回调函数入口点地址
			
			if (MmIsAddressValid((PVOID)dwThreadAddress))
			{
				//DbgBreakPoint();
				DbgPrint("[ThreadIntercept]the Thread is Intercept!：[PID：%d][TID：%d]",ProcessID, ThreadID);
				DisableWriteProtect(&uOldAttr);							//去除写保护
				*(DWORD32*)dwThreadAddress = 0xc3;
				EnableWriteProtect(uOldAttr);							//恢复写保护

			}
			
			//KeUnstackDetachProcess(stRkapcState);
			KeDetachProcess();											//恢复进程空间上下文
			
		}
		else
		{
			DbgPrint("[ThreadIntercept]the Thread is Create：[TID:%d]", ThreadID);
		}

	}
	else
		DbgPrint("[ThreadIntercept]the Thread is Exit:[TID:%d]", ThreadID);

	if(Process!=NULL)
		ObDereferenceObject(Process);										//对象引用计数减一
	if (Thread!=NULL)
		ObDereferenceObject(Thread);

}


//安装线程钩子
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
		DbgPrint("[ThreadIntercept]the Thread Hook is Install fail：the NTSTATUS is %d", ntstatus);
	}
}

//卸载线程钩子
void UnInstallThreadHook()
{
	PsRemoveCreateThreadNotifyRoutine(ThreadIntercept);
	DbgPrint("[ThreadIntercept]the Thread Hook is UnInstall!");
}






//进程钩子回调函数
void ProcessIntercept(
	PEPROCESS pEprocess, 
	HANDLE ProcessID, 
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	UCHAR stInterceptProcess[] = "";					//被拦截的进程名称
	UCHAR* stProcessName;

	stProcessName = PsGetProcessImageFileName(pEprocess);

	if (CreateInfo != NULL)
	{
		if (strcmp((char*)stProcessName, (char*)stInterceptProcess)== 0)
		{
			DbgPrint("[processIntercept]the Process is Intercept!");
			CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;					//使此进程创建失败
		}
		else
		{
			DbgPrint("[processIntercept]the Process is Cteate！[PID：%d]", ProcessID);
		}
	}
	else
		DbgPrint("[processIntercept]the Process is Exit！[PID：%d]", ProcessID);
}

//安装进程钩子
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
		DbgPrint("[processIntercept]the Process HOOK is install fail!：NTSTATUS is %d", ntstatus);
	}
}


//卸载进程钩子
void UnInstallProcessHook()
{

	PsSetCreateProcessNotifyRoutineEx(ProcessIntercept, TRUE);
	DbgPrint("[processIntercept]the HOOK is Uninstall!");

}







//驱动卸载函数
void DriverUnload(PDRIVER_OBJECT pDriver_Object)
{
	UNREFERENCED_PARAMETER(pDriver_Object);
	//UnInstallProcessHook();					//卸载进程钩子
	//UnInstallThreadHook();					//卸载线程钩子
	//UnInstallModuleHook();					//卸载模块钩子
	UnInstallRegistryHook();				//卸载注册表钩子
}




//驱动入口函数
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
	//InstallProcessHook();					//安装进程钩子
	//InstallThreadHook();					//安装线程钩子
	//InstallModuleHook();					//安装模块钩子
	InstallRegistryHook();			//安装注册表钩子
	return STATUS_SUCCESS;
}





