#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
#include<stdlib.h>
#include <tlhelp32.h>

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

/*���� WriteFile() API��һ���ֽ�Ϊ0xCC (INT 3)�����һ���ϵ� */
BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
	g_pfWriteFile = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");  //��ȡWriteFile API���׵�ַ
	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
																	  
	ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
		&g_chOrgByte, sizeof(BYTE), NULL);

	WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
		&g_chINT3, sizeof(BYTE), NULL);

	return TRUE;
}

/*��ȡ���±����ݣ��������������*/
BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
	CONTEXT ctx;         //�����߳�CPU�Ĵ�����Ϣ
	PBYTE lpBuffer = NULL;
	DWORD dwNumOfBytesToWrite, dwAddrOfBuffer, i;
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;//pde�е��쳣��¼

	// �ж��쳣��¼�������Ƿ��Ƕϵ��쳣���ϵ��쳣�������int3�쳣��
	if (EXCEPTION_BREAKPOINT == per->ExceptionCode)
	{
		// �ж϶ϵ��ַ�Ƿ�ΪWriteFile()API��ַ
		if (g_pfWriteFile == per->ExceptionAddress)
		{

			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
				&g_chOrgByte, sizeof(BYTE), NULL);//�������޸ĺ�����ֽ�0xCC�ָ�Ϊԭ���ֽڣ�6A��

			// Thread Context ��ȡ�߳�������
			ctx.ContextFlags = CONTEXT_CONTROL;
			GetThreadContext(g_cpdi.hThread, &ctx);//��ȡ�̵߳ĸ���״̬

		   //  WriteFile()��param2��3 ֵ
		   //  ����������������Ӧ���̵�ջ
		   //   ���ݻ�������ַ : ESP + 0x8
		   //   ��������С : ESP + 0xC
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0x8),
				&dwAddrOfBuffer, sizeof(DWORD), NULL);//��Esp + 0x8��ַ����ȡbuffer�ĵ�ַ����д��dwAddrOfBuffer
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0xC),
				&dwNumOfBytesToWrite, sizeof(DWORD), NULL);//��Esp + 0xC��ַ����ȡ���±��е��ַ������ȣ���д��dwNumOfBytesToWrite��

			lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite + 1);//��ʱ����������1����Ϊ��ǰ����WriteFile() + 1λ��
			if (lpBuffer != 0)
			{
				memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);//lpBuffer��ʼ��

				/*��ȡ����ӡ���±�����*/
				ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
					lpBuffer, dwNumOfBytesToWrite, NULL);
				printf("\n���±����ݣ�\n%s\n", lpBuffer);   

			}

			free(lpBuffer);

			//���߳������ĵ�EIP����ΪWriteFile()�׵�ַ
			ctx.Eip = (DWORD)g_pfWriteFile;//��WriteFile�׵�ַ��ֵ��eip
			SetThreadContext(g_cpdi.hThread, &ctx);//��ָ���߳�g_cpdi.hThread��context�浽ctx�ṹ�������Ϊ���б����Խ�����׼��
												   //g_cpdi.hThread�Ǳ������ߵ����߳̾��
			// ����Debuggee�������Խ��̣�
			ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
			Sleep(0);//�ͷŵ�ǰ�̵߳�ʣ��ʱ��Ƭ������sleep��0��֮��cpu������ִ�������̣߳�����һ��ʱ���ٻ�ÿ���Ȩ
					//������notepad���ڵ���writefile()API�Ĺ����У�����Ĺ��Ӵ����ڵ��óɹ�֮ǰִ����ϣ������ᵼ���ڴ�����쳣��
			/* �� ��Sleep(0)�� �� �� ���� �� �� �� �̣�Notepad.exe) �� �� �� �� �� �� �� �� ״ ̬ ʱ �� �� �� �� �� ��
			WriteFiIe()API��Ȼ �� �� �� һ �� ʱ �� �� �� �� Ȩ �� �� ת �� ��HookDbg.exe, Sleep(0)�� �� �� �� ���� �� �� ��*/


			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
				&g_chINT3, sizeof(BYTE), NULL);//��0xCCд��g_pfWriteFile�������׵�ַ�������������öϵ�

			return TRUE;
		}
	}

	return FALSE;
}

/*������ѭ��*/
void DebugLoop()
{
	DEBUG_EVENT de;//�����¼�
	DWORD dwContinueStatus;//����״̬

	while (WaitForDebugEvent(&de, INFINITE))//�ȴ��������߷����¼���INFINITE��ʾ����ȴ�										
	{
		dwContinueStatus = DBG_CONTINUE;

		if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)//��������֮��ĵ�һ�������¼�
		{
			OnCreateProcessDebugEvent(&de);//���̴����ɹ�֮����DEBUG_EVENT�����������ú���
		}
	
		else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)	// �쳣�¼�
		{
			//��ȡ����
			if (OnExceptionDebugEvent(&de))
				continue;
		}
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)//�����Խ��̽���
		{
			break;
		}

		// ʹ�������������е�API
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}

/*ͨ����������ȡ����ID*/
DWORD GetProcessIDByName(const char* pName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hSnapshot) {
		return NULL;
	}
	PROCESSENTRY32 pe = { sizeof(pe) };
	for (BOOL ret = Process32First(hSnapshot, &pe); ret; ret = Process32Next(hSnapshot, &pe)) {
		if (strcmp(pe.szExeFile, pName) == 0) {
			CloseHandle(hSnapshot);
			return pe.th32ProcessID;
		}
	}
	CloseHandle(hSnapshot);
	return 0;
}

int main(int argc, char* argv[])
{
	DWORD dwPID;//����ID

	dwPID = GetProcessIDByName("notepad.exe");
	if (!DebugActiveProcess(dwPID))//�������ʧ�ܣ��᷵��0��if����ִ��
	{
		printf("DebugActiveProcess(%d) failed!!!\n"
			"Error Code = %d\n", dwPID, GetLastError());
		return 1;
	}

	// ������ѭ��
	DebugLoop();

	return 0;
}