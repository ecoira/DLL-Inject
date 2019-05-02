#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
#include<stdlib.h>
#include <tlhelp32.h>

LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;

/*更改 WriteFile() API第一个字节为0xCC (INT 3)，打第一个断点 */
BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
	g_pfWriteFile = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");  //获取WriteFile API的首地址
	memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
																	  
	ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
		&g_chOrgByte, sizeof(BYTE), NULL);

	WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
		&g_chINT3, sizeof(BYTE), NULL);

	return TRUE;
}

/*窃取记事本内容，并输出在命令行*/
BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
	CONTEXT ctx;         //保存线程CPU寄存器信息
	PBYTE lpBuffer = NULL;
	DWORD dwNumOfBytesToWrite, dwAddrOfBuffer, i;
	PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;//pde中的异常记录

	// 判断异常记录的内容是否是断点异常（断点异常里面包括int3异常）
	if (EXCEPTION_BREAKPOINT == per->ExceptionCode)
	{
		// 判断断点地址是否为WriteFile()API地址
		if (g_pfWriteFile == per->ExceptionAddress)
		{

			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
				&g_chOrgByte, sizeof(BYTE), NULL);//将函数修改后的首字节0xCC恢复为原首字节（6A）

			// Thread Context 获取线程上下文
			ctx.ContextFlags = CONTEXT_CONTROL;
			GetThreadContext(g_cpdi.hThread, &ctx);//获取线程的各种状态

		   //  WriteFile()的param2、3 值
		   //  函数参数存在于相应进程的栈
		   //   数据缓冲区地址 : ESP + 0x8
		   //   缓冲区大小 : ESP + 0xC
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0x8),
				&dwAddrOfBuffer, sizeof(DWORD), NULL);//从Esp + 0x8地址处读取buffer的地址，并写到dwAddrOfBuffer
			ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0xC),
				&dwNumOfBytesToWrite, sizeof(DWORD), NULL);//从Esp + 0xC地址处读取记事本中的字符串长度，并写到dwNumOfBytesToWrite中

			lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite + 1);//临时缓冲区，加1是因为当前断在WriteFile() + 1位置
			if (lpBuffer != 0)
			{
				memset(lpBuffer, 0, dwNumOfBytesToWrite + 1);//lpBuffer初始化

				/*读取并打印记事本内容*/
				ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer,
					lpBuffer, dwNumOfBytesToWrite, NULL);
				printf("\n记事本内容：\n%s\n", lpBuffer);   

			}

			free(lpBuffer);

			//将线程上下文的EIP更改为WriteFile()首地址
			ctx.Eip = (DWORD)g_pfWriteFile;//将WriteFile首地址赋值给eip
			SetThreadContext(g_cpdi.hThread, &ctx);//将指定线程g_cpdi.hThread的context存到ctx结构体变量，为运行被调试进程做准备
												   //g_cpdi.hThread是被调试者的主线程句柄
			// 运行Debuggee（被调试进程）
			ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
			Sleep(0);//释放当前线程的剩余时间片，调用sleep（0）之后，cpu会立即执行其他线程，经过一定时间再获得控制权
					//（避免notepad正在调用writefile()API的过程中，后面的钩子代码在调用成功之前执行完毕，这样会导致内存访问异常）
			/* 调 用Sleep(0)函 数 后 ，被 调 试 进 程（Notepad.exe) 的 主 线 程 处 于 运 行 状 态 时 ， 会 正 常 调 用
			WriteFiIe()API。然 后 经 过 一 定 时 间 ， 控 制 权 再 次 转 移 给HookDbg.exe, Sleep(0)后 面 的 “ 钩子 ” 代 码*/


			WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile,
				&g_chINT3, sizeof(BYTE), NULL);//将0xCC写到g_pfWriteFile（函数首地址）——继续设置断点

			return TRUE;
		}
	}

	return FALSE;
}

/*调试器循环*/
void DebugLoop()
{
	DEBUG_EVENT de;//调试事件
	DWORD dwContinueStatus;//继续状态

	while (WaitForDebugEvent(&de, INFINITE))//等待被调试者发生事件，INFINITE表示无穷等待										
	{
		dwContinueStatus = DBG_CONTINUE;

		if (CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)//创建进程之后的第一个调试事件
		{
			OnCreateProcessDebugEvent(&de);//进程创建成功之后会把DEBUG_EVENT当参数传给该函数
		}
	
		else if (EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode)	// 异常事件
		{
			//窃取内容
			if (OnExceptionDebugEvent(&de))
				continue;
		}
		else if (EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode)//被调试进程结束
		{
			break;
		}

		// 使调试器继续运行的API
		ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
	}
}

/*通过进程名获取进程ID*/
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
	DWORD dwPID;//进程ID

	dwPID = GetProcessIDByName("notepad.exe");
	if (!DebugActiveProcess(dwPID))//如果附加失败，会返回0，if语句会执行
	{
		printf("DebugActiveProcess(%d) failed!!!\n"
			"Error Code = %d\n", dwPID, GetLastError());
		return 1;
	}

	// 调试器循环
	DebugLoop();

	return 0;
}