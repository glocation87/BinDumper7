#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>
#include <winioctl.h>
#include "driver_common.h"

#define DUMP_MODULE 0x00000007
#define DUMP_PROCESS 0x00000014

int main()
{
	std::cout << "Se7en process dumper\n";
	std::cout << "--------------------\n";
	std::cout << "getting handle to virtual driver device" << std::endl;
	std::cout << "--------------------\n\n";

	HANDLE h_device = CreateFileW(L"\\\\.\\se7en", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_device == INVALID_HANDLE_VALUE) {
		std::cout << "failed to get handle to device: " << GetLastError() << std::endl;
		std::cout << "make sure driver is loaded and started" << std::endl;
		Sleep(7000);

		return 1;
	}

	// enumerate processes
	DWORD pid;
	char module_name[256];
	DWORD dump_mode = DUMP_PROCESS;
	std::cout << "enter process id: "; std::cin >> pid;
	std::cout << "enter module name (N to skip): "; std::cin >> module_name;

	if (pid <= 0) {
		std::cout << "invalid process id\n";
		return 1;
	}

	if (module_name[0] == '\0' || module_name[0] == 'N') {
		std::cout << "module field empty\n";
		dump_mode = DUMP_PROCESS;
	}

	switch (dump_mode) {
	case DUMP_MODULE:
	{

		break;
	}
	default:
		std::cout << "scanning for process\n";
		//initialize blank process struct
		PROCESSENTRY32 process;
		process.dwSize = sizeof(PROCESSENTRY32);

		LPPROCESSENTRY32 lp_process = &process;
		HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0x0);

		BOOL found_process = FALSE;

		try {
			if (Process32First(h_snapshot, lp_process) == FALSE) {
				throw std::runtime_error("no processes found");
			}
		}
		catch (std::runtime_error& e) {
			std::cout << "no processes found\n";
			return 1;
		}

		do {
			if (lp_process->th32ProcessID == pid) {
				found_process = TRUE;
				std::cout << "found process: " << (void*)lp_process->szExeFile << "\n";
				std::cout << "process id: " << lp_process->th32ProcessID << "\n";
				std::cout << "parent process id: " << lp_process->th32ParentProcessID << "\n";
				std::cout << "thread count: " << lp_process->cntThreads << "\n";
				std::cout << "priority base: " << lp_process->pcPriClassBase << "\n";
				std::cout << "flags: " << lp_process->dwFlags << std::endl;
				break;
			}
		} while (Process32Next(h_snapshot, lp_process));

		if (!found_process) {
			std::cout << "process not found\n";
		}
		else {
			std::cout << "process found... fetching \n";
			PROCESS_BASE_ADDRESS process_base_address{};
			process_base_address.ProcessId = pid;
			DWORD bytes_returned = 0;
			BOOL status = DeviceIoControl(h_device, IOCTL_GET_BASE_ADDRESS, &process_base_address,
				sizeof(PROCESS_BASE_ADDRESS), &process_base_address, sizeof(PROCESS_BASE_ADDRESS), &bytes_returned, NULL);

			if (status) {
				std::cout << "get through" << std::endl;
				std::cout << "base address: " << process_base_address.BaseAddress << std::endl;
			}
			else {
				std::cout << "failed to get base address: " << GetLastError() << std::endl;
			}


			break;
		}

		std::cin >> pid;

		return 0;
	}
}
