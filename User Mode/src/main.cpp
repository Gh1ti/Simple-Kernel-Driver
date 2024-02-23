#include <iostream>
#include <cstdint>
#include <Windows.h>
#include <TlHelp32.h>

static DWORD get_process_id(const wchar_t* process_name) {
	DWORD procId = 0;

	HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapShot == INVALID_HANDLE_VALUE)
		return procId;

	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(decltype(entry));

	if (Process32FirstW(snapShot, &entry) == TRUE) {
		if (_wcsicmp(process_name, entry.szExeFile) == 0)
			procId = entry.th32ProcessID;
		else {
			while (Process32NextW(snapShot, &entry) == TRUE) {
				if (_wcsicmp(process_name, entry.szExeFile) == 0) {
					procId = entry.th32ProcessID;
					break;
				}
					
			}
		}
	}

	CloseHandle(snapShot);
	return procId;
}

static std::uintptr_t get_module_base(const DWORD pid, const wchar_t* module_name) {
	std::uintptr_t mod_base = 0;

	HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, NULL);
	if (snapShot == INVALID_HANDLE_VALUE)
		return mod_base;

	MODULEENTRY32 entry = {};
	entry.dwSize = sizeof(decltype(entry));

	if (Module32FirstW(snapShot, &entry) == TRUE) {
		if (_wcsicmp(module_name, entry.szModule) == 0)
			mod_base = (uintptr_t)entry.modBaseAddr;
		else {
			while (Module32FirstW(snapShot, &entry) == TRUE) {
				if (_wcsicmp(module_name, entry.szModule) == 0) {
					mod_base = (uintptr_t)entry.modBaseAddr;
					break;
				}

			}
		}
	}

	CloseHandle(snapShot);
	return mod_base;
}

namespace driver {
	namespace codes {
		constexpr ULONG attach = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x696, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG read = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x697, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
		constexpr ULONG write = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x698, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
	}

	struct Request {
		HANDLE process_id;

		PVOID target;
		PVOID buffer;

		SIZE_T size;
		SIZE_T return_size;
	};

	bool attach_to_process(HANDLE driver_handle, const DWORD pid) {
		Request r;
		r.process_id = (HANDLE)pid;

		return DeviceIoControl(driver_handle, codes::attach, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
	}

	template <class T>
	T read(HANDLE driver_handle, const std::uintptr_t addr) {
		T temp = {};

		Request r;
		r.target = (PVOID)addr;

		r.buffer = &temp;
		r.size = sizeof(T);
		DeviceIoControl(driver_handle, codes::read, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);

		return temp;
	}

	template <class T>
	void write(HANDLE driver_handle, const std::uintptr_t addr, const T& val) {
		Request r;
		r.target = reinterpret_cast<PVOID(addr);
		r.buffer = (PVOID)&val;
		r.size = sizeof(T);

		DeviceIoControl(driver_handle, codes::write, &r, sizeof(r), &r, sizeof(r), nullptr, nullptr);
	}

}


int main() {

	const DWORD pid = get_process_id(L"notepad.exe");

	if (pid == 0) {
		std::cout << "Failed to find cs2.exe. \n";
		std::cin.get();
		return 1;
	}
	std::cout << pid << "\n";
	const HANDLE driver = CreateFileW(L"\\\\.\\FunnyDriver", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

	if (driver == INVALID_HANDLE_VALUE) {
		std::cout << "Failed to create driver handle. \n";
		std::cin.get();
		return 1;
	}

	if (driver::attach_to_process(driver, pid)) {
		std::cout << "Attachment complete. \n";
	}

	CloseHandle(driver);

	std::cin.get();
	return 0;
}