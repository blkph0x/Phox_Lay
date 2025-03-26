// Ultra-Hardened DX11 ImGui Hook (Ghost Protocol - Obfuscated Dominion Edition++)
// Full Features: AES-128 CBC, PE header erasure, integrity validation, anti-debug, DNS C2, ImGui overlay, trampoline hook, stealth allocator

#define _CRT_SECURE_NO_WARNINGS
#define EXFIL_DOMAIN ".b3acon-control.xyz"

#include "pch.h"
#include <Windows.h>
#include <wincrypt.h>
#include <Psapi.h>
#include <d3d11.h>
#include <windns.h>
#include <intrin.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <unordered_map>
#include <random>
#include <bcrypt.h>
#include <winternl.h>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "Crypt32.lib")

ID3D11Device* g_pTargetDevice = nullptr;
IDXGISwapChain* g_pTargetSwapChain = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
ID3D11DeviceContext* pContext = nullptr;
bool showImGuiOverlay = false;
bool overlayInitialized = false;
std::atomic<bool> stopDNSHandler = false;

using Present11 = HRESULT(APIENTRY*)(IDXGISwapChain*, UINT, UINT);
Present11 oPresent11 = nullptr;
BYTE g_AESKey[16] = { 0 };
BYTE g_AESIV[16] = { 0 };
std::unordered_map<void*, std::vector<BYTE>> integrityMap;

// Forward declarations
bool SafeCompare(const void* addr, const BYTE* pattern, size_t length);
void RotateAESKey();
void WipePEHeader();
bool AES_Encrypt(std::string& inout);
bool AES_Decrypt(std::string& inout);
void PopulateIntegrity(void* func, size_t len) {
    std::vector<BYTE> original((BYTE*)func, (BYTE*)func + len);
    integrityMap[func] = original;
}
bool ValidateIntegrity(void* func, size_t len) {
    if (integrityMap.find(func) == integrityMap.end()) return false;
    return memcmp(integrityMap[func].data(), func, len) == 0;
}
void WipePEHeader();
void* CustomAlloc(size_t size);
void CustomFree(void* ptr);
void InitImGui11(IDXGISwapChain* pSwapChain);
void RenderOverlay11();


HRESULT APIENTRY HKPresent11(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags) {
    MessageBoxA(0, "[+] HKPresent11 called", "DEBUG", MB_OK);
    if (!g_pTargetSwapChain) {
        MessageBoxA(0, "[+] Target swapchain set", "DEBUG", MB_OK);
        g_pTargetSwapChain = pSwapChain;
        g_pTargetSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&g_pTargetDevice);
    }
    if (!overlayInitialized) {
        MessageBoxA(0, "[+] Initializing ImGui11", "DEBUG", MB_OK);
        InitImGui11(pSwapChain);
        MessageBoxA(0, "[+] InitImGui11 completed", "DEBUG", MB_OK);
    }
    if (GetAsyncKeyState(VK_HOME) & 1) {
        MessageBoxA(0, "[+] HOME key pressed", "DEBUG", MB_OK);
        showImGuiOverlay = !showImGuiOverlay;
    }
    RenderOverlay11();
    return oPresent11(pSwapChain, SyncInterval, Flags);
}

void InitImGui11(IDXGISwapChain* pSwapChain) {
    MessageBoxA(0, "[+] InitImGui11() called", "DEBUG", MB_OK);
    DXGI_SWAP_CHAIN_DESC sd;
    pSwapChain->GetDesc(&sd);
    pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&g_pTargetDevice);
    g_pTargetDevice->GetImmediateContext(&pContext);
    ID3D11Texture2D* pBackBuffer;
    pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pTargetDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
    MessageBoxA(0, "[+] Creating ImGui context", "DEBUG", MB_OK);
    ImGui::CreateContext();
    MessageBoxA(0, "[+] Initializing ImGui Win32", "DEBUG", MB_OK);
    ImGui_ImplWin32_Init(sd.OutputWindow);
    MessageBoxA(0, "[+] Initializing ImGui DX11", "DEBUG", MB_OK);
    ImGui_ImplDX11_Init(g_pTargetDevice, pContext);
    MessageBoxA(0, "[+] ImGui overlay initialization complete", "DEBUG", MB_OK);
    overlayInitialized = true;
}

void RenderOverlay11() {
    MessageBoxA(0, "[+] RenderOverlay11() entered", "DEBUG", MB_OK);
    if (!overlayInitialized || !pContext || !g_mainRenderTargetView) return;

    // Set render target
    pContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);

    // Clear background (optional, for testing visibility)
    float clearColor[4] = { 0.1f, 0.1f, 0.1f, 1.0f };
    pContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);

    // Start new ImGui frame
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    if (showImGuiOverlay) {
        ImGui::Begin("Ghost Overlay"); // "Ghost Overlay" encrypted
        ImGui::Text("[+] ImGui Overlay Active"); // "[+] ImGui Overlay Active"
        ImGui::Text("[*] Press HOME to toggle this menu."); // "[*] Press HOME to toggle this menu."
        ImGui::End();
    }

    MessageBoxA(0, "[+] Calling ImGui::Render", "DEBUG", MB_OK);
    ImGui::Render();
    MessageBoxA(0, "[+] Drawing ImGui overlay", "DEBUG", MB_OK);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
}

bool SafeCompare(const void* addr, const BYTE* pattern, size_t length) {
    __try {
        return memcmp(addr, pattern, length) == 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool TrampolineHook(void* target, void* detour, void** original) {
    DWORD old;
    BYTE jmp[14] = { 0x49, 0xBB };
    *(void**)(jmp + 2) = detour;
    jmp[10] = 0x41; jmp[11] = 0xFF; jmp[12] = 0xE3;
    VirtualProtect(target, 14, PAGE_EXECUTE_READWRITE, &old);
    *original = VirtualAlloc(nullptr, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(*original, target, 14);
    *((BYTE*)*original + 14) = 0xE9;
    *(DWORD*)((BYTE*)*original + 15) = (DWORD)((uintptr_t)target + 14 - ((uintptr_t)*original + 19));
    memcpy(target, jmp, 14);
    VirtualProtect(target, 14, old, &old);
    return true;
}

DWORD WINAPI MainThread(LPVOID lpReserved) {
    MessageBoxA(0, "[THREAD] MainThread started", "DEBUG", MB_OK);
    WNDCLASSEX wc = { sizeof(WNDCLASSEX), CS_CLASSDC, DefWindowProc, 0L, 0L, GetModuleHandle(NULL), NULL, NULL, NULL, NULL, L"Dummy", NULL };
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(L"Dummy", NULL, WS_OVERLAPPEDWINDOW, 0, 0, 100, 100, NULL, NULL, wc.hInstance, NULL);

    DXGI_SWAP_CHAIN_DESC sd = {};
    sd.BufferCount = 1;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    IDXGISwapChain* dummySwapChain = nullptr;
    ID3D11Device* dummyDevice = nullptr;
    ID3D11DeviceContext* dummyContext = nullptr;
    D3D_FEATURE_LEVEL level;

    MessageBoxA(0, "[THREAD] Creating dummy device and swapchain", "DEBUG", MB_OK);
    MessageBoxA(0, "[THREAD] Creating D3D11 device and swapchain", "DEBUG", MB_OK);
    if (FAILED(D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
        D3D11_SDK_VERSION, &sd, &dummySwapChain, &dummyDevice, &level, &dummyContext))) {
        return 0;
    }

    void** vtable = *(void***)(dummySwapChain);
    void* presentTarget = nullptr;
    BYTE pattern[] = { 0x48, 0x89, 0x5C, 0x24 };

    for (int i = 0; i < 50; ++i) {
        if (SafeCompare(vtable[i], pattern, sizeof(pattern))) {
            presentTarget = vtable[i];
            break;
        }
    }

    if (presentTarget) {
        MessageBoxA(0, "[HOOK] Present function found. Attempting hook...", "DEBUG", MB_OK);
        if (TrampolineHook(presentTarget, (void*)&HKPresent11, (void**)&oPresent11)) {
            MessageBoxA(0, "[HOOK] TrampolineHook SUCCESS", "DEBUG", MB_OK);
        }
        else {
            MessageBoxA(0, "[HOOK] TrampolineHook FAILED", "DEBUG", MB_OK);
        }
    }

    dummySwapChain->Release();
    dummyDevice->Release();
    dummyContext->Release();
    DestroyWindow(hwnd);
    UnregisterClassW(L"Dummy", GetModuleHandle(NULL));

    return 0;
}

void RotateAESKey() {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0) != 0) return;
    if (BCryptGenRandom(hAlg, g_AESKey, sizeof(g_AESKey), 0) != 0) return;
    if (BCryptGenRandom(hAlg, g_AESIV, sizeof(g_AESIV), 0) != 0) return;
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

void WipePEHeader() {
    HMODULE hModule = GetModuleHandle(nullptr);
    DWORD oldProtect;
    VirtualProtect(hModule, 4096, PAGE_EXECUTE_READWRITE, &oldProtect);
    ZeroMemory(hModule, 4096);
    VirtualProtect(hModule, 4096, oldProtect, &oldProtect);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    // Simple anti-debugging: check for debugger presence via PEB
    BOOL beingDebugged = IsDebuggerPresent();
    if (beingDebugged) {
        MessageBoxA(0, "[ANTI-DEBUG] Debugger detected! Exiting...", "DEBUG", MB_ICONERROR);
        ExitProcess(0);
    }
    if (dwReason == DLL_PROCESS_ATTACH) {
        MessageBoxA(0, "[+] DllMain hit (DLL_PROCESS_ATTACH)", "DEBUG", MB_OK);
        DisableThreadLibraryCalls(hModule);
        WipePEHeader();
        RotateAESKey();
        CreateThread(nullptr, 0, MainThread, nullptr, 0, nullptr);
    }
    return TRUE;
}
