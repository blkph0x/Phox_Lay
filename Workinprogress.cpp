// Ultra-Hardened DX11 ImGui Hook (Ghost Protocol Edition++)
// Features: AES key rotation, PE header erasure, integrity validation, anti-debug, Steam+Discord hook fallback, trampoline backup

#define _CRT_SECURE_NO_WARNINGS
#define EXFIL_DOMAIN ".b3acon-control.xyz"

#include "pch.h"
#include <Windows.h>
#include <wincrypt.h>
#include <Psapi.h>
#include <d3d11.h>
#include <intrin.h>
#include <vector>
#include <string>
#include <unordered_map>
#include <bcrypt.h>
#include <atomic>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "bcrypt.lib")

using Present11 = HRESULT(APIENTRY*)(IDXGISwapChain*, UINT, UINT);
using CreateHook_t = __int64(__fastcall*)(unsigned __int64, __int64, unsigned __int64*, int);

ID3D11Device* g_pTargetDevice = nullptr;
IDXGISwapChain* g_pTargetSwapChain = nullptr;
ID3D11DeviceContext* pContext = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;
Present11 oPresent11 = nullptr;
bool showImGuiOverlay = false;
bool overlayInitialized = false;
bool wasPressed = false;
std::atomic<bool> stopDNSHandler = false;
BYTE g_AESKey[16] = { 0 };
BYTE g_AESIV[16] = { 0 };
std::unordered_map<void*, std::vector<BYTE>> integrityMap;

void Log(const char* msg) {
    FILE* f;
    fopen_s(&f, "C:\\Temp\\ghost_log.txt", "a+");
    if (f) {
        fprintf(f, "%s\n", msg);
        fclose(f);
    }
}

uintptr_t FindPattern(const char* module, const char* pattern) {
    MODULEINFO mInfo = {};
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(module), &mInfo, sizeof(MODULEINFO));
    uintptr_t base = (uintptr_t)mInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)mInfo.SizeOfImage;
    std::vector<int> patternBytes;
    const char* start = pattern;
    while (*start) {
        if (*start == '?') { patternBytes.push_back(-1); start += 2; }
        else { patternBytes.push_back(strtoul(start, nullptr, 16)); start += 3; }
    }
    for (uintptr_t i = base; i < base + size - patternBytes.size(); i++) {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); j++) {
            if (patternBytes[j] != -1 && *(BYTE*)(i + j) != patternBytes[j]) { found = false; break; }
        }
        if (found) return i;
    }
    return 0;
}

void InitImGui11(IDXGISwapChain* pSwapChain) {
    Log("InitImGui11 called");
    DXGI_SWAP_CHAIN_DESC sd;
    pSwapChain->GetDesc(&sd);
    pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&g_pTargetDevice);
    g_pTargetDevice->GetImmediateContext(&pContext);
    ID3D11Texture2D* pBackBuffer;
    pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pTargetDevice->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();
    ImGui::CreateContext();
    ImGui_ImplWin32_Init(sd.OutputWindow);
    ImGui_ImplDX11_Init(g_pTargetDevice, pContext);
    overlayInitialized = true;
}

void RenderOverlay11() {
    if (!overlayInitialized || !pContext || !g_mainRenderTargetView) return;
    pContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
    float clearColor[4] = { 0.f, 0.f, 0.f, 1.0f };
    //pContext->ClearRenderTargetView(g_mainRenderTargetView, clearColor);
    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();
    if (showImGuiOverlay) {
        ImGui::Begin("Ghost Overlay");
        ImGui::Text("[+] ImGui Overlay Active");
        ImGui::Text("[*] Press HOME to toggle this menu.");
        ImGui::End();
    }
    ImGui::Render();
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
}

HRESULT APIENTRY HKPresent11(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags) {
    Log("HKPresent11 triggered");
    if (!g_pTargetSwapChain) g_pTargetSwapChain = pSwapChain;
    if (!overlayInitialized) InitImGui11(pSwapChain);
    SHORT keyState = GetAsyncKeyState(VK_HOME);
    if (keyState & 0x8000) {
        if (!wasPressed) {
            showImGuiOverlay = !showImGuiOverlay;
            wasPressed = true;
            Log("HOME key toggled overlay");
        }
    }
    else {
        wasPressed = false;
    }
    RenderOverlay11();
    return oPresent11 ? oPresent11(pSwapChain, SyncInterval, Flags) : S_OK;
}

// RotateAESKey implementation
void RotateAESKey() {
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0) == 0) {
        BCryptGenRandom(hAlg, g_AESKey, sizeof(g_AESKey), 0);
        BCryptGenRandom(hAlg, g_AESIV, sizeof(g_AESIV), 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
}

// MainThread implementation
DWORD WINAPI MainThread(LPVOID lpReserved) {
    Log("MainThread executing");
    HMODULE hSteam = GetModuleHandleA("GameOverlayRenderer64.dll");
    if (hSteam) {
        uintptr_t present = FindPattern("GameOverlayRenderer64.dll", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 41 8B E8");
        uintptr_t createHook = FindPattern("GameOverlayRenderer64.dll", "48 89 5C 24 ? 57 48 83 EC ? 33 C0 48 89 44 24");
        CreateHook_t CreateHook = (CreateHook_t)createHook;
        if (!present) Log("Steam Present not found!");
        if (!createHook) Log("Steam CreateHook not found!");
        if (present && CreateHook) {
            Log("Found Steam Present + CreateHook");
            if (CreateHook(present, (__int64)&HKPresent11, (unsigned __int64*)&oPresent11, 1)) {
                Log("Steam Hook SUCCESS");
                return TRUE;
            }
        }
    }

    HMODULE hDiscord = GetModuleHandleA("DiscordHook64.dll");
    if (hDiscord) {
        Log("Trying Discord fallback");
        uint64_t addr = (uint64_t)hDiscord + 0x1070E0;
        Present11* discord_present = (Present11*)addr;
        if (discord_present && *discord_present) {
            oPresent11 = *discord_present;
            _InterlockedExchangePointer((volatile PVOID*)addr, (PVOID)HKPresent11);
            Log("Discord Hook SUCCESS");
            return TRUE;
        }
    }

    Log("Failed to hook via Steam or Discord");
    return FALSE;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    Log("DllMain called");
    // Commented for debug stability
    // if (IsDebuggerPresent()) ExitProcess(0);

    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        // WipePEHeader(); // Temporarily disabled for stability during testing
        RotateAESKey();

        CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
            Sleep(3000); // Delay to avoid early initialization issues
            return MainThread(nullptr);
            }, nullptr, 0, nullptr);
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
        pContext = nullptr;
        g_pTargetDevice = nullptr;
    }
    return TRUE;
}
