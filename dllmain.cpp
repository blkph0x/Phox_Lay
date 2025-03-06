
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <d3d11.h>
#include <Psapi.h>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"


#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "Psapi.lib")


ID3D11Device* pDevice11 = nullptr;
ID3D11DeviceContext* pContext = nullptr;
IDXGISwapChain* pSwapChain = nullptr;
ID3D11RenderTargetView* g_mainRenderTargetView = nullptr;


typedef HRESULT(APIENTRY* Present11)(IDXGISwapChain*, UINT, UINT);
typedef __int64(__fastcall* CreateHook_t)(unsigned __int64 pFuncAddress, __int64 pDetourFuncAddress, unsigned __int64* pOriginalFuncAddressOut, int a4);

Present11 oPresent11 = nullptr;
CreateHook_t CreateHook = nullptr;

bool showImGuiOverlay = false;
bool overlayInitialized = false;

uintptr_t FindPattern(const char* module, const char* pattern)
{
    MODULEINFO mInfo = {};
    GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(module), &mInfo, sizeof(MODULEINFO));
    uintptr_t base = (uintptr_t)mInfo.lpBaseOfDll;
    uintptr_t size = (uintptr_t)mInfo.SizeOfImage;

    std::vector<int> patternBytes;
    const char* start = pattern;
    while (*start)
    {
        if (*start == '?')
        {
            patternBytes.push_back(-1);
            start += 2;
        }
        else
        {
            patternBytes.push_back(strtoul(start, nullptr, 16));
            start += 3;
        }
    }

    for (uintptr_t i = base; i < base + size - patternBytes.size(); i++)
    {
        bool found = true;
        for (size_t j = 0; j < patternBytes.size(); j++)
        {
            if (patternBytes[j] != -1 && *(BYTE*)(i + j) != patternBytes[j])
            {
                found = false;
                break;
            }
        }
        if (found)
        {
            return i;
        }
    }
    return 0;
}


void InitImGui11(IDXGISwapChain* pSwapChain)
{
    DXGI_SWAP_CHAIN_DESC sd;
    pSwapChain->GetDesc(&sd);

    pSwapChain->GetDevice(__uuidof(ID3D11Device), (void**)&pDevice11);
    pDevice11->GetImmediateContext(&pContext);

    ID3D11Texture2D* pBackBuffer = nullptr;
    pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    pDevice11->CreateRenderTargetView(pBackBuffer, nullptr, &g_mainRenderTargetView);
    pBackBuffer->Release();

    ImGui::CreateContext();
    ImGui_ImplWin32_Init(sd.OutputWindow);
    ImGui_ImplDX11_Init(pDevice11, pContext);

    overlayInitialized = true;
}


void RenderOverlay11()
{
    if (!pContext || !g_mainRenderTargetView || !overlayInitialized) return;

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    if (showImGuiOverlay) {
        ImGui::Begin("Cheese Window");
        ImGui::Text("Hello from Phox labs");
        ImGui::Button("Features to CuM");
        ImGui::End();
    }

    ImGui::Render();
    pContext->OMSetRenderTargets(1, &g_mainRenderTargetView, nullptr);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
}


HRESULT APIENTRY HKPresent11(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags)
{
    if (GetAsyncKeyState(VK_HOME) & 1) {
        showImGuiOverlay = !showImGuiOverlay;
        if (showImGuiOverlay && !overlayInitialized) {
            InitImGui11(pSwapChain);
        }
    }
    RenderOverlay11();
    return oPresent11(pSwapChain, SyncInterval, Flags);
}


DWORD __stdcall main_thread(LPVOID lpReserved)
{
    auto present_hk_sig = FindPattern("GameOverlayRenderer64.dll", "48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 56 41 57 48 83 EC ? 41 8B E8");  //__int64 __fastcall HkPresent(__int64 a1, __int64 a2, __int64 a3)
    auto create_hk_sig = FindPattern("GameOverlayRenderer64.dll", "48 89 5C 24 ? 57 48 83 EC ? 33 C0 48 89 44 24"); //__int64 __fastcall CreateHook(unsigned __int64 *func_address, __int64 detour_func_address, _QWORD *original_func_address_out, bool enabled)

    CreateHook = (CreateHook_t)create_hk_sig;
    if (CreateHook)
    {
        CreateHook(present_hk_sig, (__int64)&HKPresent11, (unsigned __int64*)&oPresent11, 1);
    }

    return TRUE;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        QueueUserWorkItem((LPTHREAD_START_ROUTINE)main_thread, nullptr, WT_EXECUTEDEFAULT);
    }
    else if (dwReason == DLL_PROCESS_DETACH)
    {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = nullptr; }
        pDevice11 = nullptr;
        pContext = nullptr;
    }
    return TRUE;
}
