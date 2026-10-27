#include "sync_fix.h"

static HMODULE g_realD3D11 = nullptr;
static PFN_D3D11_CREATE_DEVICE g_pfnCreateDevice = nullptr;
static PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN g_pfnCreateDeviceAndSwapChain = nullptr;

static bool InitRealD3D11() {
    if (g_realD3D11) return true;

    WCHAR sysPath[MAX_PATH];
    if (!GetSystemDirectoryW(sysPath, MAX_PATH)) return false;
    lstrcatW(sysPath, L"\\d3d11.dll");

    g_realD3D11 = LoadLibraryW(sysPath);
    if (!g_realD3D11) return false;

    g_pfnCreateDevice = (PFN_D3D11_CREATE_DEVICE)GetProcAddress(g_realD3D11, "D3D11CreateDevice");
    g_pfnCreateDeviceAndSwapChain = (PFN_D3D11_CREATE_DEVICE_AND_SWAP_CHAIN)GetProcAddress(g_realD3D11, "D3D11CreateDeviceAndSwapChain");

    return (g_pfnCreateDevice != nullptr);
}

extern "C" HRESULT WINAPI D3D11CreateDevice(
    IDXGIAdapter* pAdapter,
    D3D_DRIVER_TYPE DriverType,
    HMODULE Software,
    UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    UINT FeatureLevels,
    UINT SDKVersion,
    ID3D11Device** ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext
) {
    if (!InitRealD3D11()) return E_FAIL;

    ID3D11Device* pRealDevice = nullptr;
    ID3D11DeviceContext* pRealContext = nullptr;

    HRESULT hr = g_pfnCreateDevice(
        pAdapter, DriverType, Software, Flags,
        pFeatureLevels, FeatureLevels, SDKVersion,
        ppDevice ? &pRealDevice : nullptr,
        pFeatureLevel,
        ppImmediateContext ? &pRealContext : nullptr
    );

    if (SUCCEEDED(hr)) {
        WrapDeviceAndContext(&pRealDevice, &pRealContext);
        if (ppDevice) *ppDevice = pRealDevice;
        if (ppImmediateContext) *ppImmediateContext = pRealContext;
    }
    return hr;
}

extern "C" HRESULT WINAPI D3D11CreateDeviceAndSwapChain(
    IDXGIAdapter* pAdapter,
    D3D_DRIVER_TYPE DriverType,
    HMODULE Software,
    UINT Flags,
    const D3D_FEATURE_LEVEL* pFeatureLevels,
    UINT FeatureLevels,
    UINT SDKVersion,
    const DXGI_SWAP_CHAIN_DESC* pSwapChainDesc,
    IDXGISwapChain** ppSwapChain,
    ID3D11Device** ppDevice,
    D3D_FEATURE_LEVEL* pFeatureLevel,
    ID3D11DeviceContext** ppImmediateContext
) {
    if (!InitRealD3D11()) return E_FAIL;

    ID3D11Device* pRealDevice = nullptr;
    ID3D11DeviceContext* pRealContext = nullptr;

    HRESULT hr = g_pfnCreateDeviceAndSwapChain(
        pAdapter, DriverType, Software, Flags,
        pFeatureLevels, FeatureLevels, SDKVersion,
        pSwapChainDesc, ppSwapChain,
        ppDevice ? &pRealDevice : nullptr,
        pFeatureLevel,
        ppImmediateContext ? &pRealContext : nullptr
    );

    if (SUCCEEDED(hr)) {
        WrapDeviceAndContext(&pRealDevice, &pRealContext);
        if (ppDevice) *ppDevice = pRealDevice;
        if (ppImmediateContext) *ppImmediateContext = pRealContext;
        if (ppSwapChain) WrapSwapChain(ppSwapChain, pSwapChainDesc);
    }
    return hr;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            break;
        case DLL_PROCESS_DETACH:
            FlushStats();
            if (g_realD3D11) {
                FreeLibrary(g_realD3D11);
                g_realD3D11 = nullptr;
            }
            break;
    }
    return TRUE;
}
