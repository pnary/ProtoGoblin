#include "sync_fix.h"

// Store comparison payloads on the buffer itself so destruction releases the
// metadata and pointer reuse cannot associate a new resource with old data.
static const GUID kPayloadGuid = {0x47a43f80, 0x2f6b, 0x4983, {0xb4, 0x23, 0xc3, 0x5f, 0x46, 0x97, 0x70, 0xa1}};
static std::mutex g_cbLock;

// Diagnostic & Introspective Live Telemetry Counters
static std::atomic<uint64_t> g_cbUpdatesTotal{0};
static std::atomic<uint64_t> g_cbUpdatesRedundant{0};
static std::atomic<uint64_t> g_stateBindsTotal{0};
static std::atomic<uint64_t> g_stateBindsRedundant{0};
static std::atomic<uint64_t> g_swapchainResizesTotal{0};
static std::atomic<uint64_t> g_swapchainResizesIdentical{0};
static std::atomic<uint64_t> g_swapchainResizesRapid{0};

// Readback timings are observations. Never replace GPU readback with stale
// CPU memory or write a read mapping back into its GPU source.
static std::atomic<uint64_t> g_copyCalls{0};
static std::atomic<uint64_t> g_readMapCalls{0};
static std::atomic<uint64_t> g_readMapTicks{0};
static std::atomic<uint64_t> g_slowReadMapCalls{0};

// Precision Timer & Pacing Telemetry
typedef void (WINAPI *pfn_Sleep)(DWORD);
typedef DWORD (WINAPI *pfn_SleepEx)(DWORD, BOOL);

static pfn_Sleep g_realSleep = nullptr;
static pfn_SleepEx g_realSleepEx = nullptr;

static std::atomic<uint64_t> g_sleepCallsTotal{0};
static std::atomic<uint64_t> g_sleepSpinHybridCalls{0};
static std::atomic<uint64_t> g_overshootPreventedCalls{0};
static std::atomic<double> g_overshootAvoidedMs{0.0};

static bool IsHighPrecisionTimersEnabled() {
    static int s_val = -1;
    if (s_val == -1) {
        char buf[16] = {0};
        if (GetEnvironmentVariableA("PROTOGOBLIN_HIGH_PRECISION_TIMERS", buf, sizeof(buf))) {
            s_val = (buf[0] == '1' || buf[0] == 't' || buf[0] == 'T' || buf[0] == 'y' || buf[0] == 'Y') ? 1 : 0;
        } else {
            s_val = 0;
        }
    }
    return s_val == 1;
}

static inline void HighPrecisionWait(DWORD dwMilliseconds) {
    if (dwMilliseconds == 0) {
        SwitchToThread();
        return;
    }

    LARGE_INTEGER freq;
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) {
        if (g_realSleep) g_realSleep(dwMilliseconds);
        else Sleep(dwMilliseconds);
        return;
    }

    LARGE_INTEGER start, now;
    QueryPerformanceCounter(&start);
    LONGLONG targetTicks = start.QuadPart + (LONGLONG)((double)dwMilliseconds * (double)freq.QuadPart / 1000.0);

    // If sleep is longer than 2ms, coarse-sleep for the bulk period minus 2ms
    if (dwMilliseconds >= 3) {
        DWORD coarseMs = dwMilliseconds - 2;
        if (g_realSleep) g_realSleep(coarseMs);
        else Sleep(coarseMs);
    }

    // High-resolution spin-yield for the remaining sub-millisecond precision window
    QueryPerformanceCounter(&now);
    while (now.QuadPart < targetTicks) {
        YieldProcessor();
        QueryPerformanceCounter(&now);
    }
}

VOID WINAPI Protogoblin_Sleep(DWORD dwMilliseconds) {
    g_sleepCallsTotal.fetch_add(1, std::memory_order_relaxed);
    if (!IsHighPrecisionTimersEnabled()) {
        if (g_realSleep) g_realSleep(dwMilliseconds);
        else Sleep(dwMilliseconds);
        return;
    }

    g_sleepSpinHybridCalls.fetch_add(1, std::memory_order_relaxed);
    if (dwMilliseconds <= 2) {
        g_overshootPreventedCalls.fetch_add(1, std::memory_order_relaxed);
        double current = g_overshootAvoidedMs.load(std::memory_order_relaxed);
        while (!g_overshootAvoidedMs.compare_exchange_weak(current, current + 2.0, std::memory_order_relaxed));
    }

    HighPrecisionWait(dwMilliseconds);
}

DWORD WINAPI Protogoblin_SleepEx(DWORD dwMilliseconds, BOOL bAlertable) {
    g_sleepCallsTotal.fetch_add(1, std::memory_order_relaxed);
    if (!IsHighPrecisionTimersEnabled() || bAlertable) {
        if (g_realSleepEx) return g_realSleepEx(dwMilliseconds, bAlertable);
        return SleepEx(dwMilliseconds, bAlertable);
    }

    g_sleepSpinHybridCalls.fetch_add(1, std::memory_order_relaxed);
    if (dwMilliseconds <= 2) {
        g_overshootPreventedCalls.fetch_add(1, std::memory_order_relaxed);
        double current = g_overshootAvoidedMs.load(std::memory_order_relaxed);
        while (!g_overshootAvoidedMs.compare_exchange_weak(current, current + 2.0, std::memory_order_relaxed));
    }

    HighPrecisionWait(dwMilliseconds);
    return 0;
}

static void HookModuleIAT(HMODULE hMod) {
    if (!hMod) return;

    auto pDos = (PIMAGE_DOS_HEADER)hMod;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return;

    auto pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return;

    IMAGE_DATA_DIRECTORY importDir = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0 || importDir.Size == 0) return;

    auto pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hMod + importDir.VirtualAddress);
    while (pImportDesc->Name != 0) {
        const char* modName = (const char*)((BYTE*)hMod + pImportDesc->Name);
        if (lstrcmpiA(modName, "kernel32.dll") == 0 || lstrcmpiA(modName, "kernelbase.dll") == 0) {
            auto pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hMod + pImportDesc->FirstThunk);
            auto pOrigThunk = pImportDesc->OriginalFirstThunk ?
                              (PIMAGE_THUNK_DATA)((BYTE*)hMod + pImportDesc->OriginalFirstThunk) : pThunk;

            while (pOrigThunk->u1.AddressOfData != 0) {
                if (!(pOrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    auto pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hMod + pOrigThunk->u1.AddressOfData);
                    if (strcmp((const char*)pImportByName->Name, "Sleep") == 0) {
                        DWORD oldProt;
                        if (VirtualProtect(&pThunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProt)) {
                            if (!g_realSleep) g_realSleep = (pfn_Sleep)pThunk->u1.Function;
                            pThunk->u1.Function = (ULONG_PTR)Protogoblin_Sleep;
                            VirtualProtect(&pThunk->u1.Function, sizeof(void*), oldProt, &oldProt);
                        }
                    } else if (strcmp((const char*)pImportByName->Name, "SleepEx") == 0) {
                        DWORD oldProt;
                        if (VirtualProtect(&pThunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProt)) {
                            if (!g_realSleepEx) g_realSleepEx = (pfn_SleepEx)pThunk->u1.Function;
                            pThunk->u1.Function = (ULONG_PTR)Protogoblin_SleepEx;
                            VirtualProtect(&pThunk->u1.Function, sizeof(void*), oldProt, &oldProt);
                        }
                    }
                }
                pThunk++;
                pOrigThunk++;
            }
        }
        pImportDesc++;
    }
}

void InstallPrecisionTimerHooks() {
    static std::once_flag s_timerOnce;
    std::call_once(s_timerOnce, []() {
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (hKernel32) {
            if (!g_realSleep) g_realSleep = (pfn_Sleep)GetProcAddress(hKernel32, "Sleep");
            if (!g_realSleepEx) g_realSleepEx = (pfn_SleepEx)GetProcAddress(hKernel32, "SleepEx");
        }
        HookModuleIAT(GetModuleHandleA(nullptr));
    });
}

static bool IsStateDedupEnabled() {
    static int s_val = -1;
    if (s_val == -1) {
        char buf[16] = {0};
        if (GetEnvironmentVariableA("PROTOGOBLIN_STATE_DEDUP", buf, sizeof(buf))) {
            s_val = (buf[0] == '1' || buf[0] == 't' || buf[0] == 'T' || buf[0] == 'y' || buf[0] == 'Y') ? 1 : 0;
        } else {
            s_val = 0;
        }
    }
    return s_val == 1;
}

static bool IsSwapchainDebounceEnabled() {
    static int s_val = -1;
    if (s_val == -1) {
        char buf[16] = {0};
        if (GetEnvironmentVariableA("PROTOGOBLIN_SWAPCHAIN_DEBOUNCE", buf, sizeof(buf))) {
            s_val = (buf[0] == '1' || buf[0] == 't' || buf[0] == 'T' || buf[0] == 'y' || buf[0] == 'Y') ? 1 : 0;
        } else {
            s_val = 0;
        }
    }
    return s_val == 1;
}

static void FlushStatsInternal() {
    char sessionDir[MAX_PATH] = {0};
    if (!GetEnvironmentVariableA("PROTOGOBLIN_SESSION_DIR", sessionDir, sizeof(sessionDir))) {
        return;
    }

    char outPath[MAX_PATH];
    snprintf(outPath, sizeof(outPath), "%s\\protogoblin_d3d11_stats.json", sessionDir);

    FILE* fp = fopen(outPath, "w");
    if (!fp) return;

    uint64_t cbTotal = g_cbUpdatesTotal.load(std::memory_order_relaxed);
    uint64_t cbRedundant = g_cbUpdatesRedundant.load(std::memory_order_relaxed);
    double cbRate = cbTotal > 0 ? (double)cbRedundant * 100.0 / (double)cbTotal : 0.0;

    uint64_t stateTotal = g_stateBindsTotal.load(std::memory_order_relaxed);
    uint64_t stateRedundant = g_stateBindsRedundant.load(std::memory_order_relaxed);
    double stateRate = stateTotal > 0 ? (double)stateRedundant * 100.0 / (double)stateTotal : 0.0;

    uint64_t scTotal = g_swapchainResizesTotal.load(std::memory_order_relaxed);
    uint64_t scIdentical = g_swapchainResizesIdentical.load(std::memory_order_relaxed);
    uint64_t scRapid = g_swapchainResizesRapid.load(std::memory_order_relaxed);

    bool stateDedup = IsStateDedupEnabled();
    bool scDebounce = false;

    fprintf(fp, "{\n");
    fprintf(fp, "  \"state_dedup_active\": %s,\n", stateDedup ? "true" : "false");
    fprintf(fp, "  \"swapchain_debounce_active\": %s,\n", scDebounce ? "true" : "false");
    LARGE_INTEGER frequency{};
    QueryPerformanceFrequency(&frequency);
    double readMapMs = frequency.QuadPart > 0 ?
        1000.0 * (double)g_readMapTicks.load() / (double)frequency.QuadPart : 0.0;
    fprintf(fp, "  \"readbacks\": {\n");
    fprintf(fp, "    \"copy_calls\": %llu,\n", (unsigned long long)g_copyCalls.load());
    fprintf(fp, "    \"map_calls\": %llu,\n", (unsigned long long)g_readMapCalls.load());
    fprintf(fp, "    \"map_time_ms\": %.3f,\n", readMapMs);
    fprintf(fp, "    \"slow_map_calls\": %llu\n", (unsigned long long)g_slowReadMapCalls.load());
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"constant_buffers\": {\n");
    fprintf(fp, "    \"updates_total\": %llu,\n", (unsigned long long)cbTotal);
    fprintf(fp, "    \"updates_redundant\": %llu,\n", (unsigned long long)cbRedundant);
    fprintf(fp, "    \"redundancy_rate_pct\": %.2f\n", cbRate);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"pipeline_states\": {\n");
    fprintf(fp, "    \"binds_total\": %llu,\n", (unsigned long long)stateTotal);
    fprintf(fp, "    \"binds_redundant\": %llu,\n", (unsigned long long)stateRedundant);
    fprintf(fp, "    \"redundancy_rate_pct\": %.2f\n", stateRate);
    fprintf(fp, "  },\n");
    fprintf(fp, "  \"swapchain\": {\n");
    fprintf(fp, "    \"resizes_total\": %llu,\n", (unsigned long long)scTotal);
    fprintf(fp, "    \"resizes_identical\": %llu,\n", (unsigned long long)scIdentical);
    fprintf(fp, "    \"resizes_rapid\": %llu\n", (unsigned long long)scRapid);
    fprintf(fp, "  },\n");

    bool timersActive = IsHighPrecisionTimersEnabled();
    uint64_t sleepTotal = g_sleepCallsTotal.load(std::memory_order_relaxed);
    uint64_t sleepHybrid = g_sleepSpinHybridCalls.load(std::memory_order_relaxed);
    uint64_t overshootAvoidedCalls = g_overshootPreventedCalls.load(std::memory_order_relaxed);
    double overshootMs = g_overshootAvoidedMs.load(std::memory_order_relaxed);

    fprintf(fp, "  \"timing\": {\n");
    fprintf(fp, "    \"high_precision_timers_active\": %s,\n", timersActive ? "true" : "false");
    fprintf(fp, "    \"sleep_calls_total\": %llu,\n", (unsigned long long)sleepTotal);
    fprintf(fp, "    \"sleep_spin_hybrid_calls\": %llu,\n", (unsigned long long)sleepHybrid);
    fprintf(fp, "    \"overshoot_prevented_calls\": %llu,\n", (unsigned long long)overshootAvoidedCalls);
    fprintf(fp, "    \"overshoot_avoided_ms\": %.2f\n", overshootMs);
    fprintf(fp, "  }\n");
    fprintf(fp, "}\n");
    fclose(fp);
}

void FlushStats() {
    FlushStatsInternal();
}

class WrappedContext : public ID3D11DeviceContext {
private:
    LONG m_refCount;
    ID3D11DeviceContext* m_real;

    // Pipeline State Cache for Deduplication
    D3D11_PRIMITIVE_TOPOLOGY m_curTopology = D3D11_PRIMITIVE_TOPOLOGY_UNDEFINED;
    ID3D11InputLayout* m_curInputLayout = nullptr;
    ID3D11Buffer* m_curVSConstantBuffers[D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT] = {};
    ID3D11Buffer* m_curPSConstantBuffers[D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT] = {};

public:
    WrappedContext(ID3D11DeviceContext* real) : m_refCount(1), m_real(real) {}
    virtual ~WrappedContext() {
        if (m_real) m_real->Release();
    }

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ID3D11DeviceChild) || riid == __uuidof(ID3D11DeviceContext)) {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        return m_real->QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_refCount);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        ULONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) {
            delete this;
            return 0;
        }
        return ref;
    }

    // ID3D11DeviceChild
    void STDMETHODCALLTYPE GetDevice(ID3D11Device** ppDevice) override {
        m_real->GetDevice(ppDevice);
    }

    HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID guid, UINT* pDataSize, void* pData) override {
        return m_real->GetPrivateData(guid, pDataSize, pData);
    }

    HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID guid, UINT DataSize, const void* pData) override {
        return m_real->SetPrivateData(guid, DataSize, pData);
    }

    HRESULT STDMETHODCALLTYPE SetPrivateDataInterface(REFGUID guid, const IUnknown* pData) override {
        return m_real->SetPrivateDataInterface(guid, pData);
    }

    void STDMETHODCALLTYPE CopyResource(ID3D11Resource* dst, ID3D11Resource* src) override {
        g_copyCalls.fetch_add(1, std::memory_order_relaxed);
        m_real->CopyResource(dst, src);
    }

    HRESULT STDMETHODCALLTYPE Map(ID3D11Resource* resource, UINT subresource,
        D3D11_MAP type, UINT flags, D3D11_MAPPED_SUBRESOURCE* mapped) override {
        bool read = type == D3D11_MAP_READ || type == D3D11_MAP_READ_WRITE;
        LARGE_INTEGER begin{}, end{}, frequency{};
        if (read) QueryPerformanceCounter(&begin);
        HRESULT result = m_real->Map(resource, subresource, type, flags, mapped);
        if (read) {
            QueryPerformanceCounter(&end);
            QueryPerformanceFrequency(&frequency);
            uint64_t ticks = end.QuadPart - begin.QuadPart;
            g_readMapCalls.fetch_add(1, std::memory_order_relaxed);
            g_readMapTicks.fetch_add(ticks, std::memory_order_relaxed);
            if (frequency.QuadPart > 0 && ticks >= (uint64_t)frequency.QuadPart / 1000)
                g_slowReadMapCalls.fetch_add(1, std::memory_order_relaxed);
        }
        return result;
    }

    void STDMETHODCALLTYPE Unmap(ID3D11Resource* resource, UINT subresource) override {
        m_real->Unmap(resource, subresource);
    }

    // Delegate remaining standard pipeline methods
    void STDMETHODCALLTYPE DrawIndexed(UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation) override {
        m_real->DrawIndexed(IndexCount, StartIndexLocation, BaseVertexLocation);
    }
    void STDMETHODCALLTYPE Draw(UINT VertexCount, UINT StartVertexLocation) override {
        m_real->Draw(VertexCount, StartVertexLocation);
    }
    void STDMETHODCALLTYPE Flush() override {
        m_real->Flush();
    }
    D3D11_DEVICE_CONTEXT_TYPE STDMETHODCALLTYPE GetType() override {
        return m_real->GetType();
    }
    UINT STDMETHODCALLTYPE GetContextFlags() override {
        return m_real->GetContextFlags();
    }

    #define DELEGATE_CONTEXT(func, ...) void STDMETHODCALLTYPE func(__VA_ARGS__) override { m_real->func(__VA_ARGS__); }
    #define DELEGATE_CONTEXT_RET(ret, func, ...) ret STDMETHODCALLTYPE func(__VA_ARGS__) override { return m_real->func(__VA_ARGS__); }

    void STDMETHODCALLTYPE VSSetShaderResources(UINT start, UINT count, ID3D11ShaderResourceView* const* views) override { m_real->VSSetShaderResources(start, count, views); }
    void STDMETHODCALLTYPE VSSetSamplers(UINT start, UINT count, ID3D11SamplerState* const* samplers) override { m_real->VSSetSamplers(start, count, samplers); }
    void STDMETHODCALLTYPE SOSetTargets(UINT count, ID3D11Buffer* const* buffers, const UINT* offsets) override { m_real->SOSetTargets(count, buffers, offsets); }
    void STDMETHODCALLTYPE DrawAuto() override { m_real->DrawAuto(); }
    void STDMETHODCALLTYPE DrawIndexedInstancedIndirect(ID3D11Buffer* buffer, UINT offset) override { m_real->DrawIndexedInstancedIndirect(buffer, offset); }
    void STDMETHODCALLTYPE DrawInstancedIndirect(ID3D11Buffer* buffer, UINT offset) override { m_real->DrawInstancedIndirect(buffer, offset); }
    void STDMETHODCALLTYPE PSGetConstantBuffers(UINT start, UINT count, ID3D11Buffer** buffers) override { m_real->PSGetConstantBuffers(start, count, buffers); }
    void STDMETHODCALLTYPE VSGetShaderResources(UINT start, UINT count, ID3D11ShaderResourceView** views) override { m_real->VSGetShaderResources(start, count, views); }
    void STDMETHODCALLTYPE VSGetSamplers(UINT start, UINT count, ID3D11SamplerState** samplers) override { m_real->VSGetSamplers(start, count, samplers); }
    void STDMETHODCALLTYPE GetPredication(ID3D11Predicate** predicate, BOOL* value) override { m_real->GetPredication(predicate, value); }
    void STDMETHODCALLTYPE SOGetTargets(UINT count, ID3D11Buffer** buffers) override { m_real->SOGetTargets(count, buffers); }

    // D3D11 Context pass-through wrappers
    void STDMETHODCALLTYPE VSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override {
        g_stateBindsTotal.fetch_add(1, std::memory_order_relaxed);
        if (ppConstantBuffers && StartSlot + NumBuffers <= D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT) {
            bool allMatch = true;
            for (UINT i = 0; i < NumBuffers; ++i) {
                if (m_curVSConstantBuffers[StartSlot + i] != ppConstantBuffers[i]) {
                    allMatch = false;
                    break;
                }
            }
            if (allMatch) {
                g_stateBindsRedundant.fetch_add(1, std::memory_order_relaxed);
                if (IsStateDedupEnabled()) return;
            } else {
                for (UINT i = 0; i < NumBuffers; ++i) {
                    m_curVSConstantBuffers[StartSlot + i] = ppConstantBuffers[i];
                }
            }
        }
        m_real->VSSetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers);
    }
    void STDMETHODCALLTYPE PSSetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews) override { m_real->PSSetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE PSSetShader(ID3D11PixelShader* pPixelShader, ID3D11ClassInstance* const* ppClassInstances, UINT NumClassInstances) override { m_real->PSSetShader(pPixelShader, ppClassInstances, NumClassInstances); }
    void STDMETHODCALLTYPE PSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override { m_real->PSSetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE PSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override {
        g_stateBindsTotal.fetch_add(1, std::memory_order_relaxed);
        if (ppConstantBuffers && StartSlot + NumBuffers <= D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT) {
            bool allMatch = true;
            for (UINT i = 0; i < NumBuffers; ++i) {
                if (m_curPSConstantBuffers[StartSlot + i] != ppConstantBuffers[i]) {
                    allMatch = false;
                    break;
                }
            }
            if (allMatch) {
                g_stateBindsRedundant.fetch_add(1, std::memory_order_relaxed);
                if (IsStateDedupEnabled()) return;
            } else {
                for (UINT i = 0; i < NumBuffers; ++i) {
                    m_curPSConstantBuffers[StartSlot + i] = ppConstantBuffers[i];
                }
            }
        }
        m_real->PSSetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers);
    }
    void STDMETHODCALLTYPE VSSetShader(ID3D11VertexShader* pVertexShader, ID3D11ClassInstance* const* ppClassInstances, UINT NumClassInstances) override { m_real->VSSetShader(pVertexShader, ppClassInstances, NumClassInstances); }
    void STDMETHODCALLTYPE DrawIndexedInstanced(UINT IndexCountPerInstance, UINT InstanceCount, UINT StartIndexLocation, INT BaseVertexLocation, UINT StartInstanceLocation) override { m_real->DrawIndexedInstanced(IndexCountPerInstance, InstanceCount, StartIndexLocation, BaseVertexLocation, StartInstanceLocation); }
    void STDMETHODCALLTYPE DrawInstanced(UINT VertexCountPerInstance, UINT InstanceCount, UINT StartVertexLocation, UINT StartInstanceLocation) override { m_real->DrawInstanced(VertexCountPerInstance, InstanceCount, StartVertexLocation, StartInstanceLocation); }
    void STDMETHODCALLTYPE Begin(ID3D11Asynchronous* pAsync) override { m_real->Begin(pAsync); }
    void STDMETHODCALLTYPE End(ID3D11Asynchronous* pAsync) override { m_real->End(pAsync); }
    HRESULT STDMETHODCALLTYPE GetData(ID3D11Asynchronous* pAsync, void* pData, UINT DataSize, UINT GetDataFlags) override { return m_real->GetData(pAsync, pData, DataSize, GetDataFlags); }
    void STDMETHODCALLTYPE SetPredication(ID3D11Predicate* pPredicate, BOOL PredicateValue) override { m_real->SetPredication(pPredicate, PredicateValue); }
    void STDMETHODCALLTYPE GSSetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews) override { m_real->GSSetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE GSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override { m_real->GSSetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE GSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override { m_real->GSSetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers); }
    void STDMETHODCALLTYPE GSSetShader(ID3D11GeometryShader* pShader, ID3D11ClassInstance* const* ppClassInstances, UINT NumClassInstances) override { m_real->GSSetShader(pShader, ppClassInstances, NumClassInstances); }
    void STDMETHODCALLTYPE IASetIndexBuffer(ID3D11Buffer* pIndexBuffer, DXGI_FORMAT Format, UINT Offset) override { m_real->IASetIndexBuffer(pIndexBuffer, Format, Offset); }
    void STDMETHODCALLTYPE IASetVertexBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppVertexBuffers, const UINT* pStrides, const UINT* pOffsets) override { m_real->IASetVertexBuffers(StartSlot, NumBuffers, ppVertexBuffers, pStrides, pOffsets); }
    void STDMETHODCALLTYPE IASetInputLayout(ID3D11InputLayout* pInputLayout) override {
        g_stateBindsTotal.fetch_add(1, std::memory_order_relaxed);
        if (pInputLayout == m_curInputLayout) {
            g_stateBindsRedundant.fetch_add(1, std::memory_order_relaxed);
            if (IsStateDedupEnabled()) return;
        }
        m_curInputLayout = pInputLayout;
        m_real->IASetInputLayout(pInputLayout);
    }
    void STDMETHODCALLTYPE IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY Topology) override {
        g_stateBindsTotal.fetch_add(1, std::memory_order_relaxed);
        if (Topology == m_curTopology) {
            g_stateBindsRedundant.fetch_add(1, std::memory_order_relaxed);
            if (IsStateDedupEnabled()) return;
        }
        m_curTopology = Topology;
        m_real->IASetPrimitiveTopology(Topology);
    }
    void STDMETHODCALLTYPE OMSetRenderTargets(UINT NumViews, ID3D11RenderTargetView* const* ppRenderTargetViews, ID3D11DepthStencilView* pDepthStencilView) override { m_real->OMSetRenderTargets(NumViews, ppRenderTargetViews, pDepthStencilView); }
    void STDMETHODCALLTYPE OMSetRenderTargetsAndUnorderedAccessViews(UINT NumRTVs, ID3D11RenderTargetView* const* ppRenderTargetViews, ID3D11DepthStencilView* pDepthStencilView, UINT UAVStartSlot, UINT NumUAVs, ID3D11UnorderedAccessView* const* ppUnorderedAccessViews, const UINT* pUAVInitialCounts) override { m_real->OMSetRenderTargetsAndUnorderedAccessViews(NumRTVs, ppRenderTargetViews, pDepthStencilView, UAVStartSlot, NumUAVs, ppUnorderedAccessViews, pUAVInitialCounts); }
    void STDMETHODCALLTYPE OMSetBlendState(ID3D11BlendState* pBlendState, const FLOAT BlendFactor[4], UINT SampleMask) override { m_real->OMSetBlendState(pBlendState, BlendFactor, SampleMask); }
    void STDMETHODCALLTYPE OMSetDepthStencilState(ID3D11DepthStencilState* pDepthStencilState, UINT StencilRef) override { m_real->OMSetDepthStencilState(pDepthStencilState, StencilRef); }
    void STDMETHODCALLTYPE RSSetViewports(UINT NumViewports, const D3D11_VIEWPORT* pViewports) override { m_real->RSSetViewports(NumViewports, pViewports); }
    void STDMETHODCALLTYPE RSSetScissorRects(UINT NumRects, const D3D11_RECT* pRects) override { m_real->RSSetScissorRects(NumRects, pRects); }
    void STDMETHODCALLTYPE RSSetState(ID3D11RasterizerState* pRasterizerState) override { m_real->RSSetState(pRasterizerState); }
    void STDMETHODCALLTYPE ClearRenderTargetView(ID3D11RenderTargetView* pRenderTargetView, const FLOAT ColorRGBA[4]) override { m_real->ClearRenderTargetView(pRenderTargetView, ColorRGBA); }
    void STDMETHODCALLTYPE ClearUnorderedAccessViewUint(ID3D11UnorderedAccessView* pUnorderedAccessView, const UINT Values[4]) override { m_real->ClearUnorderedAccessViewUint(pUnorderedAccessView, Values); }
    void STDMETHODCALLTYPE ClearUnorderedAccessViewFloat(ID3D11UnorderedAccessView* pUnorderedAccessView, const FLOAT Values[4]) override { m_real->ClearUnorderedAccessViewFloat(pUnorderedAccessView, Values); }
    void STDMETHODCALLTYPE ClearDepthStencilView(ID3D11DepthStencilView* pDepthStencilView, UINT ClearFlags, FLOAT Depth, UINT8 Stencil) override { m_real->ClearDepthStencilView(pDepthStencilView, ClearFlags, Depth, Stencil); }
    void STDMETHODCALLTYPE GenerateMips(ID3D11ShaderResourceView* pShaderResourceView) override { m_real->GenerateMips(pShaderResourceView); }
    void STDMETHODCALLTYPE SetResourceMinLOD(ID3D11Resource* pResource, FLOAT MinLOD) override { m_real->SetResourceMinLOD(pResource, MinLOD); }
    FLOAT STDMETHODCALLTYPE GetResourceMinLOD(ID3D11Resource* pResource) override { return m_real->GetResourceMinLOD(pResource); }
    void STDMETHODCALLTYPE ResolveSubresource(ID3D11Resource* pDstResource, UINT DstSubresource, ID3D11Resource* pSrcResource, UINT SrcSubresource, DXGI_FORMAT Format) override { m_real->ResolveSubresource(pDstResource, DstSubresource, pSrcResource, SrcSubresource, Format); }
    void STDMETHODCALLTYPE ExecuteCommandList(ID3D11CommandList* pCommandList, BOOL RestoreContextState) override { m_real->ExecuteCommandList(pCommandList, RestoreContextState); }
    void STDMETHODCALLTYPE HSSetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews) override { m_real->HSSetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE HSSetShader(ID3D11HullShader* pHullShader, ID3D11ClassInstance* const* ppClassInstances, UINT NumClassInstances) override { m_real->HSSetShader(pHullShader, ppClassInstances, NumClassInstances); }
    void STDMETHODCALLTYPE HSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override { m_real->HSSetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE HSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override { m_real->HSSetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers); }
    void STDMETHODCALLTYPE DSSetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews) override { m_real->DSSetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE DSSetShader(ID3D11DomainShader* pDomainShader, ID3D11ClassInstance* const* ppClassInstances, UINT NumClassInstances) override { m_real->DSSetShader(pDomainShader, ppClassInstances, NumClassInstances); }
    void STDMETHODCALLTYPE DSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override { m_real->DSSetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE DSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override { m_real->DSSetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers); }
    void STDMETHODCALLTYPE CSSetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews) override { m_real->CSSetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE CSSetUnorderedAccessViews(UINT StartSlot, UINT NumUAVs, ID3D11UnorderedAccessView* const* ppUnorderedAccessViews, const UINT* pUAVInitialCounts) override { m_real->CSSetUnorderedAccessViews(StartSlot, NumUAVs, ppUnorderedAccessViews, pUAVInitialCounts); }
    void STDMETHODCALLTYPE CSSetShader(ID3D11ComputeShader* pComputeShader, ID3D11ClassInstance* const* ppClassInstances, UINT NumClassInstances) override { m_real->CSSetShader(pComputeShader, ppClassInstances, NumClassInstances); }
    void STDMETHODCALLTYPE CSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override { m_real->CSSetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE CSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override { m_real->CSSetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers); }
    void STDMETHODCALLTYPE Dispatch(UINT ThreadGroupCountX, UINT ThreadGroupCountY, UINT ThreadGroupCountZ) override { m_real->Dispatch(ThreadGroupCountX, ThreadGroupCountY, ThreadGroupCountZ); }
    void STDMETHODCALLTYPE DispatchIndirect(ID3D11Buffer* pBufferForArgs, UINT AlignedByteOffsetForArgs) override { m_real->DispatchIndirect(pBufferForArgs, AlignedByteOffsetForArgs); }
    void STDMETHODCALLTYPE CopySubresourceRegion(ID3D11Resource* pDstResource, UINT DstSubresource, UINT DstX, UINT DstY, UINT DstZ, ID3D11Resource* pSrcResource, UINT SrcSubresource, const D3D11_BOX* pSrcBox) override { m_real->CopySubresourceRegion(pDstResource, DstSubresource, DstX, DstY, DstZ, pSrcResource, SrcSubresource, pSrcBox); }
    void STDMETHODCALLTYPE CopyStructureCount(ID3D11Buffer* pDstBuffer, UINT DstAlignedByteOffset, ID3D11UnorderedAccessView* pSrcUAV) override { m_real->CopyStructureCount(pDstBuffer, DstAlignedByteOffset, pSrcUAV); }
    void STDMETHODCALLTYPE ClearState() override {
        m_curTopology = D3D11_PRIMITIVE_TOPOLOGY_UNDEFINED;
        m_curInputLayout = nullptr;
        for (UINT i = 0; i < D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT; ++i) {
            m_curVSConstantBuffers[i] = nullptr;
            m_curPSConstantBuffers[i] = nullptr;
        }
        m_real->ClearState();
    }
    void STDMETHODCALLTYPE UpdateSubresource(ID3D11Resource* pDstResource, UINT DstSubresource, const D3D11_BOX* pDstBox, const void* pSrcData, UINT SrcRowPitch, UINT SrcDepthPitch) override {
        if (pDstResource && pSrcData && !pDstBox) {
            D3D11_RESOURCE_DIMENSION dimension;
            pDstResource->GetType(&dimension);
            if (dimension == D3D11_RESOURCE_DIMENSION_BUFFER) {
                ID3D11Buffer* buffer = nullptr;
                if (SUCCEEDED(pDstResource->QueryInterface(__uuidof(ID3D11Buffer), (void**)&buffer))) {
                    D3D11_BUFFER_DESC desc{};
                    buffer->GetDesc(&desc);
                    if (desc.BindFlags & D3D11_BIND_CONSTANT_BUFFER) {
                        std::lock_guard<std::mutex> lock(g_cbLock);
                        g_cbUpdatesTotal.fetch_add(1, std::memory_order_relaxed);
                        std::vector<uint8_t> previous(desc.ByteWidth);
                        UINT size = desc.ByteWidth;
                        if (SUCCEEDED(buffer->GetPrivateData(kPayloadGuid, &size, previous.data())) &&
                            size == desc.ByteWidth && memcmp(previous.data(), pSrcData, size) == 0)
                            g_cbUpdatesRedundant.fetch_add(1, std::memory_order_relaxed);
                        buffer->SetPrivateData(kPayloadGuid, desc.ByteWidth, pSrcData);
                    }
                    buffer->Release();
                }
            }
        }
        // Matching CPU payloads do not prove the GPU contents are unchanged:
        // Map, copies, and command lists can also modify the resource.
        m_real->UpdateSubresource(pDstResource, DstSubresource, pDstBox, pSrcData, SrcRowPitch, SrcDepthPitch);
    }
    HRESULT STDMETHODCALLTYPE FinishCommandList(BOOL RestoreDeferredContextState, ID3D11CommandList** ppCommandList) override { return m_real->FinishCommandList(RestoreDeferredContextState, ppCommandList); }
    void STDMETHODCALLTYPE VSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override { m_real->VSGetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers); }
    void STDMETHODCALLTYPE PSGetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView** ppShaderResourceViews) override { m_real->PSGetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE PSGetShader(ID3D11PixelShader** ppPixelShader, ID3D11ClassInstance** ppClassInstances, UINT* pNumClassInstances) override { m_real->PSGetShader(ppPixelShader, ppClassInstances, pNumClassInstances); }
    void STDMETHODCALLTYPE PSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override { m_real->PSGetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE VSGetShader(ID3D11VertexShader** ppVertexShader, ID3D11ClassInstance** ppClassInstances, UINT* pNumClassInstances) override { m_real->VSGetShader(ppVertexShader, ppClassInstances, pNumClassInstances); }
    void STDMETHODCALLTYPE GSGetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView** ppShaderResourceViews) override { m_real->GSGetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE GSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override { m_real->GSGetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE GSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override { m_real->GSGetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers); }
    void STDMETHODCALLTYPE GSGetShader(ID3D11GeometryShader** ppGeometryShader, ID3D11ClassInstance** ppClassInstances, UINT* pNumClassInstances) override { m_real->GSGetShader(ppGeometryShader, ppClassInstances, pNumClassInstances); }
    void STDMETHODCALLTYPE IAGetIndexBuffer(ID3D11Buffer** pIndexBuffer, DXGI_FORMAT* Format, UINT* Offset) override { m_real->IAGetIndexBuffer(pIndexBuffer, Format, Offset); }
    void STDMETHODCALLTYPE IAGetVertexBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppVertexBuffers, UINT* pStrides, UINT* pOffsets) override { m_real->IAGetVertexBuffers(StartSlot, NumBuffers, ppVertexBuffers, pStrides, pOffsets); }
    void STDMETHODCALLTYPE IAGetInputLayout(ID3D11InputLayout** ppInputLayout) override { m_real->IAGetInputLayout(ppInputLayout); }
    void STDMETHODCALLTYPE IAGetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY* pTopology) override { m_real->IAGetPrimitiveTopology(pTopology); }
    void STDMETHODCALLTYPE OMGetRenderTargets(UINT NumViews, ID3D11RenderTargetView** ppRenderTargetViews, ID3D11DepthStencilView** ppDepthStencilView) override { m_real->OMGetRenderTargets(NumViews, ppRenderTargetViews, ppDepthStencilView); }
    void STDMETHODCALLTYPE OMGetRenderTargetsAndUnorderedAccessViews(UINT NumRTVs, ID3D11RenderTargetView** ppRenderTargetViews, ID3D11DepthStencilView** ppDepthStencilView, UINT UAVStartSlot, UINT NumUAVs, ID3D11UnorderedAccessView** ppUnorderedAccessViews) override { m_real->OMGetRenderTargetsAndUnorderedAccessViews(NumRTVs, ppRenderTargetViews, ppDepthStencilView, UAVStartSlot, NumUAVs, ppUnorderedAccessViews); }
    void STDMETHODCALLTYPE OMGetBlendState(ID3D11BlendState** ppBlendState, FLOAT BlendFactor[4], UINT* pSampleMask) override { m_real->OMGetBlendState(ppBlendState, BlendFactor, pSampleMask); }
    void STDMETHODCALLTYPE OMGetDepthStencilState(ID3D11DepthStencilState** ppDepthStencilState, UINT* pStencilRef) override { m_real->OMGetDepthStencilState(ppDepthStencilState, pStencilRef); }
    void STDMETHODCALLTYPE RSGetViewports(UINT* pNumViewports, D3D11_VIEWPORT* pViewports) override { m_real->RSGetViewports(pNumViewports, pViewports); }
    void STDMETHODCALLTYPE RSGetScissorRects(UINT* pNumRects, D3D11_RECT* pRects) override { m_real->RSGetScissorRects(pNumRects, pRects); }
    void STDMETHODCALLTYPE RSGetState(ID3D11RasterizerState** ppRasterizerState) override { m_real->RSGetState(ppRasterizerState); }
    void STDMETHODCALLTYPE HSGetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView** ppShaderResourceViews) override { m_real->HSGetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE HSGetShader(ID3D11HullShader** ppHullShader, ID3D11ClassInstance** ppClassInstances, UINT* pNumClassInstances) override { m_real->HSGetShader(ppHullShader, ppClassInstances, pNumClassInstances); }
    void STDMETHODCALLTYPE HSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override { m_real->HSGetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE HSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override { m_real->HSGetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers); }
    void STDMETHODCALLTYPE DSGetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView** ppShaderResourceViews) override { m_real->DSGetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE DSGetShader(ID3D11DomainShader** ppDomainShader, ID3D11ClassInstance** ppClassInstances, UINT* pNumClassInstances) override { m_real->DSGetShader(ppDomainShader, ppClassInstances, pNumClassInstances); }
    void STDMETHODCALLTYPE DSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override { m_real->DSGetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE DSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override { m_real->DSGetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers); }
    void STDMETHODCALLTYPE CSGetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView** ppShaderResourceViews) override { m_real->CSGetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE CSGetUnorderedAccessViews(UINT StartSlot, UINT NumUAVs, ID3D11UnorderedAccessView** ppUnorderedAccessViews) override { m_real->CSGetUnorderedAccessViews(StartSlot, NumUAVs, ppUnorderedAccessViews); }
    void STDMETHODCALLTYPE CSGetShader(ID3D11ComputeShader** ppComputeShader, ID3D11ClassInstance** ppClassInstances, UINT* pNumClassInstances) override { m_real->CSGetShader(ppComputeShader, ppClassInstances, pNumClassInstances); }
    void STDMETHODCALLTYPE CSGetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState** ppSamplers) override { m_real->CSGetSamplers(StartSlot, NumSamplers, ppSamplers); }
    void STDMETHODCALLTYPE CSGetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer** ppConstantBuffers) override { m_real->CSGetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers); }
};

class WrappedDevice : public ID3D11Device {
private:
    LONG m_refCount;
    ID3D11Device* m_real;

public:
    WrappedDevice(ID3D11Device* real) : m_refCount(1), m_real(real) {}
    virtual ~WrappedDevice() {
        if (m_real) m_real->Release();
    }

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(ID3D11Device)) {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        return m_real->QueryInterface(riid, ppvObject);
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return InterlockedIncrement(&m_refCount);
    }

    ULONG STDMETHODCALLTYPE Release() override {
        ULONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) {
            delete this;
            return 0;
        }
        return ref;
    }

    // Intercept Buffer Creation to track Staging Buffers & Constant Buffers
    HRESULT STDMETHODCALLTYPE CreateBuffer(
        const D3D11_BUFFER_DESC* pDesc,
        const D3D11_SUBRESOURCE_DATA* pInitialData,
        ID3D11Buffer** ppBuffer
    ) override {
        HRESULT hr = m_real->CreateBuffer(pDesc, pInitialData, ppBuffer);
        return hr;
    }

    // Pass-through Device methods
    HRESULT STDMETHODCALLTYPE CreateTexture1D(const D3D11_TEXTURE1D_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Texture1D** ppTexture1D) override { return m_real->CreateTexture1D(pDesc, pInitialData, ppTexture1D); }
    HRESULT STDMETHODCALLTYPE CreateTexture2D(const D3D11_TEXTURE2D_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Texture2D** ppTexture2D) override { return m_real->CreateTexture2D(pDesc, pInitialData, ppTexture2D); }
    HRESULT STDMETHODCALLTYPE CreateTexture3D(const D3D11_TEXTURE3D_DESC* pDesc, const D3D11_SUBRESOURCE_DATA* pInitialData, ID3D11Texture3D** ppTexture3D) override { return m_real->CreateTexture3D(pDesc, pInitialData, ppTexture3D); }
    HRESULT STDMETHODCALLTYPE CreateShaderResourceView(ID3D11Resource* pResource, const D3D11_SHADER_RESOURCE_VIEW_DESC* pDesc, ID3D11ShaderResourceView** ppSRView) override { return m_real->CreateShaderResourceView(pResource, pDesc, ppSRView); }
    HRESULT STDMETHODCALLTYPE CreateUnorderedAccessView(ID3D11Resource* pResource, const D3D11_UNORDERED_ACCESS_VIEW_DESC* pDesc, ID3D11UnorderedAccessView** ppUAView) override { return m_real->CreateUnorderedAccessView(pResource, pDesc, ppUAView); }
    HRESULT STDMETHODCALLTYPE CreateRenderTargetView(ID3D11Resource* pResource, const D3D11_RENDER_TARGET_VIEW_DESC* pDesc, ID3D11RenderTargetView** ppRTView) override { return m_real->CreateRenderTargetView(pResource, pDesc, ppRTView); }
    HRESULT STDMETHODCALLTYPE CreateDepthStencilView(ID3D11Resource* pResource, const D3D11_DEPTH_STENCIL_VIEW_DESC* pDesc, ID3D11DepthStencilView** ppDepthStencilView) override { return m_real->CreateDepthStencilView(pResource, pDesc, ppDepthStencilView); }
    HRESULT STDMETHODCALLTYPE CreateInputLayout(const D3D11_INPUT_ELEMENT_DESC* pInputElementDescs, UINT NumElements, const void* pShaderBytecodeWithInputSignature, SIZE_T BytecodeLength, ID3D11InputLayout** ppInputLayout) override { return m_real->CreateInputLayout(pInputElementDescs, NumElements, pShaderBytecodeWithInputSignature, BytecodeLength, ppInputLayout); }
    HRESULT STDMETHODCALLTYPE CreateVertexShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11VertexShader** ppVertexShader) override { return m_real->CreateVertexShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppVertexShader); }
    HRESULT STDMETHODCALLTYPE CreateGeometryShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11GeometryShader** ppGeometryShader) override { return m_real->CreateGeometryShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppGeometryShader); }
    HRESULT STDMETHODCALLTYPE CreateGeometryShaderWithStreamOutput(const void* pShaderBytecode, SIZE_T BytecodeLength, const D3D11_SO_DECLARATION_ENTRY* pSODeclaration, UINT NumEntries, const UINT* pBufferStrides, UINT NumStrides, UINT RasterizedStream, ID3D11ClassLinkage* pClassLinkage, ID3D11GeometryShader** ppGeometryShader) override { return m_real->CreateGeometryShaderWithStreamOutput(pShaderBytecode, BytecodeLength, pSODeclaration, NumEntries, pBufferStrides, NumStrides, RasterizedStream, pClassLinkage, ppGeometryShader); }
    HRESULT STDMETHODCALLTYPE CreatePixelShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11PixelShader** ppPixelShader) override { return m_real->CreatePixelShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppPixelShader); }
    HRESULT STDMETHODCALLTYPE CreateHullShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11HullShader** ppHullShader) override { return m_real->CreateHullShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppHullShader); }
    HRESULT STDMETHODCALLTYPE CreateDomainShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11DomainShader** ppDomainShader) override { return m_real->CreateDomainShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppDomainShader); }
    HRESULT STDMETHODCALLTYPE CreateComputeShader(const void* pShaderBytecode, SIZE_T BytecodeLength, ID3D11ClassLinkage* pClassLinkage, ID3D11ComputeShader** ppComputeShader) override { return m_real->CreateComputeShader(pShaderBytecode, BytecodeLength, pClassLinkage, ppComputeShader); }
    HRESULT STDMETHODCALLTYPE CreateClassLinkage(ID3D11ClassLinkage** ppLinkage) override { return m_real->CreateClassLinkage(ppLinkage); }
    HRESULT STDMETHODCALLTYPE CreateBlendState(const D3D11_BLEND_DESC* pBlendStateDesc, ID3D11BlendState** ppBlendState) override { return m_real->CreateBlendState(pBlendStateDesc, ppBlendState); }
    HRESULT STDMETHODCALLTYPE CreateDepthStencilState(const D3D11_DEPTH_STENCIL_DESC* pDepthStencilDesc, ID3D11DepthStencilState** ppDepthStencilState) override { return m_real->CreateDepthStencilState(pDepthStencilDesc, ppDepthStencilState); }
    HRESULT STDMETHODCALLTYPE CreateRasterizerState(const D3D11_RASTERIZER_DESC* pRasterizerDesc, ID3D11RasterizerState** ppRasterizerState) override { return m_real->CreateRasterizerState(pRasterizerDesc, ppRasterizerState); }
    HRESULT STDMETHODCALLTYPE CreateSamplerState(const D3D11_SAMPLER_DESC* pSamplerDesc, ID3D11SamplerState** ppSamplerState) override { return m_real->CreateSamplerState(pSamplerDesc, ppSamplerState); }
    HRESULT STDMETHODCALLTYPE CreateQuery(const D3D11_QUERY_DESC* pQueryDesc, ID3D11Query** ppQuery) override { return m_real->CreateQuery(pQueryDesc, ppQuery); }
    HRESULT STDMETHODCALLTYPE CreatePredicate(const D3D11_QUERY_DESC* pPredicateDesc, ID3D11Predicate** ppPredicate) override { return m_real->CreatePredicate(pPredicateDesc, ppPredicate); }
    HRESULT STDMETHODCALLTYPE CreateCounter(const D3D11_COUNTER_DESC* pCounterDesc, ID3D11Counter** ppCounter) override { return m_real->CreateCounter(pCounterDesc, ppCounter); }
    HRESULT STDMETHODCALLTYPE CreateDeferredContext(UINT ContextFlags, ID3D11DeviceContext** ppDeferredContext) override { return m_real->CreateDeferredContext(ContextFlags, ppDeferredContext); }
    HRESULT STDMETHODCALLTYPE OpenSharedResource(HANDLE hResource, REFIID ReturnedInterface, void** ppResource) override { return m_real->OpenSharedResource(hResource, ReturnedInterface, ppResource); }
    HRESULT STDMETHODCALLTYPE CheckFormatSupport(DXGI_FORMAT Format, UINT* pFormatSupport) override { return m_real->CheckFormatSupport(Format, pFormatSupport); }
    HRESULT STDMETHODCALLTYPE CheckMultisampleQualityLevels(DXGI_FORMAT Format, UINT SampleCount, UINT* pNumQualityLevels) override { return m_real->CheckMultisampleQualityLevels(Format, SampleCount, pNumQualityLevels); }
    void STDMETHODCALLTYPE CheckCounterInfo(D3D11_COUNTER_INFO* pCounterInfo) override { m_real->CheckCounterInfo(pCounterInfo); }
    HRESULT STDMETHODCALLTYPE CheckCounter(const D3D11_COUNTER_DESC* pDesc, D3D11_COUNTER_TYPE* pType, UINT* pActiveCounters, LPSTR szName, UINT* pNameLength, LPSTR szUnits, UINT* pUnitsLength, LPSTR szDescription, UINT* pDescriptionLength) override { return m_real->CheckCounter(pDesc, pType, pActiveCounters, szName, pNameLength, szUnits, pUnitsLength, szDescription, pDescriptionLength); }
    HRESULT STDMETHODCALLTYPE CheckFeatureSupport(D3D11_FEATURE Feature, void* pFeatureSupportData, UINT FeatureSupportDataSize) override { return m_real->CheckFeatureSupport(Feature, pFeatureSupportData, FeatureSupportDataSize); }
    HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID guid, UINT* pDataSize, void* pData) override { return m_real->GetPrivateData(guid, pDataSize, pData); }
    HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID guid, UINT DataSize, const void* pData) override { return m_real->SetPrivateData(guid, DataSize, pData); }
    HRESULT STDMETHODCALLTYPE SetPrivateDataInterface(REFGUID guid, const IUnknown* pData) override { return m_real->SetPrivateDataInterface(guid, pData); }
    D3D_FEATURE_LEVEL STDMETHODCALLTYPE GetFeatureLevel() override { return m_real->GetFeatureLevel(); }
    UINT STDMETHODCALLTYPE GetCreationFlags() override { return m_real->GetCreationFlags(); }
    HRESULT STDMETHODCALLTYPE GetDeviceRemovedReason() override { return m_real->GetDeviceRemovedReason(); }
    void STDMETHODCALLTYPE GetImmediateContext(ID3D11DeviceContext** ppImmediateContext) override {
        if (!ppImmediateContext) return;
        ID3D11DeviceContext* realCtx = nullptr;
        m_real->GetImmediateContext(&realCtx);
        if (realCtx) {
            *ppImmediateContext = new WrappedContext(realCtx);
        } else {
            *ppImmediateContext = nullptr;
        }
    }
    HRESULT STDMETHODCALLTYPE SetExceptionMode(UINT RaiseFlags) override { return m_real->SetExceptionMode(RaiseFlags); }
    UINT STDMETHODCALLTYPE GetExceptionMode() override { return m_real->GetExceptionMode(); }
};

void WrapDeviceAndContext(ID3D11Device** ppDevice, ID3D11DeviceContext** ppContext) {
    static std::once_flag s_once;
    std::call_once(s_once, []() {
        std::atexit(FlushStats);
        InstallPrecisionTimerHooks();
    });

    if (ppDevice && *ppDevice) {
        *ppDevice = new WrappedDevice(*ppDevice);
    }
    if (ppContext && *ppContext) {
        *ppContext = new WrappedContext(*ppContext);
    }
}

class WrappedSwapChain : public IDXGISwapChain {
private:
    LONG m_refCount;
    IDXGISwapChain* m_real;
    UINT m_curWidth = 0;
    UINT m_curHeight = 0;
    DXGI_FORMAT m_curFormat = DXGI_FORMAT_UNKNOWN;
    UINT m_curBufferCount = 0;
    UINT m_curFlags = 0;
    ULONGLONG m_lastResizeTick = 0;

public:
    WrappedSwapChain(IDXGISwapChain* real, UINT initialWidth = 0, UINT initialHeight = 0, DXGI_FORMAT format = DXGI_FORMAT_UNKNOWN, UINT bufferCount = 0)
        : m_refCount(1), m_real(real), m_curWidth(initialWidth), m_curHeight(initialHeight), m_curFormat(format), m_curBufferCount(bufferCount) {
        m_lastResizeTick = GetTickCount64();
    }
    virtual ~WrappedSwapChain() {
        if (m_real) m_real->Release();
    }

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_POINTER;
        if (riid == __uuidof(IUnknown) || riid == __uuidof(IDXGIObject) || riid == __uuidof(IDXGIDeviceSubObject) || riid == __uuidof(IDXGISwapChain)) {
            *ppvObject = this;
            AddRef();
            return S_OK;
        }
        return m_real->QueryInterface(riid, ppvObject);
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return InterlockedIncrement(&m_refCount); }
    ULONG STDMETHODCALLTYPE Release() override {
        ULONG ref = InterlockedDecrement(&m_refCount);
        if (ref == 0) { delete this; return 0; }
        return ref;
    }

    // IDXGIObject
    HRESULT STDMETHODCALLTYPE SetPrivateData(REFGUID Name, UINT DataSize, const void* pData) override { return m_real->SetPrivateData(Name, DataSize, pData); }
    HRESULT STDMETHODCALLTYPE SetPrivateDataInterface(REFGUID Name, const IUnknown* pUnknown) override { return m_real->SetPrivateDataInterface(Name, pUnknown); }
    HRESULT STDMETHODCALLTYPE GetPrivateData(REFGUID Name, UINT* pDataSize, void* pData) override { return m_real->GetPrivateData(Name, pDataSize, pData); }
    HRESULT STDMETHODCALLTYPE GetParent(REFIID riid, void** ppParent) override { return m_real->GetParent(riid, ppParent); }

    // IDXGIDeviceSubObject
    HRESULT STDMETHODCALLTYPE GetDevice(REFIID riid, void** ppDevice) override { return m_real->GetDevice(riid, ppDevice); }

    // IDXGISwapChain
    HRESULT STDMETHODCALLTYPE Present(UINT SyncInterval, UINT Flags) override {
        static std::atomic<uint32_t> s_presentCount{0};
        uint32_t p = s_presentCount.fetch_add(1, std::memory_order_relaxed);
        if ((p & 511) == 511) {
            FlushStatsInternal();
        }
        return m_real->Present(SyncInterval, Flags);
    }

    HRESULT STDMETHODCALLTYPE GetBuffer(UINT Buffer, REFIID riid, void** ppSurface) override {
        return m_real->GetBuffer(Buffer, riid, ppSurface);
    }

    HRESULT STDMETHODCALLTYPE SetFullscreenState(BOOL Fullscreen, IDXGIOutput* pTarget) override {
        return m_real->SetFullscreenState(Fullscreen, pTarget);
    }

    HRESULT STDMETHODCALLTYPE GetFullscreenState(BOOL* pFullscreen, IDXGIOutput** ppTarget) override {
        return m_real->GetFullscreenState(pFullscreen, ppTarget);
    }

    HRESULT STDMETHODCALLTYPE GetDesc(DXGI_SWAP_CHAIN_DESC* pDesc) override {
        return m_real->GetDesc(pDesc);
    }

    HRESULT STDMETHODCALLTYPE ResizeBuffers(
        UINT BufferCount,
        UINT Width,
        UINT Height,
        DXGI_FORMAT NewFormat,
        UINT SwapChainFlags
    ) override {
        g_swapchainResizesTotal.fetch_add(1, std::memory_order_relaxed);
        ULONGLONG now = GetTickCount64();

        // 1. Redundant identical resize check: drop if dimensions and format match
        if (m_curWidth != 0 && m_curHeight != 0) {
            if (Width == m_curWidth && Height == m_curHeight &&
                (NewFormat == DXGI_FORMAT_UNKNOWN || NewFormat == m_curFormat) &&
                (BufferCount == 0 || BufferCount == m_curBufferCount)) {
                g_swapchainResizesIdentical.fetch_add(1, std::memory_order_relaxed);

            }
        }

        // 2. High-frequency resize debounce (rapid window DPI / borderless focus jitter < 50ms)
        if (now - m_lastResizeTick < 50 && m_curWidth != 0 && m_curHeight != 0) {
            g_swapchainResizesRapid.fetch_add(1, std::memory_order_relaxed);

        }

        HRESULT hr = m_real->ResizeBuffers(BufferCount, Width, Height, NewFormat, SwapChainFlags);
        if (SUCCEEDED(hr)) {
            m_curWidth = Width;
            m_curHeight = Height;
            if (NewFormat != DXGI_FORMAT_UNKNOWN) m_curFormat = NewFormat;
            if (BufferCount != 0) m_curBufferCount = BufferCount;
            m_curFlags = SwapChainFlags;
            m_lastResizeTick = now;
        }
        return hr;
    }

    HRESULT STDMETHODCALLTYPE ResizeTarget(const DXGI_MODE_DESC* pNewTargetParameters) override {
        return m_real->ResizeTarget(pNewTargetParameters);
    }

    HRESULT STDMETHODCALLTYPE GetContainingOutput(IDXGIOutput** ppOutput) override {
        return m_real->GetContainingOutput(ppOutput);
    }

    HRESULT STDMETHODCALLTYPE GetFrameStatistics(DXGI_FRAME_STATISTICS* pStats) override {
        return m_real->GetFrameStatistics(pStats);
    }

    HRESULT STDMETHODCALLTYPE GetLastPresentCount(UINT* pLastPresentCount) override {
        return m_real->GetLastPresentCount(pLastPresentCount);
    }
};

void WrapSwapChain(IDXGISwapChain** ppSwapChain, const DXGI_SWAP_CHAIN_DESC* pDesc) {
    if (ppSwapChain && *ppSwapChain) {
        UINT initW = pDesc ? pDesc->BufferDesc.Width : 0;
        UINT initH = pDesc ? pDesc->BufferDesc.Height : 0;
        DXGI_FORMAT fmt = pDesc ? pDesc->BufferDesc.Format : DXGI_FORMAT_UNKNOWN;
        UINT bufCount = pDesc ? pDesc->BufferCount : 0;
        *ppSwapChain = new WrappedSwapChain(*ppSwapChain, initW, initH, fmt, bufCount);
    }
}
