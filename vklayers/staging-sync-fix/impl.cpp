#include "sync_fix.h"

// Shadow buffer tracking structures
struct StagingResourceTracker {
    bool isStaging = false;
    bool dirty = false;
    std::vector<uint8_t> shadowBuffer;
    ID3D11Resource* gpuSource = nullptr;
    UINT subresource = 0;
};

struct ConstantBufferTracker {
    UINT byteWidth = 0;
    bool isConstantBuffer = false;
    bool hasData = false;
    std::vector<uint8_t> data;
};

static std::mutex g_resourceLock;
static std::unordered_map<ID3D11Resource*, StagingResourceTracker> g_stagingResources;

static std::mutex g_cbLock;
static std::unordered_map<ID3D11Resource*, ConstantBufferTracker> g_constantBuffers;

class WrappedContext : public ID3D11DeviceContext {
private:
    ULONG m_refCount;
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

    // Intercept CopyResource to decouple redundant intra-frame CPU-GPU sync flushes
    void STDMETHODCALLTYPE CopyResource(ID3D11Resource* pDstResource, ID3D11Resource* pSrcResource) override {
        bool intercept = false;
        {
            std::lock_guard<std::mutex> lock(g_resourceLock);
            auto it = g_stagingResources.find(pDstResource);
            if (it != g_stagingResources.end() && it->second.isStaging) {
                // Gust/Atelier engine pattern: CopyResource(staging, gpu) immediately followed by Map(staging).
                // Recording GPU source and deferring prevents synchronous fence stall on active command queue.
                it->second.gpuSource = pSrcResource;
                it->second.dirty = true;
                intercept = true;
            }
        }

        if (!intercept) {
            m_real->CopyResource(pDstResource, pSrcResource);
        }
    }

    // Intercept Map to provide non-blocking shadow mapping
    HRESULT STDMETHODCALLTYPE Map(
        ID3D11Resource* pResource,
        UINT Subresource,
        D3D11_MAP MapType,
        UINT MapFlags,
        D3D11_MAPPED_SUBRESOURCE* pMappedResource
    ) override {
        {
            std::lock_guard<std::mutex> lock(g_resourceLock);
            auto it = g_stagingResources.find(pResource);
            if (it != g_stagingResources.end() && it->second.isStaging) {
                // If mapping for read-write or write on an intra-frame staging buffer,
                // fulfill via shadow buffer memory without stalling on a GPU fence flush.
                if (!it->second.shadowBuffer.empty() && pMappedResource) {
                    pMappedResource->pData = it->second.shadowBuffer.data();
                    pMappedResource->RowPitch = (UINT)it->second.shadowBuffer.size();
                    pMappedResource->DepthPitch = (UINT)it->second.shadowBuffer.size();
                    return S_OK;
                }
            }
        }

        return m_real->Map(pResource, Subresource, MapType, MapFlags, pMappedResource);
    }

    void STDMETHODCALLTYPE Unmap(ID3D11Resource* pResource, UINT Subresource) override {
        ID3D11Resource* gpuSrc = nullptr;
        bool hasShadow = false;
        void* shadowData = nullptr;
        size_t shadowSize = 0;

        {
            std::lock_guard<std::mutex> lock(g_resourceLock);
            auto it = g_stagingResources.find(pResource);
            if (it != g_stagingResources.end() && it->second.isStaging && it->second.dirty) {
                gpuSrc = it->second.gpuSource;
                hasShadow = !it->second.shadowBuffer.empty();
                if (hasShadow) {
                    shadowData = it->second.shadowBuffer.data();
                    shadowSize = it->second.shadowBuffer.size();
                }
                it->second.dirty = false;
            }
        }

        if (hasShadow && gpuSrc && shadowData) {
            // Asynchronously push modified shadow buffer back to GPU target
            m_real->UpdateSubresource(gpuSrc, Subresource, nullptr, shadowData, (UINT)shadowSize, (UINT)shadowSize);
        } else {
            m_real->Unmap(pResource, Subresource);
        }
    }

    // Delegate remaining standard pipeline methods
    void STDMETHODCALLTYPE SetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override {
        m_real->VSSetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers);
    }
    void STDMETHODCALLTYPE SetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews) override {
        m_real->PSSetShaderResources(StartSlot, NumViews, ppShaderResourceViews);
    }
    void STDMETHODCALLTYPE SetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override {
        m_real->PSSetSamplers(StartSlot, NumSamplers, ppSamplers);
    }
    void STDMETHODCALLTYPE SetShader(ID3D11VertexShader* pVertexShader, ID3D11ClassInstance* const* ppClassInstances, UINT NumClassInstances) override {
        m_real->VSSetShader(pVertexShader, ppClassInstances, NumClassInstances);
    }
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

    // D3D11 Context pass-through wrappers
    void STDMETHODCALLTYPE VSSetConstantBuffers(UINT StartSlot, UINT NumBuffers, ID3D11Buffer* const* ppConstantBuffers) override {
        if (ppConstantBuffers && StartSlot + NumBuffers <= D3D11_COMMONSHADER_CONSTANT_BUFFER_API_SLOT_COUNT) {
            bool allMatch = true;
            for (UINT i = 0; i < NumBuffers; ++i) {
                if (m_curVSConstantBuffers[StartSlot + i] != ppConstantBuffers[i]) {
                    allMatch = false;
                    break;
                }
            }
            if (allMatch) return;
            for (UINT i = 0; i < NumBuffers; ++i) {
                m_curVSConstantBuffers[StartSlot + i] = ppConstantBuffers[i];
            }
        }
        m_real->VSSetConstantBuffers(StartSlot, NumBuffers, ppConstantBuffers);
    }
    void STDMETHODCALLTYPE PSSetShaderResources(UINT StartSlot, UINT NumViews, ID3D11ShaderResourceView* const* ppShaderResourceViews) override { m_real->PSSetShaderResources(StartSlot, NumViews, ppShaderResourceViews); }
    void STDMETHODCALLTYPE PSSetShader(ID3D11PixelShader* pPixelShader, ID3D11ClassInstance* const* ppClassInstances, UINT NumClassInstances) override { m_real->PSSetShader(pPixelShader, ppClassInstances, NumClassInstances); }
    void STDMETHODCALLTYPE PSSetSamplers(UINT StartSlot, UINT NumSamplers, ID3D11SamplerState* const* ppSamplers) override { m_real->PSSetSamplers(StartSlot, NumSamplers, ppSamplers); }
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
        if (pInputLayout == m_curInputLayout) return;
        m_curInputLayout = pInputLayout;
        m_real->IASetInputLayout(pInputLayout);
    }
    void STDMETHODCALLTYPE IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY Topology) override {
        if (Topology == m_curTopology) return;
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
            std::lock_guard<std::mutex> lock(g_cbLock);
            auto it = g_constantBuffers.find(pDstResource);
            if (it != g_constantBuffers.end() && it->second.isConstantBuffer) {
                if (it->second.hasData && it->second.data.size() == it->second.byteWidth) {
                    if (memcmp(it->second.data.data(), pSrcData, it->second.byteWidth) == 0) {
                        // Redundant constant buffer update: drop to prevent Vulkan descriptor / command buffer churn
                        return;
                    }
                }
                it->second.data.assign((const uint8_t*)pSrcData, (const uint8_t*)pSrcData + it->second.byteWidth);
                it->second.hasData = true;
            }
        }
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
    ULONG m_refCount;
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
        if (SUCCEEDED(hr) && ppBuffer && *ppBuffer && pDesc) {
            if (pDesc->Usage == D3D11_USAGE_STAGING && (pDesc->CPUAccessFlags & D3D11_CPU_ACCESS_READ)) {
                std::lock_guard<std::mutex> lock(g_resourceLock);
                auto& tracker = g_stagingResources[*ppBuffer];
                tracker.isStaging = true;
                tracker.shadowBuffer.resize(pDesc->ByteWidth, 0);
                if (pInitialData && pInitialData->pSysMem) {
                    memcpy(tracker.shadowBuffer.data(), pInitialData->pSysMem, pDesc->ByteWidth);
                }
            }
            if (pDesc->BindFlags & D3D11_BIND_CONSTANT_BUFFER) {
                std::lock_guard<std::mutex> lock(g_cbLock);
                auto& cb = g_constantBuffers[*ppBuffer];
                cb.byteWidth = pDesc->ByteWidth;
                cb.isConstantBuffer = true;
                if (pInitialData && pInitialData->pSysMem && pDesc->ByteWidth > 0) {
                    cb.data.assign((const uint8_t*)pInitialData->pSysMem, (const uint8_t*)pInitialData->pSysMem + pDesc->ByteWidth);
                    cb.hasData = true;
                }
            }
        }
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
    if (ppDevice && *ppDevice) {
        *ppDevice = new WrappedDevice(*ppDevice);
    }
    if (ppContext && *ppContext) {
        *ppContext = new WrappedContext(*ppContext);
    }
}

class WrappedSwapChain : public IDXGISwapChain {
private:
    ULONG m_refCount;
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
        ULONGLONG now = GetTickCount64();

        // 1. Redundant identical resize check: drop if dimensions and format match
        if (m_curWidth != 0 && m_curHeight != 0) {
            if (Width == m_curWidth && Height == m_curHeight &&
                (NewFormat == DXGI_FORMAT_UNKNOWN || NewFormat == m_curFormat) &&
                (BufferCount == 0 || BufferCount == m_curBufferCount)) {
                return S_OK;
            }
        }

        // 2. High-frequency resize debounce (rapid window DPI / borderless focus jitter < 50ms)
        if (now - m_lastResizeTick < 50 && m_curWidth != 0 && m_curHeight != 0) {
            return S_OK;
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
