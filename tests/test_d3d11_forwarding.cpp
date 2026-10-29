#include "../vklayers/staging-sync-fix/impl.cpp"
#include <cassert>

// These objects exercise the real wrapper without requiring a GPU or game.
class FakeContext : public WrappedContext {
public:
    int value = 42;
    int copies = 0;
    int maps = 0;
    int unmaps = 0;
    int updates = 0;
    HRESULT mapResult = S_OK;
    FakeContext() : WrappedContext(nullptr) {}
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    void STDMETHODCALLTYPE CopyResource(ID3D11Resource*, ID3D11Resource*) override { ++copies; }
    HRESULT STDMETHODCALLTYPE Map(ID3D11Resource*, UINT, D3D11_MAP, UINT,
        D3D11_MAPPED_SUBRESOURCE* mapped) override {
        ++maps;
        if (SUCCEEDED(mapResult)) mapped->pData = &value;
        return mapResult;
    }
    void STDMETHODCALLTYPE Unmap(ID3D11Resource*, UINT) override { ++unmaps; }
    void STDMETHODCALLTYPE UpdateSubresource(ID3D11Resource*, UINT, const D3D11_BOX*,
        const void*, UINT, UINT) override { ++updates; }
};

class FakeSwapChain : public WrappedSwapChain {
public:
    int resizes = 0;
    FakeSwapChain() : WrappedSwapChain(nullptr) {}
    ULONG STDMETHODCALLTYPE Release() override { return 1; }
    HRESULT STDMETHODCALLTYPE ResizeBuffers(UINT, UINT, UINT, DXGI_FORMAT, UINT) override {
        ++resizes;
        return DXGI_ERROR_INVALID_CALL;
    }
};

int main() {
    FakeContext real;
    WrappedContext wrapper(&real);
    D3D11_MAPPED_SUBRESOURCE mapped{};
    wrapper.CopyResource(nullptr, nullptr);
    assert(real.copies == 1);
    assert(wrapper.Map(nullptr, 0, D3D11_MAP_READ, 0, &mapped) == S_OK);
    assert(mapped.pData == &real.value);
    wrapper.Unmap(nullptr, 0);
    assert(real.maps == 1 && real.unmaps == 1 && real.updates == 0);
    real.mapResult = DXGI_ERROR_WAS_STILL_DRAWING;
    assert(wrapper.Map(nullptr, 0, D3D11_MAP_READ, D3D11_MAP_FLAG_DO_NOT_WAIT, &mapped)
        == DXGI_ERROR_WAS_STILL_DRAWING);

    FakeSwapChain swap;
    WrappedSwapChain chain(&swap, 1920, 1080, DXGI_FORMAT_R8G8B8A8_UNORM, 2);
    assert(chain.ResizeBuffers(2, 1920, 1080, DXGI_FORMAT_R8G8B8A8_UNORM, 0)
        == DXGI_ERROR_INVALID_CALL);
    assert(swap.resizes == 1);
    return 0;
}
