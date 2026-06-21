/*
 * syringe_profiler.cpp — .NET profiler wrapper for syringe
 *
 * This .so is loaded by the .NET runtime via AttachProfiler IPC command.
 * It receives the target .so path as client_data in InitializeForAttach(),
 * then dlopen's that .so — effectively injecting it into the .NET process.
 *
 * This bypasses ptrace entirely: no CAP_SYS_PTRACE needed, no anti-debug
 * detection, no EPERM.
 *
 * COM dance:
 *   1. .NET calls DllGetClassObject(CLSID, IID_IClassFactory, &factory)
 *   2. .NET calls factory->CreateInstance(NULL, IID_IUnknown, &profiler)
 *   3. .NET calls profiler->QueryInterface(IID_ICorProfilerCallback3, &cb3)
 *   4. .NET calls cb3->InitializeForAttach(info, clientData, clientDataLen)
 *   5. We dlopen(clientData) — target .so constructor runs
 *   6. Return S_OK — .NET thinks profiler initialized successfully
 *
 * Build: compiled as C++ (COM vtables require C++ class layout)
 */

/* _GNU_SOURCE is defined by meson (-D_GNU_SOURCE), don't redefine */
#include "dotnet/corprof_min.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

/* ── SyringeProfiler — implements ICorProfilerCallback3 ─────────────────── */
/*
 * All methods return S_OK (or E_NOTIMPL for a few) except InitializeForAttach,
 * which dlopens the target .so from client_data.
 */

class SyringeProfiler : public ICorProfilerCallback3 {
private:
    LONG refCount;

public:
    SyringeProfiler() : refCount(1) {}

    /* ── IUnknown ── */
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_NOTIMPL;
        if (riid == &IID_IUnknown ||
            riid == &IID_ICorProfilerCallback ||
            riid == &IID_ICorProfilerCallback2 ||
            riid == &IID_ICorProfilerCallback3) {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override {
        return ++refCount;
    }

    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = --refCount;
        if (r == 0) delete this;
        return r;
    }

    /* ── ICorProfilerCallback ── */
    HRESULT STDMETHODCALLTYPE Initialize(IUnknown* pICorProfilerInfoUnk) override {
        (void)pICorProfilerInfoUnk;
        return S_OK;
    }

    HRESULT STDMETHODCALLTYPE Shutdown() override { return S_OK; }

    /* All other ICorProfilerCallback methods — stubs returning S_OK */
    #define STUB(name, ...) HRESULT STDMETHODCALLTYPE name(__VA_ARGS__) override { return S_OK; }
    STUB(AppDomainCreationStarted, void* a)
    STUB(AppDomainCreationFinished, void* a, HRESULT b)
    STUB(AppDomainShutdownStarted, void* a)
    STUB(AppDomainShutdownFinished, void* a, HRESULT b)
    STUB(AssemblyLoadStarted, void* a)
    STUB(AssemblyLoadFinished, void* a, HRESULT b)
    STUB(AssemblyUnloadStarted, void* a)
    STUB(AssemblyUnloadFinished, void* a, HRESULT b)
    STUB(ModuleLoadStarted, void* a)
    STUB(ModuleLoadFinished, void* a, HRESULT b)
    STUB(ModuleUnloadStarted, void* a)
    STUB(ModuleUnloadFinished, void* a, HRESULT b)
    STUB(ModuleAttachedToAssembly, void* a, void* b)
    STUB(ClassLoadStarted, void* a)
    STUB(ClassLoadFinished, void* a, HRESULT b)
    STUB(ClassUnloadStarted, void* a)
    STUB(ClassUnloadFinished, void* a, HRESULT b)
    STUB(FunctionUnloadStarted, void* a)
    STUB(JITCompilationStarted, void* a, BOOL b)
    STUB(JITCompilationFinished, void* a, HRESULT b, BOOL c)
    STUB(JITCachedFunctionSearchStarted, void* a, BOOL* b)
    STUB(JITCachedFunctionSearchFinished, void* a, uint32_t b)
    STUB(JITFunctionPitched, void* a)
    STUB(JITInlining, void* a, void* b, BOOL* c)
    STUB(ThreadCreated, void* a)
    STUB(ThreadDestroyed, void* a)
    STUB(ThreadAssignedToOSThread, void* a, uint32_t b)
    STUB(RemotingClientInvocationStarted)
    STUB(RemotingClientInvocationFinished)
    STUB(RemotingClientReceivingReply, void* a, BOOL b)
    STUB(RemotingClientSendingMessage, void* a, BOOL b)
    STUB(RemotingServerInvocationStarted)
    STUB(RemotingServerInvocationReturned)
    STUB(RemotingServerReceivingReply, void* a, BOOL b)
    STUB(RemotingServerSendingReply, void* a, BOOL b)
    STUB(UnmanagedToManagedTransition, void* a, uint32_t b)
    STUB(ManagedToUnmanagedTransition, void* a, uint32_t b)
    STUB(RuntimeSuspendStarted, uint32_t a)
    STUB(RuntimeSuspendFinished)
    STUB(RuntimeSuspendAborted)
    STUB(RuntimeResumeStarted)
    STUB(RuntimeResumeFinished)
    STUB(RuntimeThreadSuspended, void* a)
    STUB(RuntimeThreadResumed, void* a)
    STUB(MovedReferences, uint32_t a, void* b[], void* c[])
    STUB(ObjectAllocated, void* a, void* b)
    STUB(ObjectsAllocatedByClass, uint32_t a, uint32_t b[], uint32_t c[])
    STUB(ObjectReferences, void* a, void* b, uint32_t c, void* d[])
    STUB(RootReferences, uint32_t a, void* b[])
    STUB(ExceptionThrown, void* a)
    STUB(ExceptionSearchFunctionEnter, void* a)
    STUB(ExceptionSearchFunctionLeave)
    STUB(ExceptionSearchFilterEnter, void* a)
    STUB(ExceptionSearchFilterLeave)
    STUB(ExceptionSearchCatcherFound, void* a)
    STUB(ExceptionOSHandlerEnter, void* a)
    STUB(ExceptionOSHandlerLeave, void* a)
    STUB(ExceptionUnwindFunctionEnter, void* a)
    STUB(ExceptionUnwindFunctionLeave)
    STUB(ExceptionUnwindFilterEnter, void* a)
    STUB(ExceptionUnwindFilterLeave)
    STUB(ExceptionCatcherEnter, void* a, void* b)
    STUB(ExceptionCatcherLeave)
    STUB(COMClassicVTableCreated, void* a, void* b, void* c, void* d, uint32_t e)
    STUB(COMClassicVTableDestroyed, void* a, void* b, void* c)
    STUB(ExceptionCLRCatcherFound)
    STUB(ExceptionCLRCatcherExecute)

    /* ── ICorProfilerCallback2 ── */
    STUB(ThreadNameChanged, void* a, uint32_t b, wchar_t c[])
    STUB(GarbageCollectionStarted, int a, BOOL b[], uint32_t c)
    STUB(SurvivingReferences, uint32_t a, void* b[], uint32_t c[])
    STUB(FinalizeableObjectQueued, uint32_t a, void* b)
    STUB(RootReferences2, uint32_t a, void* b[], uint32_t c[], void* d[])
    STUB(HandleCreated, void* a, void* b)
    STUB(HandleDestroyed, void* a)

    /* ── ICorProfilerCallback3 ── */
    /* THIS is the key method — called by .NET when AttachProfiler is used.
     * pvClientData contains the target .so path (NUL-terminated string). */
    HRESULT STDMETHODCALLTYPE InitializeForAttach(IUnknown* pCorProfilerInfoUnk,
                                                    void* pvClientData,
                                                    uint32_t cbClientData) override {
        (void)pCorProfilerInfoUnk;

        if (!pvClientData || cbClientData == 0) {
            fprintf(stderr, "[syringe-profiler] InitializeForAttach: no client data\n");
            return S_OK;  /* return OK so .NET doesn't error */
        }

        /* client_data is the target .so path (NUL-terminated string) */
        const char* so_path = (const char*)pvClientData;
        fprintf(stderr, "[syringe-profiler] InitializeForAttach: loading %s\n", so_path);

        void* handle = dlopen(so_path, RTLD_NOW | RTLD_GLOBAL);
        if (!handle) {
            fprintf(stderr, "[syringe-profiler] dlopen(%s) failed: %s\n",
                    so_path, dlerror());
            /* Return S_OK anyway — we don't want .NET to think the profiler
             * failed and potentially crash. The overlay just won't show. */
        } else {
            fprintf(stderr, "[syringe-profiler] %s loaded successfully\n", so_path);
            /* Keep handle open — dlopen'd library persists for process lifetime */
        }

        return S_OK;
    }

    #undef STUB
};

/* ── SyringeClassFactory — implements IClassFactory ─────────────────────── */

class SyringeClassFactory : public IClassFactory {
private:
    LONG refCount;

public:
    SyringeClassFactory() : refCount(1) {}

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_NOTIMPL;
        if (riid == &IID_IUnknown || riid == &IID_IClassFactory) {
            *ppv = this;
            AddRef();
            return S_OK;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    ULONG STDMETHODCALLTYPE AddRef() override { return ++refCount; }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = --refCount;
        if (r == 0) delete this;
        return r;
    }

    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) override {
        if (!ppvObject) return E_NOTIMPL;
        if (pUnkOuter) return E_NOTIMPL;  /* no aggregation */

        SyringeProfiler* profiler = new SyringeProfiler();
        HRESULT hr = profiler->QueryInterface(riid, ppvObject);
        profiler->Release();
        return hr;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override {
        (void)fLock;
        return S_OK;
    }
};

/* ── DllGetClassObject — entry point called by .NET runtime ─────────────── */

extern "C" HRESULT STDMETHODCALLTYPE DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (!ppv) return E_NOTIMPL;

    /* Accept any CLSID — syringe sends a fixed GUID, but be lenient */
    (void)rclsid;

    if (riid == &IID_IUnknown || riid == &IID_IClassFactory) {
        SyringeClassFactory* factory = new SyringeClassFactory();
        *ppv = factory;
        return S_OK;
    }

    *ppv = NULL;
    return E_NOINTERFACE;
}
