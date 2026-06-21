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
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <fcntl.h>

/* ── Constructor — loads overlay before DllGetClassObject ────────────────── */
/* The constructor runs when .NET dlopen's our .so. It reads the overlay path
 * from /tmp/woverlay_path (written by syringe-cli), dlopen's the overlay,
 * then CreateInstance returns CLASS_E_CLASSNOTAVAILABLE so the CLR aborts the
 * profiler attach cleanly. The overlay stays loaded in process memory. */
__attribute__((constructor)) static void syringe_profiler_init() {
    int fd = open("/tmp/woverlay_path", O_RDONLY);
    if (fd < 0) return; /* no path file — LD_PRELOAD or other injection path */
    char path[4096];
    ssize_t n = read(fd, path, sizeof(path) - 1);
    close(fd);
    unlink("/tmp/woverlay_path");
    if (n <= 0) return;
    while (n > 0 && (path[n - 1] == '\n' || path[n - 1] == ' ')) n--;
    path[n] = '\0';
    fprintf(stderr, "[syringe-profiler] constructor: dlopen(%s)\n", path);
    void* h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (h)
        fprintf(stderr, "[syringe-profiler] overlay loaded OK\n");
    else
        fprintf(stderr, "[syringe-profiler] dlopen failed: %s\n", dlerror());
}

/* ── SyringeProfiler — implements ICorProfilerCallback3 ─────────────────── */
/*
 * All methods return S_OK stubs. CreateInstance returns
 * CLASS_E_CLASSNOTAVAILABLE to abort the attach cleanly —
 * the overlay was already loaded by our constructor.
 */

class SyringeProfiler : public ICorProfilerCallback3 {
private:
    LONG refCount;

public:
    SyringeProfiler() : refCount(1) {}

    /* ── IUnknown ── */
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        FILE* f = fopen("/tmp/syringe_profiler.log", "a");
        if (f) {
            fprintf(f, "[profiler] QueryInterface called: %08x-%04x-%04x\n",
                        riid->Data1, riid->Data2, riid->Data3);
            fclose(f);
        }
        if (!ppv) return E_NOTIMPL;
        /* Compare GUID contents, NOT pointers — .NET passes its own copy */
        if (memcmp(riid, &IID_IUnknown, sizeof(GUID)) == 0) {
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
     * pvClientData contains the target .so path (NUL-terminated string).
     *
     * We do NOT call dlopen() directly here — the CLR's managed-to-native
     * transition thread has a different stack/TLS context that can trigger
     * "stack smashing detected" from glibc's stack protection inside the
     * dynamic linker or Mesa's constructor code (nested dlopen).
     *
     * Instead, we copy the path and spawn a detached thread to do the
     * dlopen. The thread runs on a normal pthread with proper TLS setup. */
    STUB(ProfilerAttachComplete)   /* called by CLR after InitializeForAttach */

    HRESULT STDMETHODCALLTYPE InitializeForAttach(IUnknown* pCorProfilerInfoUnk,
                                                    void* pvClientData,
                                                    uint32_t cbClientData) override {
        (void)pCorProfilerInfoUnk;
        (void)pvClientData;
        (void)cbClientData;
        fprintf(stderr, "[syringe-profiler] InitializeForAttach: no-op (S_OK)\n");
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
        if (memcmp(riid, &IID_IUnknown, sizeof(GUID)) == 0 ||
            memcmp(riid, &IID_IClassFactory, sizeof(GUID)) == 0) {
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
        /* Return CLASS_E_CLASSNOTAVAILABLE so the CLR aborts the profiler
         * attach cleanly WITHOUT entering the crashy CommitProfilerAttach path.
         * The overlay was already loaded by our constructor. */
        (void)riid;
        *ppvObject = NULL;
        return CLASS_E_CLASSNOTAVAILABLE;
    }

    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override {
        (void)fLock;
        return S_OK;
    }
};

/* ── DllGetClassObject — entry point called by .NET runtime ─────────────── */

extern "C" HRESULT STDMETHODCALLTYPE DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    {
        FILE* f = fopen("/tmp/syringe_profiler.log", "a");
        if (f) {
            fprintf(f, "DllGetClassObject called: clsid=%08x riid=%08x\n",
                    rclsid->Data1, riid->Data1);
            fclose(f);
        }
    }
    if (!ppv) return E_NOTIMPL;
    /* Accept any CLSID — syringe sends a fixed GUID, but be lenient */
    (void)rclsid;
    SyringeClassFactory* factory = new SyringeClassFactory();
    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}
