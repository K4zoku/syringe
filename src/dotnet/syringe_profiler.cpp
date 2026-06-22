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
#include "dotnet/corprof_min.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/file.h>
#include <stdarg.h>

/* ── Logger (matches syringe_hook convention: SYRINGE_HOOK_DEBUG env) ────── */

static void profiler_log_real(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fflush(stderr);
}

static void profiler_log_nop(const char *fmt, ...) { (void)fmt; }

static void (*profiler_log_fn)(const char *fmt, ...) = profiler_log_nop;
static int profiler_log_ready = 0;

static void profiler_log_init(void) {
    profiler_log_ready = 1;
    const char *e = getenv("SYRINGE_HOOK_DEBUG");
    if (e && e[0])
        profiler_log_fn = profiler_log_real;
}

#define PROFILER_LOG(fmt, ...) do {                                  \
    if (!profiler_log_ready) profiler_log_init();                     \
    profiler_log_fn("[syringe_profiler] " fmt "\n", ##__VA_ARGS__);    \
} while (0)

/* ── Claim our path from /tmp/syringe_inject ────────────────────────────────
 * Reads entries ("<pid> <path>\n"), consumes the one matching our pid,
 * writes back the rest so other processes can claim theirs. */
static int syringe_profiler_claim_path(char *path, size_t path_sz) {
    pid_t my_pid = getpid();
    char pid_str[16];
    int pid_len = snprintf(pid_str, sizeof(pid_str), "%d", (int)my_pid);

    int fd = open("/tmp/syringe_inject", O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;
    flock(fd, LOCK_EX);

    char buf[65536];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) { flock(fd, LOCK_UN); close(fd); return -1; }
    buf[n] = '\0';

    char remaining[65536];
    size_t rem = 0;
    int found = 0;

    char *p = buf;
    while (p < buf + n) {
        char *nl = strchr(p, '\n');
        if (!nl) break;
        size_t entry_len = nl - p + 1;

        if (!found && (int)entry_len > pid_len + 1 && p[pid_len] == ' ' &&
            strncmp(p, pid_str, pid_len) == 0) {
            size_t path_len = entry_len - pid_len - 2;
            if (path_len > 0 && path_len < path_sz) {
                memcpy(path, p + pid_len + 1, path_len);
                path[path_len] = '\0';
                found = 1;
            }
        } else if (rem + entry_len <= sizeof(remaining)) {
            memcpy(remaining + rem, p, entry_len);
            rem += entry_len;
        }
        p = nl + 1;
    }

    if (rem > 0) {
        ftruncate(fd, 0);
        lseek(fd, 0, SEEK_SET);
        write(fd, remaining, rem);
    }
    flock(fd, LOCK_UN);
    close(fd);
    return found ? 0 : -1;
}

/* ── Constructor — loads overlay before DllGetClassObject ────────────────── */
__attribute__((constructor)) static void syringe_profiler_init() {
    char path[4096];
    if (syringe_profiler_claim_path(path, sizeof(path)) < 0) return;

    PROFILER_LOG("dlopen(%s)", path);
    void* h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (h)
        PROFILER_LOG("library loaded OK");
    else
        PROFILER_LOG("dlopen failed: %s", dlerror());
}

/* ── SyringeProfiler — implements ICorProfilerCallback3 ─────────────────── */
/*
 * All methods return S_OK stubs. CreateInstance returns
 * CLASS_E_CLASSNOTAVAILABLE to abort the attach cleanly —
 * the overlay was already loaded by our constructor.
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

class SyringeProfiler : public ICorProfilerCallback3 {
private:
    LONG refCount;

public:
    SyringeProfiler() : refCount(1) {}
    virtual ~SyringeProfiler() {}

    /* ── IUnknown ── */
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (!ppv) return E_NOTIMPL;
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
        PROFILER_LOG("InitializeForAttach: no-op (S_OK)");
        return S_OK;
    }

    #undef STUB
};

#pragma GCC diagnostic pop

/* ── SyringeClassFactory — implements IClassFactory ─────────────────────── */

class SyringeClassFactory : public IClassFactory {
private:
    LONG refCount;

public:
    SyringeClassFactory() : refCount(1) {}
    virtual ~SyringeClassFactory() {}

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
    if (!ppv) return E_NOTIMPL;
    /* Accept any CLSID — syringe sends a fixed GUID, but be lenient */
    (void)rclsid;
    SyringeClassFactory* factory = new SyringeClassFactory();
    HRESULT hr = factory->QueryInterface(riid, ppv);
    factory->Release();
    return hr;
}
