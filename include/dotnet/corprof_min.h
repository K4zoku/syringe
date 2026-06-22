/*
 * corprof_min.h — Minimal .NET profiler COM interface definitions
 *
 * Vendored from corprof.h (dotnet/runtime). Only includes the interface
 * definitions needed for libsyringe-dotnet-profiler.so — no .NET SDK required.
 *
 * ICorProfilerCallback3 vtable layout (77 methods total):
 *   IUnknown (3):                    QueryInterface, AddRef, Release
 *   ICorProfilerCallback (66):       Initialize, Shutdown, ... (64 more)
 *   ICorProfilerCallback2 (7):       ThreadNameChanged, GarbageCollectionStarted, ...
 *   ICorProfilerCallback3 (1):       InitializeForAttach
 *
 * The .NET runtime calls DllGetClassObject → IClassFactory::CreateInstance →
 * QueryInterface(IID_ICorProfilerCallback3) → InitializeForAttach(info, clientData, len).
 */

#ifndef SYRINGE_CORPROF_MIN_H
#define SYRINGE_CORPROF_MIN_H

#include <stdint.h>

/* ── COM compatibility macros ───────────────────────────────────────────── */
/* These are normally defined in objbase.h / unknwn.h on Windows. */

#define interface class
#define STDMETHODCALLTYPE  /* empty on Linux — stdcall is x86 Windows only */
#define BOOL int32_t

#ifdef __cplusplus
extern "C" {
#endif

/* ── COM types ──────────────────────────────────────────────────────────── */

typedef int32_t  HRESULT;
typedef uint32_t ULONG;
typedef int32_t  LONG;
typedef int64_t  LONG_PTR;
typedef uint64_t ULONG_PTR;
typedef void*    LPVOID;

#define S_OK        ((HRESULT)0)
#define S_FALSE     ((HRESULT)1)
#define E_NOTIMPL   ((HRESULT)0x80004001)
#define E_NOINTERFACE ((HRESULT)0x80004002)
#define CLASS_E_CLASSNOTAVAILABLE ((HRESULT)0x80040154)

typedef struct {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
} GUID;

typedef GUID IID;
typedef GUID CLSID;
typedef const IID* REFIID;
typedef const CLSID* REFCLSID;

/* IID definitions */
static const IID IID_IUnknown = {
    0x00000000, 0x0000, 0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};
static const IID IID_IClassFactory = {
    0x00000001, 0x0000, 0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}
};
static const IID IID_ICorProfilerCallback = {
    0x176FBED1, 0xA55C, 0x4796,
    {0x98, 0xCA, 0xA9, 0xDA, 0x0E, 0xF8, 0x83, 0xE7}
};
static const IID IID_ICorProfilerCallback2 = {
    0x8A8CC829, 0xCCF2, 0x49FE,
    {0xBB, 0xAE, 0x0F, 0x02, 0x22, 0x28, 0x07, 0x1A}
};
static const IID IID_ICorProfilerCallback3 = {
    0x4FD2ED52, 0x7731, 0x4B8D,
    {0x94, 0x69, 0x03, 0xD2, 0xCC, 0x30, 0x86, 0xC5}
};

/* CLSID for our profiler — must match what syringe sends in AttachProfiler */
static const CLSID CLSID_SyringeProfiler = {
    0x12345678, 0x1234, 0x1234,
    {0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
};

#ifdef __cplusplus
}

/* ── C++ COM interface definitions ──────────────────────────────────────── */
/* The vtable layout is determined by the order of virtual methods. */

interface IUnknown {
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) = 0;
    virtual ULONG   STDMETHODCALLTYPE AddRef() = 0;
    virtual ULONG   STDMETHODCALLTYPE Release() = 0;
};

interface IClassFactory : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppvObject) = 0;
    virtual HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) = 0;
};

/* ICorProfilerCallback — 66 methods after IUnknown */
interface ICorProfilerCallback : public IUnknown {
    virtual HRESULT STDMETHODCALLTYPE Initialize(IUnknown* pICorProfilerInfoUnk) = 0;
    virtual HRESULT STDMETHODCALLTYPE Shutdown() = 0;
    virtual HRESULT STDMETHODCALLTYPE AppDomainCreationStarted(void* appDomainId) = 0;
    virtual HRESULT STDMETHODCALLTYPE AppDomainCreationFinished(void* appDomainId, HRESULT hrStatus) = 0;
    virtual HRESULT STDMETHODCALLTYPE AppDomainShutdownStarted(void* appDomainId) = 0;
    virtual HRESULT STDMETHODCALLTYPE AppDomainShutdownFinished(void* appDomainId, HRESULT hrStatus) = 0;
    virtual HRESULT STDMETHODCALLTYPE AssemblyLoadStarted(void* assemblyId) = 0;
    virtual HRESULT STDMETHODCALLTYPE AssemblyLoadFinished(void* assemblyId, HRESULT hrStatus) = 0;
    virtual HRESULT STDMETHODCALLTYPE AssemblyUnloadStarted(void* assemblyId) = 0;
    virtual HRESULT STDMETHODCALLTYPE AssemblyUnloadFinished(void* assemblyId, HRESULT hrStatus) = 0;
    virtual HRESULT STDMETHODCALLTYPE ModuleLoadStarted(void* moduleId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ModuleLoadFinished(void* moduleId, HRESULT hrStatus) = 0;
    virtual HRESULT STDMETHODCALLTYPE ModuleUnloadStarted(void* moduleId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ModuleUnloadFinished(void* moduleId, HRESULT hrStatus) = 0;
    virtual HRESULT STDMETHODCALLTYPE ModuleAttachedToAssembly(void* moduleId, void* assemblyId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ClassLoadStarted(void* classId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ClassLoadFinished(void* classId, HRESULT hrStatus) = 0;
    virtual HRESULT STDMETHODCALLTYPE ClassUnloadStarted(void* classId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ClassUnloadFinished(void* classId, HRESULT hrStatus) = 0;
    virtual HRESULT STDMETHODCALLTYPE FunctionUnloadStarted(void* functionId) = 0;
    virtual HRESULT STDMETHODCALLTYPE JITCompilationStarted(void* functionId, BOOL fIsSafeToBlock) = 0;
    virtual HRESULT STDMETHODCALLTYPE JITCompilationFinished(void* functionId, HRESULT hrStatus, BOOL fIsSafeToBlock) = 0;
    virtual HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchStarted(void* functionId, BOOL* pbUseCachedFunction) = 0;
    virtual HRESULT STDMETHODCALLTYPE JITCachedFunctionSearchFinished(void* functionId, uint32_t result) = 0;
    virtual HRESULT STDMETHODCALLTYPE JITFunctionPitched(void* functionId) = 0;
    virtual HRESULT STDMETHODCALLTYPE JITInlining(void* callerId, void* calleeId, BOOL* pfShouldInline) = 0;
    virtual HRESULT STDMETHODCALLTYPE ThreadCreated(void* threadId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ThreadDestroyed(void* threadId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ThreadAssignedToOSThread(void* managedThreadId, uint32_t osThreadId) = 0;
    virtual HRESULT STDMETHODCALLTYPE RemotingClientInvocationStarted() = 0;
    virtual HRESULT STDMETHODCALLTYPE RemotingClientInvocationFinished() = 0;
    virtual HRESULT STDMETHODCALLTYPE RemotingClientReceivingReply(void* pCookie, BOOL fIsAsync) = 0;
    virtual HRESULT STDMETHODCALLTYPE RemotingClientSendingMessage(void* pCookie, BOOL fIsAsync) = 0;
    virtual HRESULT STDMETHODCALLTYPE RemotingServerInvocationStarted() = 0;
    virtual HRESULT STDMETHODCALLTYPE RemotingServerInvocationReturned() = 0;
    virtual HRESULT STDMETHODCALLTYPE RemotingServerReceivingReply(void* pCookie, BOOL fIsAsync) = 0;
    virtual HRESULT STDMETHODCALLTYPE RemotingServerSendingReply(void* pCookie, BOOL fIsAsync) = 0;
    virtual HRESULT STDMETHODCALLTYPE UnmanagedToManagedTransition(void* functionId, uint32_t reason) = 0;
    virtual HRESULT STDMETHODCALLTYPE ManagedToUnmanagedTransition(void* functionId, uint32_t reason) = 0;
    virtual HRESULT STDMETHODCALLTYPE RuntimeSuspendStarted(uint32_t suspendReason) = 0;
    virtual HRESULT STDMETHODCALLTYPE RuntimeSuspendFinished() = 0;
    virtual HRESULT STDMETHODCALLTYPE RuntimeSuspendAborted() = 0;
    virtual HRESULT STDMETHODCALLTYPE RuntimeResumeStarted() = 0;
    virtual HRESULT STDMETHODCALLTYPE RuntimeResumeFinished() = 0;
    virtual HRESULT STDMETHODCALLTYPE RuntimeThreadSuspended(void* threadId) = 0;
    virtual HRESULT STDMETHODCALLTYPE RuntimeThreadResumed(void* threadId) = 0;
    virtual HRESULT STDMETHODCALLTYPE MovedReferences(uint32_t cMovedObjectID, void* oldObjectID[], void* newObjectID[]) = 0;
    virtual HRESULT STDMETHODCALLTYPE ObjectAllocated(void* objectID, void* classId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ObjectsAllocatedByClass(uint32_t cClassCount, uint32_t classIDs[], uint32_t cObjects[]) = 0;
    virtual HRESULT STDMETHODCALLTYPE ObjectReferences(void* objectId, void* classId, uint32_t cObjectRefs, void* objectRefIds[]) = 0;
    virtual HRESULT STDMETHODCALLTYPE RootReferences(uint32_t cRootRefs, void* rootRefIds[]) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionThrown(void* objectId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionEnter(void* functionId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchFunctionLeave() = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchFilterEnter(void* filterId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchFilterLeave() = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionSearchCatcherFound(void* functionId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionOSHandlerEnter(void* __unused) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionOSHandlerLeave(void* __unused) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionEnter(void* functionId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionUnwindFunctionLeave() = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionUnwindFilterEnter(void* filterId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionUnwindFilterLeave() = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionCatcherEnter(void* functionId, void* objectId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionCatcherLeave() = 0;
    virtual HRESULT STDMETHODCALLTYPE COMClassicVTableCreated(void* managedId, void* classId, void* interfaceId, void* vTable, uint32_t cSlot) = 0;
    virtual HRESULT STDMETHODCALLTYPE COMClassicVTableDestroyed(void* managedId, void* classId, void* interfaceId) = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherFound() = 0;
    virtual HRESULT STDMETHODCALLTYPE ExceptionCLRCatcherExecute() = 0;
};

/* ICorProfilerCallback2 — 7 methods after ICorProfilerCallback */
interface ICorProfilerCallback2 : public ICorProfilerCallback {
    virtual HRESULT STDMETHODCALLTYPE ThreadNameChanged(void* threadId, uint32_t cchName, wchar_t name[]) = 0;
    virtual HRESULT STDMETHODCALLTYPE GarbageCollectionStarted(int cGenerations, BOOL generationCollected[], uint32_t reason) = 0;
    virtual HRESULT STDMETHODCALLTYPE SurvivingReferences(uint32_t cSurvivingObjectID, void* objectIDRangeStart[], uint32_t cObjectIDRangeLength[]) = 0;
    virtual HRESULT STDMETHODCALLTYPE FinalizeableObjectQueued(uint32_t finalizerFlags, void* objectID) = 0;
    virtual HRESULT STDMETHODCALLTYPE RootReferences2(uint32_t cRootRefs, void* rootRefIds[], uint32_t rootKinds[], void* rootIds[]) = 0;
    virtual HRESULT STDMETHODCALLTYPE HandleCreated(void* handleId, void* initialObjectId) = 0;
    virtual HRESULT STDMETHODCALLTYPE HandleDestroyed(void* handleId) = 0;
};

/* ICorProfilerCallback3 — 2 methods after ICorProfilerCallback2 */
interface ICorProfilerCallback3 : public ICorProfilerCallback2 {
    virtual HRESULT STDMETHODCALLTYPE InitializeForAttach(IUnknown* pCorProfilerInfoUnk, void* pvClientData, uint32_t cbClientData) = 0;
    virtual HRESULT STDMETHODCALLTYPE ProfilerAttachComplete() = 0;
};

#endif /* __cplusplus */

#endif /* SYRINGE_CORPROF_MIN_H */
