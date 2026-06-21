/*
 * dotnet_diagnostic.h — .NET CoreCLR Diagnostic Server IPC client
 *
 * Implements the AttachProfiler command via the .NET diagnostic socket,
 * allowing syringe to load a .so into a running .NET process WITHOUT
 * ptrace. This bypasses anti-debug techniques (prctl PR_SET_DUMPABLE,
 * seccomp) that block ptrace-based injection.
 *
 * Protocol: .NET CoreCLR Diagnostic IPC v1
 *   - Socket: /tmp/dotnet-diagnostic-{pid}-{key}-socket (AF_UNIX)
 *   - Binary format: 20-byte header + payload, little-endian
 *   - AttachProfiler: loads a profiler .so via dlopen in the target
 *
 * References:
 *   - dotnet/diagnostics repo (IpcHeader.cs, IpcCommands.cs, DiagnosticsClient.cs)
 *   - https://learn.microsoft.com/en-us/dotnet/core/diagnostics/
 *
 * Usage:
 *   int rc = syringe_dotnet_attach_profiler(pid, profiler_path, client_data);
 *   if (rc == 0) { // profiler loaded, constructor runs in target }
 */

#ifndef SYRINGE_DOTNET_DIAGNOSTIC_H
#define SYRINGE_DOTNET_DIAGNOSTIC_H

#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Return codes ────────────────────────────────────────────────────────
 *
 * 0  = success — profiler .so loaded by .NET runtime
 * -1 = generic error (socket not found, connect failed, malformed response)
 * -2 = .NET runtime rejected the command (e.g., profiler already active,
 *      invalid argument) — check stderr for HRESULT
 * -3 = diagnostic socket not found — target may not be .NET, or diagnostics
 *      disabled (DOTNET_EnableDiagnostics=0)
 */
#define SYRINGE_DOTNET_OK              0
#define SYRINGE_DOTNET_ERROR          -1
#define SYRINGE_DOTNET_REJECTED       -2
#define SYRINGE_DOTNET_NO_SOCKET      -3

/**
 * Find the .NET diagnostic socket for a given PID.
 *
 * .NET creates /tmp/dotnet-diagnostic-{pid}-{key}-socket where {key} is
 * a numeric disambiguation key. We glob /tmp for the pattern and return
 * the most recently modified match.
 *
 * @param pid       Target process ID
 * @param out_path  Buffer to receive socket path (must be >= 128 bytes)
 * @param path_size Size of out_path buffer
 * @return          0 on success, -1 if not found
 */
int syringe_dotnet_find_socket(pid_t pid, char *out_path, size_t path_size);

/**
 * Attach a profiler .so to a running .NET process via the diagnostic socket.
 *
 * Sends the AttachProfiler IPC command, which causes the .NET runtime to
 * dlopen() the profiler .so and call its Initialize() method. The profiler
 * receives client_data as an opaque pointer — typically a path to the
 * actual library to load.
 *
 * This bypasses ptrace entirely — no CAP_SYS_PTRACE needed, no anti-debug
 * detection. Works on .NET Core 3.0+ and .NET 5+.
 *
 * @param pid           Target .NET process ID
 * @param profiler_path Path to the profiler .so (must export DllGetClassObject)
 * @param client_data   Opaque data passed to profiler Initialize() (may be NULL)
 * @param client_len    Length of client_data (0 if NULL)
 * @return              SYRINGE_DOTNET_OK on success, negative on failure
 */
int syringe_dotnet_attach_profiler(pid_t pid,
                                    const char *profiler_path,
                                    const void *client_data,
                                    size_t client_len);

/**
 * Convenience wrapper: attach profiler with client_data = target .so path.
 *
 * The profiler .so's Initialize() will dlopen(client_data) — i.e., it loads
 * the target library into the .NET process. This mimics syringe_inject()
 * but via .NET diagnostic IPC instead of ptrace.
 *
 * @param pid        Target .NET process ID
 * @param so_path    Path to the library to inject (passed as client_data)
 * @return           SYRINGE_DOTNET_OK on success, negative on failure
 */
int syringe_inject_dotnet(pid_t pid, const char *so_path);

#ifdef __cplusplus
}
#endif

#endif /* SYRINGE_DOTNET_DIAGNOSTIC_H */
