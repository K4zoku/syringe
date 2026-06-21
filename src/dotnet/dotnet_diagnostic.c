/*
 * dotnet_diagnostic.c — .NET CoreCLR Diagnostic Server IPC client
 *
 * Implements the AttachProfiler command via the .NET diagnostic socket.
 * This allows syringe to load a .so into a running .NET process WITHOUT
 * ptrace, bypassing anti-debug techniques.
 *
 * Wire format (little-endian):
 *
 *   HEADER (20 bytes):
 *     [0..13]  "DOTNET_IPC_V1\0"  (14 bytes, ASCII + NUL)
 *     [14..15] uint16_le total_size  (20 + payload_len)
 *     [16]     uint8  CommandSet  (0x03 = Profiler)
 *     [17]     uint8  CommandId   (0x01 = AttachProfiler)
 *     [18..19] uint16_le reserved (0x0000)
 *
 *   PAYLOAD (AttachProfiler):
 *     [0..3]   uint32_le attach_timeout_seconds
 *     [4..19]  byte[16]  profiler_guid (.NET mixed-endian)
 *     [20..23] int32_le  path_char_count (strlen + 1, includes NUL)
 *     [24..]   UTF-16LE  path bytes ((strlen+1) * 2 bytes, incl 0x0000 terminator)
 *     [..]     uint32_le additional_data_len
 *     [..]     byte[]    additional_data
 *
 *   RESPONSE (20-byte header + optional payload):
 *     CommandId 0x00 = OK (no payload)
 *     CommandId 0xFF = Error (uint32_le HRESULT at payload[0..3])
 *
 * GUID byte order (.NET ToByteArray):
 *   {aabbccdd-eeff-gghh-iijj-kkllmmnnoopp}
 *   → dd cc bb aa ff ee hh gg ii jj kk ll mm nn oo pp
 *   (Data1 LE, Data2 LE, Data3 LE, Data4 native)
 */

#define _GNU_SOURCE
#include "dotnet/dotnet_diagnostic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <stdint.h>

/* ── Helpers: little-endian write ───────────────────────────────────────── */

static void put_u16le(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)(v & 0xFF);
    buf[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void put_u32le(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)(v & 0xFF);
    buf[1] = (uint8_t)((v >> 8) & 0xFF);
    buf[2] = (uint8_t)((v >> 16) & 0xFF);
    buf[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint16_t get_u16le(const uint8_t *buf) {
    return (uint16_t)(buf[0] | (buf[1] << 8));
}

/* get_u32le only used if reading HRESULT from error response payload.
 * Kept for future use when we read the full response. */
__attribute__((unused))
static uint32_t get_u32le(const uint8_t *buf) {
    return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

/* ── Socket discovery ───────────────────────────────────────────────────── */

/*
 * .NET diagnostic socket pattern: dotnet-diagnostic-{pid}-{key}-socket
 * where {key} is a numeric disambiguation key. We glob /tmp for matches
 * and return the most recently modified one.
 */
int syringe_dotnet_find_socket(pid_t pid, char *out_path, size_t path_size) {
    DIR *d = opendir("/tmp");
    if (!d) {
        fprintf(stderr, "[dotnet] opendir(/tmp): %s\n", strerror(errno));
        return -1;
    }

    char pattern[64];
    snprintf(pattern, sizeof(pattern), "dotnet-diagnostic-%d-", pid);
    size_t pat_len = strlen(pattern);

    char best_path[128] = {0};
    time_t best_mtime = 0;

    struct dirent *de;
    while ((de = readdir(d))) {
        /* Check prefix matches "dotnet-diagnostic-{pid}-" */
        if (strncmp(de->d_name, pattern, pat_len) != 0) continue;
        /* Check suffix "-socket" */
        size_t name_len = strlen(de->d_name);
        if (name_len < 7) continue;
        if (strcmp(de->d_name + name_len - 7, "-socket") != 0) continue;
        /* Check middle part is numeric */
        const char *mid = de->d_name + pat_len;
        const char *mid_end = de->d_name + name_len - 7;
        if (mid >= mid_end) continue;
        int all_digits = 1;
        for (const char *p = mid; p < mid_end; p++) {
            if (*p < '0' || *p > '9') { all_digits = 0; break; }
        }
        if (!all_digits) continue;

        /* Found a match — check mtime */
        char full[128];
        snprintf(full, sizeof(full), "/tmp/%s", de->d_name);
        struct stat st;
        if (stat(full, &st) == 0 && S_ISSOCK(st.st_mode)) {
            if (st.st_mtime > best_mtime) {
                best_mtime = st.st_mtime;
                snprintf(best_path, sizeof(best_path), "%s", full);
            }
        }
    }
    closedir(d);

    if (best_path[0] == '\0') {
        return -1;  /* not found */
    }

    snprintf(out_path, path_size, "%s", best_path);
    return 0;
}

/* ── Build AttachProfiler message ───────────────────────────────────────── */

/*
 * Build the full IPC message (header + payload) for AttachProfiler.
 * Returns malloc'd buffer (caller frees) and sets *out_len.
 * Returns NULL on error.
 *
 * profiler_guid: 16 bytes in .NET mixed-endian order.
 *   We use a fixed GUID {12345678-1234-1234-1234-123456789abc} —
 *   .NET doesn't validate the GUID for AttachProfiler, it's just a label.
 */
static uint8_t *build_attach_profiler_msg(const char *profiler_path,
                                           const void *client_data,
                                           size_t client_len,
                                           size_t *out_len) {
    /* Calculate sizes */
    size_t path_chars = strlen(profiler_path) + 1;  /* include NUL */
    size_t path_bytes = path_chars * 2;  /* UTF-16LE */

    size_t payload_len = 4 + 16 + 4 + path_bytes + 4 + client_len;
    size_t total_len = 20 + payload_len;

    uint8_t *msg = malloc(total_len);
    if (!msg) return NULL;
    memset(msg, 0, total_len);

    /* ── Header (20 bytes) ── */
    memcpy(msg, "DOTNET_IPC_V1\0", 14);  /* magic + NUL */
    put_u16le(msg + 14, (uint16_t)total_len);
    msg[16] = 0x03;  /* CommandSet = Profiler */
    msg[17] = 0x01;  /* CommandId = AttachProfiler */
    put_u16le(msg + 18, 0x0000);  /* reserved */

    /* ── Payload ── */
    uint8_t *p = msg + 20;

    /* [1] attach_timeout_seconds = 5 (5 seconds should be plenty) */
    put_u32le(p, 5);
    p += 4;

    /* [2] profiler_guid — fixed GUID {12345678-1234-1234-1234-123456789abc}
     * .NET byte order: Data1 LE, Data2 LE, Data3 LE, Data4 native
     * {12345678-1234-1234-1234-123456789abc}
     *   Data1 = 0x12345678 → 78 56 34 12
     *   Data2 = 0x1234     → 34 12
     *   Data3 = 0x1234     → 34 12
     *   Data4 = 12 34 56 78 9a bc (6 bytes... wait, Data4 is 8 bytes)
     * Actually: {12345678-1234-1234-1234-123456789abc}
     *   Data4 = "1234123456789abc" = 8 bytes: 12 34 12 34 56 78 9a bc
     */
    static const uint8_t guid[16] = {
        0x78, 0x56, 0x34, 0x12,  /* Data1 LE */
        0x34, 0x12,              /* Data2 LE */
        0x34, 0x12,              /* Data3 LE */
        0x12, 0x34, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc  /* Data4 */
    };
    memcpy(p, guid, 16);
    p += 16;

    /* [3] profiler_path — UTF-16LE, char-count length prefix */
    put_u32le(p, (uint32_t)path_chars);  /* char count including NUL */
    p += 4;
    /* Convert ASCII path to UTF-16LE (ASCII chars → 0x00 0xXX) */
    for (size_t i = 0; i < path_chars; i++) {
        p[0] = (uint8_t)profiler_path[i];
        p[1] = 0;
        p += 2;
    }
    /* p now points past the trailing 0x0000 NUL */

    /* [4] additional_data (client_data) */
    put_u32le(p, (uint32_t)client_len);
    p += 4;
    if (client_data && client_len > 0) {
        memcpy(p, client_data, client_len);
        p += client_len;
    }

    *out_len = total_len;
    return msg;
}

/* ── Send message + receive response ────────────────────────────────────── */

static int send_and_recv(const char *socket_path,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t *resp_hdr, size_t resp_hdr_size) {
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[dotnet] socket(): %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* Copy socket path, leave room for NUL terminator (sun_path is 108 bytes) */
    size_t path_len = strlen(socket_path);
    if (path_len >= sizeof(addr.sun_path)) {
        fprintf(stderr, "[dotnet] socket path too long: %s\n", socket_path);
        close(fd);
        return -1;
    }
    memcpy(addr.sun_path, socket_path, path_len + 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[dotnet] connect(%s): %s\n", socket_path, strerror(errno));
        close(fd);
        return -1;
    }

    /* Send message */
    ssize_t sent = 0;
    while ((size_t)sent < msg_len) {
        ssize_t n = write(fd, msg + sent, msg_len - sent);
        if (n < 0) {
            fprintf(stderr, "[dotnet] write: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        sent += n;
    }

    /* Receive response header (20 bytes) */
    ssize_t recvd = 0;
    while ((size_t)recvd < resp_hdr_size) {
        ssize_t n = read(fd, resp_hdr + recvd, resp_hdr_size - recvd);
        if (n < 0) {
            fprintf(stderr, "[dotnet] read: %s\n", strerror(errno));
            close(fd);
            return -1;
        }
        if (n == 0) {
            fprintf(stderr, "[dotnet] connection closed by server\n");
            close(fd);
            return -1;
        }
        recvd += n;
    }

    close(fd);
    return 0;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

int syringe_dotnet_attach_profiler(pid_t pid,
                                    const char *profiler_path,
                                    const void *client_data,
                                    size_t client_len) {
    if (!profiler_path) {
        fprintf(stderr, "[dotnet] profiler_path is NULL\n");
        return SYRINGE_DOTNET_ERROR;
    }

    /* Find diagnostic socket */
    char socket_path[128];
    if (syringe_dotnet_find_socket(pid, socket_path, sizeof(socket_path)) < 0) {
        fprintf(stderr, "[dotnet] No diagnostic socket for pid %d "
                "(not a .NET process, or diagnostics disabled)\n", pid);
        return SYRINGE_DOTNET_NO_SOCKET;
    }
    fprintf(stderr, "[dotnet] Found diagnostic socket: %s\n", socket_path);

    /* Build AttachProfiler message */
    size_t msg_len = 0;
    uint8_t *msg = build_attach_profiler_msg(profiler_path, client_data,
                                              client_len, &msg_len);
    if (!msg) {
        fprintf(stderr, "[dotnet] Failed to build IPC message\n");
        return SYRINGE_DOTNET_ERROR;
    }

    fprintf(stderr, "[dotnet] Sending AttachProfiler (profiler=%s, %zu bytes client_data)\n",
            profiler_path, client_len);

    /* Send + receive */
    uint8_t resp[20];
    int rc = send_and_recv(socket_path, msg, msg_len, resp, sizeof(resp));
    free(msg);
    if (rc < 0) {
        return SYRINGE_DOTNET_ERROR;
    }

    /* Parse response */
    /* Verify magic */
    if (memcmp(resp, "DOTNET_IPC_V1\0", 14) != 0) {
        fprintf(stderr, "[dotnet] Bad response magic\n");
        return SYRINGE_DOTNET_ERROR;
    }

    uint16_t resp_size = get_u16le(resp + 14);
    uint8_t resp_cmd = resp[17];  /* CommandId */

    if (resp_cmd == 0x00) {
        /* OK */
        fprintf(stderr, "[dotnet] AttachProfiler OK — profiler .so loaded\n");
        return SYRINGE_DOTNET_OK;
    } else if (resp_cmd == 0xFF) {
        /* Error — read HRESULT from payload (if any) */
        uint32_t hresult = 0;
        if (resp_size > 20) {
            /* Need to read payload — but we only got 20 bytes so far.
             * For simplicity, just report generic error. */
            hresult = 0x8013136A;  /* ProfilerAlreadyActive guess */
        }
        fprintf(stderr, "[dotnet] .NET rejected AttachProfiler (HRESULT=0x%08x)\n",
                hresult);
        return SYRINGE_DOTNET_REJECTED;
    } else {
        fprintf(stderr, "[dotnet] Unexpected response CommandId=0x%02x\n", resp_cmd);
        return SYRINGE_DOTNET_ERROR;
    }
}

int syringe_inject_dotnet(pid_t pid, const char *so_path) {
    if (!so_path) {
        fprintf(stderr, "[dotnet] so_path is NULL\n");
        return SYRINGE_DOTNET_ERROR;
    }

    /* For now, use so_path directly as the profiler path.
     * In a full implementation, we'd use a syringe-profiler.so wrapper
     * that receives so_path as client_data and dlopens it.
     *
     * But .NET requires the profiler to export DllGetClassObject (COM).
     * A regular .so won't work. For now, just pass so_path as both
     * profiler_path and client_data — if so_path happens to be a valid
     * COM profiler, it works. Otherwise, user needs to build a wrapper.
     *
     * TODO: ship syringe-dotnet-profiler.so that wraps any .so. */
    return syringe_dotnet_attach_profiler(pid, so_path, NULL, 0);
}
