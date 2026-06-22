/*
 * syringe_hook_dotnet.h — .NET CoreCLR Diagnostic Server IPC client (header-only)
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
 * Usage:
 *   int rc = syringe_dotnet_attach_profiler(pid, profiler_path, client_data);
 *   if (rc == 0) { // profiler loaded, constructor runs in target }
 *
 * This is a header-only library — just #include it from one .c file.
 * Set SYRINGE_HOOK_DEBUG=1 for diagnostic output.
 */
#ifndef SYRINGE_HOOK_DOTNET_H
#define SYRINGE_HOOK_DOTNET_H

#ifndef _GNU_SOURCE
#warning "syringe_hook_dotnet: _GNU_SOURCE not defined — define it before including this header"
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

/* ── Return codes ──────────────────────────────────────────────────────────
 *
 * 0  = success — profiler .so loaded by .NET runtime
 * -1 = generic error (socket not found, connect failed, malformed response)
 * -2 = .NET runtime rejected the command (e.g., profiler already active,
 *      invalid argument) — check stderr for HRESULT
 * -3 = diagnostic socket not found — target may not be .NET, or diagnostics
 *      disabled (DOTNET_EnableDiagnostics=0)
 */
#define SYRINGE_DOTNET_OK 0
#define SYRINGE_DOTNET_ERROR -1
#define SYRINGE_DOTNET_REJECTED -2
#define SYRINGE_DOTNET_NO_SOCKET -3

/* ── Debug helper (controlled by SYRINGE_HOOK_DEBUG env var) ───────────── */

static inline int syringe_hook_dotnet_debug(void) {
  static int checked = 0;
  static int enabled = 0;
  if (!checked) {
    checked = 1;
    enabled = getenv("SYRINGE_HOOK_DEBUG") && getenv("SYRINGE_HOOK_DEBUG")[0] != '\0';
  }
  return enabled;
}

/* ── Helpers: little-endian write/read ─────────────────────────────────── */

static inline void syringe_dotnet_put_u16le(uint8_t *buf, uint16_t v) {
  buf[0] = (uint8_t)(v & 0xFF);
  buf[1] = (uint8_t)((v >> 8) & 0xFF);
}

static inline void syringe_dotnet_put_u32le(uint8_t *buf, uint32_t v) {
  buf[0] = (uint8_t)(v & 0xFF);
  buf[1] = (uint8_t)((v >> 8) & 0xFF);
  buf[2] = (uint8_t)((v >> 16) & 0xFF);
  buf[3] = (uint8_t)((v >> 24) & 0xFF);
}

static inline uint16_t syringe_dotnet_get_u16le(const uint8_t *buf) { return (uint16_t)(buf[0] | (buf[1] << 8)); }

static inline uint32_t syringe_dotnet_get_u32le(const uint8_t *buf) {
  return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

/* ── Socket discovery ──────────────────────────────────────────────────────

 * .NET diagnostic socket pattern: dotnet-diagnostic-{pid}-{key}-socket
 * where {key} is a numeric disambiguation key. We glob /tmp for matches
 * and return the most recently modified one. */

static inline int syringe_dotnet_find_socket(pid_t pid, char *out_path, size_t path_size) {
  DIR *d = opendir("/tmp");
  if (!d) {
    fprintf(stderr, "[!] [dotnet] opendir(/tmp): %s\n", strerror(errno));
    return -1;
  }

  char pattern[64];
  snprintf(pattern, sizeof(pattern), "dotnet-diagnostic-%d-", pid);
  size_t pat_len = strlen(pattern);

  char best_path[128] = {0};
  time_t best_mtime = 0;

  struct dirent *de;
  while ((de = readdir(d))) {
    if (strncmp(de->d_name, pattern, pat_len) != 0)
      continue;
    size_t name_len = strlen(de->d_name);
    if (name_len < 7)
      continue;
    if (strcmp(de->d_name + name_len - 7, "-socket") != 0)
      continue;
    const char *mid = de->d_name + pat_len;
    const char *mid_end = de->d_name + name_len - 7;
    if (mid >= mid_end)
      continue;
    int all_digits = 1;
    for (const char *p = mid; p < mid_end; p++) {
      if (*p < '0' || *p > '9') {
        all_digits = 0;
        break;
      }
    }
    if (!all_digits)
      continue;

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

  if (best_path[0] == '\0')
    return -1;

  snprintf(out_path, path_size, "%s", best_path);
  return 0;
}

/* ── Build AttachProfiler message ───────────────────────────────────────────

 * Build the full IPC message (header + payload) for AttachProfiler.
 * Returns malloc'd buffer (caller frees) and sets *out_len.
 * Returns NULL on error. */

static inline uint8_t *syringe_dotnet_build_attach_msg(const char *profiler_path, const void *client_data,
                                                       size_t client_len, size_t *out_len) {
  size_t path_chars = strlen(profiler_path) + 1;
  size_t path_bytes = path_chars * 2;

  size_t payload_len = 4 + 16 + 4 + path_bytes + 4 + client_len;
  size_t total_len = 20 + payload_len;

  uint8_t *msg = (uint8_t *)malloc(total_len);
  if (!msg)
    return NULL;
  memset(msg, 0, total_len);

  memcpy(msg, "DOTNET_IPC_V1\0", 14);
  syringe_dotnet_put_u16le(msg + 14, (uint16_t)total_len);
  msg[16] = 0x03;
  msg[17] = 0x01;
  syringe_dotnet_put_u16le(msg + 18, 0x0000);

  uint8_t *p = msg + 20;
  syringe_dotnet_put_u32le(p, 5);
  p += 4;

  static const uint8_t guid[16] = {0xb5, 0x6c, 0x1c, 0x0c, 0xc9, 0x3a, 0x38, 0x43,
                                   0x8e, 0x16, 0x42, 0xa0, 0xdc, 0x8b, 0x34, 0xf1};
  memcpy(p, guid, 16);
  p += 16;

  syringe_dotnet_put_u32le(p, (uint32_t)path_chars);
  p += 4;
  for (size_t i = 0; i < path_chars; i++) {
    p[0] = (uint8_t)profiler_path[i];
    p[1] = 0;
    p += 2;
  }

  syringe_dotnet_put_u32le(p, (uint32_t)client_len);
  p += 4;
  if (client_data && client_len > 0) {
    memcpy(p, client_data, client_len);
  }

  *out_len = total_len;
  return msg;
}

/* ── Send message + receive full response ───────────────────────────────────

 * Send IPC message and receive full response (header + payload).
 * Returns 0 on success, -1 on error. */

static inline int syringe_dotnet_send_recv(const char *socket_path, const uint8_t *msg, size_t msg_len,
                                           uint8_t *resp_buf, size_t resp_buf_size, size_t *out_len) {
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    fprintf(stderr, "[!] [dotnet] socket(): %s\n", strerror(errno));
    return -1;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  size_t path_len = strlen(socket_path);
  if (path_len >= sizeof(addr.sun_path)) {
    if (syringe_hook_dotnet_debug())
      fprintf(stderr, "[*] [dotnet] socket path too long: %s\n", socket_path);
    close(fd);
    return -1;
  }
  memcpy(addr.sun_path, socket_path, path_len + 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "[!] [dotnet] connect(%s): %s\n", socket_path, strerror(errno));
    close(fd);
    return -1;
  }

  ssize_t sent = 0;
  while ((size_t)sent < msg_len) {
    ssize_t n = write(fd, msg + sent, msg_len - sent);
    if (n < 0) {
      fprintf(stderr, "[!] [dotnet] write: %s\n", strerror(errno));
      close(fd);
      return -1;
    }
    sent += n;
  }

  ssize_t recvd = 0;
  while (recvd < 20) {
    ssize_t n = read(fd, resp_buf + recvd, 20 - recvd);
    if (n < 0) {
      fprintf(stderr, "[!] [dotnet] read header: %s\n", strerror(errno));
      close(fd);
      return -1;
    }
    if (n == 0) {
      close(fd);
      return -1;
    }
    recvd += n;
  }

  uint16_t total_size = syringe_dotnet_get_u16le(resp_buf + 14);
  if (total_size < 20)
    total_size = 20;
  if (total_size > resp_buf_size)
    total_size = (uint16_t)resp_buf_size;

  while (recvd < total_size) {
    ssize_t n = read(fd, resp_buf + recvd, total_size - recvd);
    if (n < 0)
      break;
    if (n == 0)
      break;
    recvd += n;
  }

  close(fd);
  *out_len = (size_t)recvd;
  return 0;
}

/* ── Public API ────────────────────────────────────────────────────────── */

static inline int syringe_dotnet_attach_profiler(pid_t pid, const char *profiler_path, const void *client_data,
                                                 size_t client_len) {
  if (!profiler_path) {
    fprintf(stderr, "[!] [dotnet] profiler_path is NULL\n");
    return SYRINGE_DOTNET_ERROR;
  }

  char socket_path[128];
  if (syringe_dotnet_find_socket(pid, socket_path, sizeof(socket_path)) < 0) {
    fprintf(stderr,
            "[!] [dotnet] No diagnostic socket for pid %d "
            "(not a .NET process, or diagnostics disabled)\n",
            pid);
    return SYRINGE_DOTNET_NO_SOCKET;
  }
  if (syringe_hook_dotnet_debug())
    fprintf(stderr, "[*] [dotnet] Found diagnostic socket: %s\n", socket_path);

  size_t msg_len = 0;
  uint8_t *msg = syringe_dotnet_build_attach_msg(profiler_path, client_data, client_len, &msg_len);
  if (!msg) {
    fprintf(stderr, "[!] [dotnet] Failed to build IPC message\n");
    return SYRINGE_DOTNET_ERROR;
  }

  if (syringe_hook_dotnet_debug())
    fprintf(stderr, "[*] [dotnet] Sending AttachProfiler (profiler=%s, %zu bytes client_data)\n", profiler_path,
            client_len);

  uint8_t resp[512];
  size_t resp_len = 0;
  int rc = syringe_dotnet_send_recv(socket_path, msg, msg_len, resp, sizeof(resp), &resp_len);
  free(msg);
  if (rc < 0)
    return SYRINGE_DOTNET_ERROR;

  if (memcmp(resp, "DOTNET_IPC_V1\0", 14) != 0) {
    fprintf(stderr, "[!] [dotnet] Bad response magic\n");
    return SYRINGE_DOTNET_ERROR;
  }

  uint8_t resp_cmd = resp[17];

  if (syringe_hook_dotnet_debug()) {
    uint16_t resp_size = syringe_dotnet_get_u16le(resp + 14);
    fprintf(stderr, "[*] [dotnet] Response: size=%u cmdset=0x%02x cmdid=0x%02x resp_len=%zu\n", resp_size, resp[16],
            resp_cmd, resp_len);
    fprintf(stderr, "[*] [dotnet] Raw: ");
    for (size_t i = 0; i < resp_len && i < 64; i++)
      fprintf(stderr, "%02x ", resp[i]);
    fprintf(stderr, "\n");
  }

  if (resp_cmd == 0x00) {
    if (syringe_hook_dotnet_debug())
      fprintf(stderr, "[*] [dotnet] AttachProfiler OK — profiler .so loaded\n");
    return SYRINGE_DOTNET_OK;
  } else if (resp_cmd == 0xFF) {
    uint32_t hresult = 0;
    if (resp_len >= 24)
      hresult = syringe_dotnet_get_u32le(resp + 20);

    if (hresult == 0x80040154) {
      if (syringe_hook_dotnet_debug())
        fprintf(stderr, "[*] [dotnet] Injected OK\n");
      return SYRINGE_DOTNET_OK;
    }

    fprintf(stderr, "[!] [dotnet] .NET rejected AttachProfiler (HRESULT=0x%08x)\n", hresult);

    if (hresult == 0x8013136A) {
      if (syringe_hook_dotnet_debug())
        fprintf(stderr, "[*] [dotnet]   → CORPROF_E_PROFILER_ALREADY_ACTIVE\n");
    } else if (hresult == 0x80131385) {
      if (syringe_hook_dotnet_debug())
        fprintf(stderr, "[*] [dotnet]   → Unknown command\n");
    } else if (hresult == 0x80070057) {
      if (syringe_hook_dotnet_debug())
        fprintf(stderr, "[*] [dotnet]   → Invalid argument\n");
    } else if (hresult == 0x80131515) {
      if (syringe_hook_dotnet_debug())
        fprintf(stderr, "[*] [dotnet]   → Not supported\n");
    }

    if (resp_len > 28) {
      uint32_t msg_len = syringe_dotnet_get_u32le(resp + 24);
      if (msg_len > 0 && 28 + msg_len * 2 <= resp_len) {
        fprintf(stderr, "[!] [dotnet]   Error message: ");
        for (uint32_t i = 0; i < msg_len && 28 + i * 2 < resp_len; i++) {
          char c = resp[28 + i * 2];
          fputc(c >= 32 && c < 127 ? c : '?', stderr);
        }
        fputc('\n', stderr);
      }
    }

    return SYRINGE_DOTNET_REJECTED;
  } else {
    fprintf(stderr, "[!] [dotnet] Unexpected response CommandId=0x%02x\n", resp_cmd);
    return SYRINGE_DOTNET_ERROR;
  }
}

static inline int syringe_inject_dotnet(pid_t pid, const char *so_path) {
  if (!so_path) {
    fprintf(stderr, "[!] [dotnet] so_path is NULL\n");
    return SYRINGE_DOTNET_ERROR;
  }

  char abs_path[4096];

  if (so_path[0] == '/') {
    strncpy(abs_path, so_path, sizeof(abs_path) - 1);
    abs_path[sizeof(abs_path) - 1] = '\0';
  } else if (so_path[0] == '.') {
    if (!realpath(so_path, abs_path)) {
      fprintf(stderr, "[!] [dotnet] realpath('%s'): %s\n", so_path, strerror(errno));
      return SYRINGE_DOTNET_ERROR;
    }
  } else {
    char candidate[4096];
    int found = 0;

    snprintf(candidate, sizeof(candidate), "./%s", so_path);
    if (realpath(candidate, abs_path))
      found = 1;

    int has_usr_local_lib = 0, has_usr_lib = 0;
    const char *ld_lib = getenv("LD_LIBRARY_PATH");
    if (!found && ld_lib && ld_lib[0]) {
      char ld_buf[4096];
      strncpy(ld_buf, ld_lib, sizeof(ld_buf) - 1);
      ld_buf[sizeof(ld_buf) - 1] = '\0';
      char *saveptr, *dir = strtok_r(ld_buf, ":", &saveptr);
      while (dir && !found) {
        if (strcmp(dir, "/usr/local/lib") == 0)
          has_usr_local_lib = 1;
        if (strcmp(dir, "/usr/lib") == 0)
          has_usr_lib = 1;
        snprintf(candidate, sizeof(candidate), "%s/%s", dir, so_path);
        if (realpath(candidate, abs_path))
          found = 1;
        dir = strtok_r(NULL, ":", &saveptr);
      }
    }

    if (!found) {
      const char *fallback[2];
      int n = 0;
      if (!has_usr_local_lib)
        fallback[n++] = "/usr/local/lib";
      if (!has_usr_lib)
        fallback[n++] = "/usr/lib";
      for (int i = 0; i < n && !found; i++) {
        snprintf(candidate, sizeof(candidate), "%s/%s", fallback[i], so_path);
        if (access(candidate, F_OK) == 0) {
          strncpy(abs_path, candidate, sizeof(abs_path) - 1);
          abs_path[sizeof(abs_path) - 1] = '\0';
          found = 1;
        }
      }
    }

    if (!found) {
      fprintf(stderr, "[!] [dotnet] library '%s' not found\n", so_path);
      return SYRINGE_DOTNET_ERROR;
    }
  }

  char entry[4112];
  int elen = snprintf(entry, sizeof(entry), "%d %s\n", pid, abs_path);
  int wfd = open("/tmp/syringe_inject", O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (wfd >= 0) {
    write(wfd, entry, elen);
    close(wfd);
  }

  char profiler_path[4096];
  const char *env = getenv("SYRINGE_PROFILER_PATH");
  if (env && env[0]) {
    if (!realpath(env, profiler_path)) {
      fprintf(stderr, "[!] [dotnet] realpath('%s'): %s\n", env, strerror(errno));
      return SYRINGE_DOTNET_ERROR;
    }
  } else {
    const char *slash = strrchr(abs_path, '/');
    if (slash) {
      size_t dir_len = (size_t)(slash - abs_path);
      snprintf(profiler_path, sizeof(profiler_path), "%.*s/libsyringe-dotnet-profiler.so", (int)dir_len, abs_path);
    } else {
      snprintf(profiler_path, sizeof(profiler_path), "./libsyringe-dotnet-profiler.so");
    }

    if (access(profiler_path, F_OK) != 0) {
      snprintf(profiler_path, sizeof(profiler_path), "/usr/local/lib/libsyringe-dotnet-profiler.so");
      if (access(profiler_path, F_OK) != 0) {
        snprintf(profiler_path, sizeof(profiler_path), "/usr/lib/libsyringe-dotnet-profiler.so");
      }
    }
  }

  size_t client_len = strlen(abs_path) + 1;
  return syringe_dotnet_attach_profiler(pid, profiler_path, abs_path, client_len);
}

#endif /* SYRINGE_HOOK_DOTNET_H */
