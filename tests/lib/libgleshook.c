/*
 * libgleshook.c — inject-ready sample library using GOT patching
 *
 * Hooks the swap/present functions of 4 common graphics stacks:
 *   eglSwapBuffers    (OpenGL ES / EGL — Mali, Adreno, most Wayland stacks)
 *   glXSwapBuffers    (OpenGL / GLX  — X11 desktops, classic games)
 *   SDL_GL_SwapWindow (SDL2/SDL3 wrapper — many indie games / ports)
 *   wl_surface_commit (Wayland raw surface commit — non-GL compositors)
 *
 * Build:
 *   gcc -shared -fPIC -O2 -o libgleshook.so libgleshook.c \
 *       -ldl -lGL -lEGL -lpthread
 *
 *   (Link only what you actually use; EGL/GL are weak-linked so the lib
 *    loads even if those aren't present in the target.)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>

/* pull in EGL / GL types without requiring the dev headers at runtime */
typedef void*    EGLDisplay;
typedef void*    EGLSurface;
typedef uint32_t EGLBoolean;

/* GLX */
typedef void* Display;
typedef void* GLXDrawable;

/* Wayland opaque types */
struct wl_surface;
struct wl_proxy;

#include "syringe_hook.h"

/* ── original function pointers ─────────────────────────────────────────── */

static EGLBoolean (*orig_eglSwapBuffers)(EGLDisplay, EGLSurface) = NULL;
static void       (*orig_glXSwapBuffers)(Display*, GLXDrawable)  = NULL;
static void       (*orig_SDL_GL_SwapWindow)(void*)               = NULL;
static int        (*orig_wl_surface_commit)(struct wl_proxy*)    = NULL;

/* ── hook implementations ───────────────────────────────────────────────── */

static EGLBoolean hook_eglSwapBuffers(EGLDisplay dpy, EGLSurface surface) {
    return orig_eglSwapBuffers(dpy, surface);
}

static void hook_glXSwapBuffers(Display *dpy, GLXDrawable drawable) {
    orig_glXSwapBuffers(dpy, drawable);
}

static void hook_SDL_GL_SwapWindow(void *window) {
    orig_SDL_GL_SwapWindow(window);
}

static int hook_wl_surface_commit(struct wl_proxy *surface) {
    return orig_wl_surface_commit(surface);
}

/* ── install / remove ───────────────────────────────────────────────────── */

/*
 * Try to hook `sym`.  We first verify the symbol actually exists in the
 * process (via dlsym) before attempting GOT patching — avoids spamming
 * warnings for hooks the target doesn't use.
 */
#define TRY_HOOK(sym, hook_fn, orig_ptr) do {                       \
    void *_real = dlsym(RTLD_DEFAULT, #sym);                        \
    if (_real) {                                                     \
        int _n = syringe_hook_install(#sym, (void*)(hook_fn),           \
                                  (void**)&(orig_ptr));             \
        if (_n == 0) {                                              \
            /* GOT has no entry (maybe called via PLT thunk inside  \
               the same lib). Fall back to storing dlsym result. */ \
            (orig_ptr) = (typeof(orig_ptr))_real;                   \
            fprintf(stderr,                                          \
                "[sample] '%s' present but no GOT entry found — "  \
                "stored dlsym fallback\n", #sym);                   \
        }                                                            \
    } else {                                                         \
        fprintf(stderr, "[sample] '%s' not found in process\n",    \
                #sym);                                               \
    }                                                                \
} while(0)

__attribute__((constructor))
static void sample_load(void) {
    fprintf(stderr, "[sample] loading into pid %d\n", getpid());

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    TRY_HOOK(eglSwapBuffers,    hook_eglSwapBuffers,    orig_eglSwapBuffers);
    TRY_HOOK(glXSwapBuffers,    hook_glXSwapBuffers,    orig_glXSwapBuffers);
    TRY_HOOK(SDL_GL_SwapWindow, hook_SDL_GL_SwapWindow, orig_SDL_GL_SwapWindow);
    TRY_HOOK(wl_surface_commit, hook_wl_surface_commit, orig_wl_surface_commit);
#pragma GCC diagnostic pop

    fprintf(stderr, "[sample] ready — hooks installed\n");
}

__attribute__((destructor))
static void sample_unload(void) {
    fprintf(stderr, "[sample] unloading, removing hooks\n");
    syringe_hook_remove_all();
}
