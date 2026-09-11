# PlatformIO pre-build script: apply the ScotMesh patches in patches/<library>/
# to the libraries this environment pulls in through lib_deps.
#
# The fixes live in this fork, not in forks of the libraries, so every build
# (local and the GitHub release workflow) patches the fetched copy in
# .pio/libdeps/<env>/<library> before compiling. Each patch is applied once:
# a patch that is already in place is left alone, and one that no longer
# applies (the library moved under it) stops the build rather than shipping
# firmware without the fix.
import os
import subprocess
import sys

Import("env")  # noqa: F821  (provided by PlatformIO/SCons)

PATCH_ROOT = os.path.join(env.subst("$PROJECT_DIR"), "patches")
LIBDEPS = os.path.join(env.subst("$PROJECT_LIBDEPS_DIR"), env.subst("$PIOENV"))


def git_apply(lib_dir, patch, *args):
    return subprocess.run(["git", "apply", *args, patch], cwd=lib_dir,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def patch_library(name):
    lib_dir = os.path.join(LIBDEPS, name)
    patches = sorted(os.path.join(PATCH_ROOT, name, p) for p in os.listdir(os.path.join(PATCH_ROOT, name)) if p.endswith(".patch"))
    if not patches:
        return
    # lib_deps are normally installed after pre-scripts run, and reinstalled
    # when their spec changes. Install now (a no-op when nothing changed) so
    # the patch is always applied to the copy that gets compiled.
    subprocess.run([sys.executable, "-m", "platformio", "pkg", "install", "-e", env.subst("$PIOENV"),
                    "-d", env.subst("$PROJECT_DIR"), "--silent"], check=True)
    if not os.path.isdir(lib_dir):
        return  # this environment does not use the library
    for patch in patches:
        label = f"{name}/{os.path.basename(patch)}"
        if git_apply(lib_dir, patch, "--reverse", "--check").returncode == 0:
            print(f"[patches] {label}: already applied")
            continue
        check = git_apply(lib_dir, patch, "--check")
        if check.returncode != 0:
            sys.stderr.write(f"[patches] {label} no longer applies to {lib_dir}:\n{check.stdout}\n")
            env.Exit(1)
        git_apply(lib_dir, patch)
        print(f"[patches] {label}: applied")


if os.path.isdir(PATCH_ROOT):
    for library in sorted(os.listdir(PATCH_ROOT)):
        if os.path.isdir(os.path.join(PATCH_ROOT, library)):
            patch_library(library)
