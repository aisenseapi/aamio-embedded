"""Generate the vector header, compile the conformance test, run it.

    python tools/build.py           # the lot
    python tools/build.py --size    # and print what it costs in code and stack

Finds a compiler on PATH, or the sandbox one under %TEMP%/aamio-tc/mingw. Warnings are
errors: a device has no room for the kind of mistake a warning names.
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FLAGS = ["-std=c99", "-Wall", "-Wextra", "-Werror", "-Iinclude"]


def compiler():
    found = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")

    if found:
        return found

    sandbox = os.path.join(os.environ.get("TEMP", ""), "aamio-tc", "mingw", "mingw64", "bin", "gcc.exe")

    if os.path.exists(sandbox):
        return sandbox

    raise SystemExit("no C compiler on PATH and none in the sandbox")


def run(command, **kwargs):
    done = subprocess.run(command, cwd=ROOT, **kwargs)

    if done.returncode != 0:
        raise SystemExit(done.returncode)

    return done


def main():
    gcc = compiler()
    print("compiler: %s" % gcc)

    run([sys.executable, os.path.join("tools", "make-vectors.py"), "--write"])

    binary = os.path.join(ROOT, "conformance.exe" if os.name == "nt" else "conformance")
    run([gcc] + FLAGS + ["-O2", "-o", binary, os.path.join("src", "aamio.c"),
                         os.path.join("test", "conformance.c")])
    print()
    run([binary])

    if "--size" in sys.argv:
        print()
        object_file = os.path.join(ROOT, "aamio-os.o")
        run([gcc] + FLAGS + ["-Os", "-fstack-usage", "-c", "-o", object_file, os.path.join("src", "aamio.c")])
        size = shutil.which("size") or os.path.join(os.path.dirname(gcc), "size.exe")

        if os.path.exists(size) or shutil.which("size"):
            run([size, object_file])

        usage = os.path.join(ROOT, "aamio-os.su")

        if os.path.exists(usage):
            frames = sorted(
                (int(line.split("\t")[1]), line.split("\t")[0].split(":")[-1])
                for line in open(usage, encoding="utf-8").read().splitlines() if "\t" in line
            )
            print()
            print("deepest stack frames:")

            for size_of, name in frames[-4:][::-1]:
                print("  %-26s %5d bytes" % (name, size_of))

            os.remove(usage)

        os.remove(object_file)


if __name__ == "__main__":
    main()
