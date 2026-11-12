#!/usr/bin/env python3
"""Build pinned Android/Bionic Tor runtimes.

Requires Linux, Android NDK 27.3.13750724, Go 1.27.3, make, Perl and Python 3.12+.
Ordinary rebuilds must match the checked-in hashes. --update-pins is an explicit
maintainer action whose resulting binaries and manifest must be reviewed together.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "src-tauri/vendor/tor/android"
SOURCES = {
    "tor": ("https://dist.torproject.org/tor-0.4.9.15.tar.gz", "1911f5b216a6814ed143a08bbcff1c6dc96d2ca3b505df9a21876080a92963f3", "tor-0.4.9.15"),
    "openssl": ("https://github.com/openssl/openssl/releases/download/openssl-3.5.9/openssl-3.5.9.tar.gz", "603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a", "openssl-3.5.9"),
    "libevent": ("https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz", "92e6de1be9ec176428fd2367677e61ceffc2ee1cb119035037a27d346b0403bb", "libevent-2.1.12-stable"),
    "zlib": ("https://zlib.net/zlib-1.3.2.tar.gz", "bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16", "zlib-1.3.2"),
    "lyrebird": ("https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/archive/0b10edbb61e0ca6fb70c7d57aeaabf315f1fade1/lyrebird-0b10edbb61e0ca6fb70c7d57aeaabf315f1fade1.tar.gz", "a0bd43cbbd3b7932b8dedc80e9ffdb6f0092b5b94e12fccd0fe76c8a825ce2cd", "lyrebird-0b10edbb61e0ca6fb70c7d57aeaabf315f1fade1"),
}
TARGETS = {
    "arm64-v8a": ("aarch64-linux-android", "android-arm64", "arm64"),
    "x86_64": ("x86_64-linux-android", "android-x86_64", "amd64"),
}


def digest(path):
    return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abi", choices=TARGETS, action="append")
    parser.add_argument("--work-dir", type=Path, default=ROOT / ".cache/android-tor-build")
    parser.add_argument("--update-pins", action="store_true")
    args = parser.parse_args()
    work = args.work_dir.resolve()
    ndk = Path(os.environ.get("NDK_HOME", ""))
    if not ndk.is_dir() or "27.3.13750724" not in (ndk / "source.properties").read_text():
        raise SystemExit("Set NDK_HOME to Android NDK 27.3.13750724")
    if subprocess.check_output(["go", "version"], text=True).split()[2] != "go1.27.3":
        raise SystemExit("Use the pinned Go 1.27.3 compiler")
    tools = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    work.mkdir(parents=True, exist_ok=True)
    sources = work / "sources"
    sources.mkdir(exist_ok=True)
    for name, (url, sha, dirname) in SOURCES.items():
        archive = work / "downloads" / ("lyrebird-commit.tar.gz" if name == "lyrebird" else name + ".tar.gz")
        archive.parent.mkdir(exist_ok=True)
        if not archive.exists():
            urllib.request.urlretrieve(url, archive)
        if digest(archive) != sha:
            raise SystemExit(f"Unauthenticated source archive: {archive}")
        
        source = sources / dirname
        if source.exists():
            shutil.rmtree(source)
        with tarfile.open(archive) as stream:
            stream.extractall(sources, filter="data")
    DEST.mkdir(parents=True, exist_ok=True)
    pin_file = DEST / "manifest.json"
    pins = json.loads(pin_file.read_text()) if pin_file.exists() else {"abis": {}}
    if not args.update_pins and not pin_file.exists():
        raise SystemExit("Missing reviewed Android Tor pins")
    pins.update({"version": "0.4.9.15-lyrebird-0.8.1", "minSdk": 24, "ndk": "27.3.13750724", "go": "1.27.3", "sources": {name: {"url": url, "sha256": sha} for name, (url, sha, _) in SOURCES.items()}})
    for abi in args.abi or TARGETS:
        triple, ssl_target, go_arch = TARGETS[abi]
        build = work / abi
        if build.exists():
            shutil.rmtree(build)
        build.mkdir()
        prefix = build / "prefix"
        prefix.mkdir()
        env = os.environ.copy()
        flags = f"-O2 -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2 -ffile-prefix-map={work}=/build/qorc-android-tor"
        ldflags = "-Wl,-z,relro,-z,now,-z,noexecstack,-z,max-page-size=16384 -Wl,--build-id=sha1"
        env.update({"PATH": f"{tools}:{env['PATH']}", "ANDROID_NDK_ROOT": str(ndk), "CC": f"{tools}/{triple}24-clang", "AR": str(tools / "llvm-ar"), "RANLIB": str(tools / "llvm-ranlib"), "CFLAGS": flags, "CPPFLAGS": "", "LDFLAGS": ldflags, "SOURCE_DATE_EPOCH": "1793194373", "LC_ALL": "C", "TZ": "UTC", "PKG_CONFIG_LIBDIR": str(prefix / "lib/pkgconfig"), "PKG_CONFIG_PATH": ""})
        log = work / f"{abi}.log"

        def run(cmd, cwd, extra=None):
            print(f"{abi}: {' '.join(map(str, cmd[:3]))} (log: {log})", flush=True)
            with log.open("ab") as output:
                result = subprocess.run(list(map(str, cmd)), cwd=cwd, env=env | (extra or {}), stdout=output, stderr=subprocess.STDOUT)
            if result.returncode:
                print(log.read_text(errors="replace")[-6000:])
                raise SystemExit(result.returncode)

        ssl = build / "openssl"
        ssl.mkdir()
        run(["perl", sources / SOURCES["openssl"][2] / "Configure", ssl_target, "-D__ANDROID_API__=24", "no-shared", "no-tests", "no-module", "no-dso", f"--prefix={prefix}", "--openssldir=/nonexistent/qorc/openssl", flags, ldflags], ssl)
        run(["make", "-j2", "build_libs"], ssl)
        run(["make", "install_dev"], ssl)
        event = build / "libevent"
        event.mkdir()
        run([sources / SOURCES["libevent"][2] / "configure", f"--host={triple}", f"--prefix={prefix}", "--disable-shared", "--enable-static", "--disable-openssl", "--disable-samples", "--disable-libevent-regress"], event)
        run(["make", "-j2"], event)
        run(["make", "install"], event)
        zlib = build / "zlib"
        zlib.mkdir()
        run([sources / SOURCES["zlib"][2] / "configure", "--static", f"--prefix={prefix}"], zlib, {"CHOST": triple})
        run(["make", "-j2"], zlib)
        run(["make", "install"], zlib)
        tor = build / "tor"
        tor.mkdir()
        run([sources / SOURCES["tor"][2] / "configure", f"--host={triple}", "--disable-asciidoc", "--disable-manpage", "--disable-html-manual", "--disable-unittests", "--disable-tool-name-check", "--disable-system-torrc", "--disable-systemd", "--disable-lzma", "--disable-zstd", "--enable-static-openssl", "--enable-static-libevent", "--enable-static-zlib", f"--with-openssl-dir={prefix}", f"--with-libevent-dir={prefix}", f"--with-zlib-dir={prefix}"], tor, {"LDFLAGS": ldflags + " -pie"})
        run(["make", "-j2", "src/app/tor"], tor)
        output = build / "out"
        output.mkdir()
        shutil.copyfile(tor / "src/app/tor", output / "libqorc_tor.so")

        run(["go", "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-buildmode=pie", "-ldflags", f"-s -w -buildid= -checklinkname=0 -X main.lyrebirdVersion=0.8.1 -linkmode external -extldflags '{ldflags}'", "-o", output / "libqorc_lyrebird.so", "./cmd/lyrebird"], sources / SOURCES["lyrebird"][2], {"GOOS": "android", "GOARCH": go_arch, "CGO_ENABLED": "1", "GOTOOLCHAIN": "local", "GOMAXPROCS": "2", "GOCACHE": str(work / "go-cache"), "GOMODCACHE": str(work / "go-modules")})
        for binary in output.iterdir():
            run([tools / "llvm-strip", "--strip-unneeded", binary], output)
            run([tools / "llvm-readelf", "--program-headers", "--dynamic", binary], output)
        hashes = {p.name: digest(p) for p in sorted(output.iterdir())}
        if not args.update_pins and pins["abis"].get(abi) != hashes:
            raise SystemExit(f"Rebuild differs from reviewed hashes: {abi}: {hashes}")
        native = DEST / "jniLibs" / abi
        native.mkdir(parents=True, exist_ok=True)
        for binary in output.iterdir():
            shutil.copyfile(binary, native / binary.name)
            (native / binary.name).chmod(0o755)
        pins["abis"][abi] = hashes
        print(f"{abi}: built and verified {hashes}", flush=True)
        
    archive_bytes = io.BytesIO()
    with gzip.GzipFile(fileobj=archive_bytes, mode="wb", filename="", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar:
            tor_source = sources / SOURCES["tor"][2]
            files = {"geoip": tor_source / "src/config/geoip", "geoip6": tor_source / "src/config/geoip6", "tor.txt": tor_source / "LICENSE", "lyrebird.txt": sources / SOURCES["lyrebird"][2] / "LICENSE"}
            for name, file in files.items():
                data = file.read_bytes()
                info = tarfile.TarInfo("tor/" + name)
                info.size = len(data)
                info.mode = 0o600
                tar.addfile(info, io.BytesIO(data))
    data = archive_bytes.getvalue()
    data_sha = hashlib.sha256(data).hexdigest()
    if not args.update_pins and pins.get("dataSha256") != data_sha:
        raise SystemExit("Rebuilt Tor data differs from reviewed hash")
    (DEST / "tor-data.tar.gz").write_bytes(data)
    pins["dataSha256"] = data_sha
    
    go_env = os.environ | {"GOOS": "android", "GOARCH": "arm64", "CGO_ENABLED": "1", "GOTOOLCHAIN": "local", "GOMODCACHE": str(work / "go-modules")}
    module_dirs = subprocess.check_output(["go", "list", "-mod=readonly", "-deps", "-f", "{{if .Module}}{{.Module.Dir}}{{end}}", "./cmd/lyrebird"], cwd=sources / SOURCES["lyrebird"][2], env=go_env, text=True).splitlines()
    licenses = []
    for directory in sorted(set(module_dirs) | {str(sources / SOURCES[name][2]) for name in SOURCES}):
        if not directory:
            continue
        directory = Path(directory)
        for file in sorted(directory.iterdir()):
            if file.is_file() and file.name.lower().startswith(("license", "copying", "notice")):
                label = str(directory).replace(str(work / "go-modules"), "Go module").replace(str(sources), "Source")
                licenses.append(f"\n{'=' * 72}\n{label}/{file.name}\n{'=' * 72}\n" + file.read_text(errors="replace"))
    notices = DEST / "licenses"
    notices.mkdir(exist_ok=True)
    (notices / "QORC_TOR_THIRD_PARTY_LICENSES.txt").write_text("".join(licenses))
    if args.update_pins:
        pin_file.write_text(json.dumps(pins, indent=2) + "\n")


if __name__ == "__main__":
    main()
