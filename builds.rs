========== build.rs from anyhow-1.0.58 ============================================================
#![allow(clippy::option_if_let_else)]

use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::str;

#[cfg(all(feature = "backtrace", not(feature = "std")))]
compile_error! {
    "`backtrace` feature without `std` feature is not supported"
}

// This code exercises the surface area that we expect of the std Backtrace
// type. If the current toolchain is able to compile it, we go ahead and use
// backtrace in anyhow.
const PROBE: &str = r#"
    #![feature(backtrace)]
    #![allow(dead_code)]

    use std::backtrace::{Backtrace, BacktraceStatus};
    use std::error::Error;
    use std::fmt::{self, Display};

    #[derive(Debug)]
    struct E;

    impl Display for E {
        fn fmt(&self, _formatter: &mut fmt::Formatter) -> fmt::Result {
            unimplemented!()
        }
    }

    impl Error for E {
        fn backtrace(&self) -> Option<&Backtrace> {
            let backtrace = Backtrace::capture();
            match backtrace.status() {
                BacktraceStatus::Captured | BacktraceStatus::Disabled | _ => {}
            }
            unimplemented!()
        }
    }
"#;

fn main() {
    if cfg!(feature = "std") {
        match compile_probe() {
            Some(status) if status.success() => println!("cargo:rustc-cfg=backtrace"),
            _ => {}
        }
    }

    let rustc = match rustc_minor_version() {
        Some(rustc) => rustc,
        None => return,
    };

    if rustc < 51 {
        println!("cargo:rustc-cfg=anyhow_no_ptr_addr_of");
    }

    if rustc < 52 {
        println!("cargo:rustc-cfg=anyhow_no_fmt_arguments_as_str");
    }
}

fn compile_probe() -> Option<ExitStatus> {
    let rustc = env::var_os("RUSTC")?;
    let out_dir = env::var_os("OUT_DIR")?;
    let probefile = Path::new(&out_dir).join("probe.rs");
    fs::write(&probefile, PROBE).ok()?;

    // Make sure to pick up Cargo rustc configuration.
    let mut cmd = if let Some(wrapper) = env::var_os("CARGO_RUSTC_WRAPPER") {
        let mut cmd = Command::new(wrapper);
        // The wrapper's first argument is supposed to be the path to rustc.
        cmd.arg(rustc);
        cmd
    } else {
        Command::new(rustc)
    };

    cmd.stderr(Stdio::null())
        .arg("--edition=2018")
        .arg("--crate-name=anyhow_build")
        .arg("--crate-type=lib")
        .arg("--emit=metadata")
        .arg("--out-dir")
        .arg(out_dir)
        .arg(probefile);

    // If Cargo wants to set RUSTFLAGS, use that.
    if let Ok(rustflags) = env::var("CARGO_ENCODED_RUSTFLAGS") {
        if !rustflags.is_empty() {
            for arg in rustflags.split('\x1f') {
                cmd.arg(arg);
            }
        }
    }

    cmd.status().ok()
}

fn rustc_minor_version() -> Option<u32> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    pieces.next()?.parse().ok()
}
========== build.rs from atomic-polyfill-0.1.8 ============================================================
use std::env;
use std::fmt;

#[derive(Clone, Copy)]
enum PolyfillLevel {
    // Native, ie no polyfill. Just reexport from core::sync::atomic
    Native,
    // CAS polyfill: use AtomicXX from core::sync::atomic, add CAS polyfills with critical sections
    Cas,
    // Full polyfill: polyfill both load/store and CAS with critical sections
    Full,
}

impl fmt::Display for PolyfillLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Self::Native => "native",
            Self::Cas => "cas",
            Self::Full => "full",
        };
        write!(f, "{}", s)
    }
}

fn main() {
    let target = env::var("TARGET").unwrap();

    use PolyfillLevel::*;

    let patterns = [
        ("riscv32imac-*", (Native, Full)),
        ("riscv32gc-*", (Native, Full)),
        ("riscv32imc-*-espidf", (Native, Native)),
        ("riscv32*", (Full, Full)),
        ("avr-*", (Full, Full)),
        ("thumbv4t-*", (Full, Full)),
        ("thumbv6m-*", (Cas, Full)),
        ("thumbv7m-*", (Native, Full)),
        ("thumbv7em-*", (Native, Full)),
        ("thumbv8m.base-*", (Native, Full)),
        ("thumbv8m.main-*", (Native, Full)),
        ("xtensa-*-espidf", (Native, Native)),
        ("xtensa-esp32-*", (Native, Full)),
        ("xtensa-esp32s2-*", (Full, Full)),
        ("xtensa-esp32s3-*", (Native, Full)),
        ("xtensa-esp8266-*", (Cas, Full)),
    ];

    if let Some((_, (level, level64))) = patterns
        .iter()
        .find(|(pattern, _)| matches(pattern, &target))
    {
        println!("cargo:rustc-cfg=u8_{}", level);
        println!("cargo:rustc-cfg=u16_{}", level);
        println!("cargo:rustc-cfg=u32_{}", level);
        println!("cargo:rustc-cfg=u64_{}", level64);
        println!("cargo:rustc-cfg=usize_{}", level);
        println!("cargo:rustc-cfg=i8_{}", level);
        println!("cargo:rustc-cfg=i16_{}", level);
        println!("cargo:rustc-cfg=i32_{}", level);
        println!("cargo:rustc-cfg=i64_{}", level64);
        println!("cargo:rustc-cfg=isize_{}", level);
        println!("cargo:rustc-cfg=ptr_{}", level);
        println!("cargo:rustc-cfg=bool_{}", level);
    } else {
        // If we don't know about the target, just reexport the entire `core::atomic::*`
        // This doesn't polyfill anything, but it's guaranteed to never fail build.
        println!("cargo:rustc-cfg=reexport_core");
    }

    if target.starts_with("avr-") {
        println!("cargo:rustc-cfg=missing_refunwindsafe")
    }
}

// tiny glob replacement to avoid pulling in more crates.
// Supports 0 or 1 wildcards `*`
fn matches(pattern: &str, val: &str) -> bool {
    if let Some(p) = pattern.find('*') {
        let prefix = &pattern[..p];
        let suffix = &pattern[p + 1..];
        val.len() >= prefix.len() + suffix.len() && val.starts_with(prefix) && val.ends_with(suffix)
    } else {
        val == pattern
    }
}
========== build.rs from az-1.2.1 ============================================================
// Copyright © 2019–2021 Trevor Spiteri

// Copying and distribution of this file, with or without
// modification, are permitted in any medium without royalty provided
// the copyright notice and this notice are preserved. This file is
// offered as-is, without any warranty.

use std::{
    env,
    ffi::OsString,
    fs::{self, File},
    io::{Result as IoResult, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

fn main() {
    check_feature("track_caller", TRY_TRACK_CALLER);
}

fn check_feature(name: &str, contents: &str) {
    let rustc = cargo_env("RUSTC");
    let out_dir = PathBuf::from(cargo_env("OUT_DIR"));

    let try_dir = out_dir.join(format!("try_{}", name));
    let filename = format!("try_{}.rs", name);
    create_dir_or_panic(&try_dir);
    println!("$ cd {:?}", try_dir);
    create_file_or_panic(&try_dir.join(&filename), contents);
    let mut cmd = Command::new(&rustc);
    cmd.current_dir(&try_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .args(&[&*filename, "--emit=dep-info,metadata"]);
    println!("$ {:?} >& /dev/null", cmd);
    let status = cmd
        .status()
        .unwrap_or_else(|_| panic!("Unable to execute: {:?}", cmd));
    if status.success() {
        println!("cargo:rustc-cfg={}", name);
    }
    if cfg!(target_os = "windows") {
        // remove_dir_all started to fail on rustc 1.64.0-nightly
        let _ = remove_dir(&try_dir);
    } else {
        remove_dir_or_panic(&try_dir);
    }
}

fn cargo_env(name: &str) -> OsString {
    env::var_os(name)
        .unwrap_or_else(|| panic!("environment variable not found: {}, please use cargo", name))
}

fn remove_dir(dir: &Path) -> IoResult<()> {
    if !dir.exists() {
        return Ok(());
    }
    assert!(dir.is_dir(), "Not a directory: {:?}", dir);
    println!("$ rm -r {:?}", dir);
    fs::remove_dir_all(dir)
}

fn remove_dir_or_panic(dir: &Path) {
    remove_dir(dir).unwrap_or_else(|_| panic!("Unable to remove directory: {:?}", dir));
}

fn create_dir(dir: &Path) -> IoResult<()> {
    println!("$ mkdir -p {:?}", dir);
    fs::create_dir_all(dir)
}

fn create_dir_or_panic(dir: &Path) {
    create_dir(dir).unwrap_or_else(|_| panic!("Unable to create directory: {:?}", dir));
}

fn create_file_or_panic(filename: &Path, contents: &str) {
    println!("$ printf '%s' {:?}... > {:?}", &contents[0..10], filename);
    let mut file =
        File::create(filename).unwrap_or_else(|_| panic!("Unable to create file: {:?}", filename));
    file.write_all(contents.as_bytes())
        .unwrap_or_else(|_| panic!("Unable to write to file: {:?}", filename));
}

const TRY_TRACK_CALLER: &str = r#"// try_track_caller.rs
#[track_caller]
fn _tracked() {}
fn main() {}
"#;
========== build.rs from bare-metal-0.2.4 ============================================================
extern crate rustc_version;

fn main() {
    let vers = rustc_version::version().unwrap();

    if vers.major == 1 && vers.minor < 31 {
        println!("cargo:rustc-cfg=unstable_const_fn")
    }
}
========== build.rs from bzip2-sys-0.1.11+1.0.8 ============================================================
extern crate cc;
extern crate pkg_config;

use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let mut cfg = cc::Build::new();
    let target = env::var("TARGET").unwrap();
    cfg.warnings(false);

    if target.contains("windows") {
        cfg.define("_WIN32", None);
        cfg.define("BZ_EXPORT", None);
    } else if !cfg!(feature = "static") {
        // pkg-config doesn't guarantee static link
        if pkg_config::Config::new()
            .cargo_metadata(true)
            .probe("bzip2")
            .is_ok()
        {
            return;
        }
    }

    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    cfg.include("bzip2-1.0.8")
        .define("_FILE_OFFSET_BITS", Some("64"))
        .define("BZ_NO_STDIO", None)
        .file("bzip2-1.0.8/blocksort.c")
        .file("bzip2-1.0.8/huffman.c")
        .file("bzip2-1.0.8/crctable.c")
        .file("bzip2-1.0.8/randtable.c")
        .file("bzip2-1.0.8/compress.c")
        .file("bzip2-1.0.8/decompress.c")
        .file("bzip2-1.0.8/bzlib.c")
        .out_dir(dst.join("lib"))
        .compile("libbz2.a");

    let src = env::current_dir().unwrap().join("bzip2-1.0.8");
    let include = dst.join("include");
    fs::create_dir_all(&include).unwrap();
    fs::copy(src.join("bzlib.h"), dst.join("include/bzlib.h")).unwrap();
    println!("cargo:root={}", dst.display());
    println!("cargo:include={}", dst.join("include").display());
}
========== build.rs from cast-0.2.7 ============================================================
extern crate rustc_version;

fn main() {
    let vers = rustc_version::version().unwrap();
    if vers.major == 1 && vers.minor >= 26 {
        println!("cargo:rustc-cfg=stable_i128")
    }
}
========== build.rs from compiler_builtins-0.1.73 ============================================================
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let target = env::var("TARGET").unwrap();
    let cwd = env::current_dir().unwrap();

    println!("cargo:compiler-rt={}", cwd.join("compiler-rt").display());

    // Activate libm's unstable features to make full use of Nightly.
    println!("cargo:rustc-cfg=feature=\"unstable\"");

    // Emscripten's runtime includes all the builtins
    if target.contains("emscripten") {
        return;
    }

    // OpenBSD provides compiler_rt by default, use it instead of rebuilding it from source
    if target.contains("openbsd") {
        println!("cargo:rustc-link-search=native=/usr/lib");
        println!("cargo:rustc-link-lib=compiler_rt");
        return;
    }

    // Forcibly enable memory intrinsics on wasm & SGX as we don't have a libc to
    // provide them.
    if (target.contains("wasm") && !target.contains("wasi"))
        || (target.contains("sgx") && target.contains("fortanix"))
        || target.contains("-none")
        || target.contains("nvptx")
    {
        println!("cargo:rustc-cfg=feature=\"mem\"");
    }

    // These targets have hardware unaligned access support.
    if target.contains("x86_64")
        || target.contains("i686")
        || target.contains("aarch64")
        || target.contains("bpf")
    {
        println!("cargo:rustc-cfg=feature=\"mem-unaligned\"");
    }

    // NOTE we are going to assume that llvm-target, what determines our codegen option, matches the
    // target triple. This is usually correct for our built-in targets but can break in presence of
    // custom targets, which can have arbitrary names.
    let llvm_target = target.split('-').collect::<Vec<_>>();

    // Build missing intrinsics from compiler-rt C source code. If we're
    // mangling names though we assume that we're also in test mode so we don't
    // build anything and we rely on the upstream implementation of compiler-rt
    // functions
    if !cfg!(feature = "mangled-names") && cfg!(feature = "c") {
        // Don't use a C compiler for these targets:
        //
        // * wasm - clang for wasm is somewhat hard to come by and it's
        //   unlikely that the C is really that much better than our own Rust.
        // * nvptx - everything is bitcode, not compatible with mixed C/Rust
        // * riscv - the rust-lang/rust distribution container doesn't have a C
        //   compiler nor is cc-rs ready for compilation to riscv (at this
        //   time). This can probably be removed in the future
        if !target.contains("wasm") && !target.contains("nvptx") && !target.starts_with("riscv") {
            #[cfg(feature = "c")]
            c::compile(&llvm_target, &target);
        }
    }

    // To compile intrinsics.rs for thumb targets, where there is no libc
    if llvm_target[0].starts_with("thumb") {
        println!("cargo:rustc-cfg=thumb")
    }

    // compiler-rt `cfg`s away some intrinsics for thumbv6m and thumbv8m.base because
    // these targets do not have full Thumb-2 support but only original Thumb-1.
    // We have to cfg our code accordingly.
    if llvm_target[0] == "thumbv6m" || llvm_target[0] == "thumbv8m.base" {
        println!("cargo:rustc-cfg=thumb_1")
    }

    // Only emit the ARM Linux atomic emulation on pre-ARMv6 architectures. This
    // includes the old androideabi. It is deprecated but it is available as a
    // rustc target (arm-linux-androideabi).
    if llvm_target[0] == "armv4t"
        || llvm_target[0] == "armv5te"
        || target == "arm-linux-androideabi"
    {
        println!("cargo:rustc-cfg=kernel_user_helpers")
    }
}

#[cfg(feature = "c")]
mod c {
    extern crate cc;

    use std::collections::{BTreeMap, HashSet};
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    struct Sources {
        // SYMBOL -> PATH TO SOURCE
        map: BTreeMap<&'static str, &'static str>,
    }

    impl Sources {
        fn new() -> Sources {
            Sources {
                map: BTreeMap::new(),
            }
        }

        fn extend(&mut self, sources: &[(&'static str, &'static str)]) {
            // NOTE Some intrinsics have both a generic implementation (e.g.
            // `floatdidf.c`) and an arch optimized implementation
            // (`x86_64/floatdidf.c`). In those cases, we keep the arch optimized
            // implementation and discard the generic implementation. If we don't
            // and keep both implementations, the linker will yell at us about
            // duplicate symbols!
            for (symbol, src) in sources {
                if src.contains("/") {
                    // Arch-optimized implementation (preferred)
                    self.map.insert(symbol, src);
                } else {
                    // Generic implementation
                    if !self.map.contains_key(symbol) {
                        self.map.insert(symbol, src);
                    }
                }
            }
        }

        fn remove(&mut self, symbols: &[&str]) {
            for symbol in symbols {
                self.map.remove(*symbol).unwrap();
            }
        }
    }

    /// Compile intrinsics from the compiler-rt C source code
    pub fn compile(llvm_target: &[&str], target: &String) {
        let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
        let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
        let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap();
        let mut consider_float_intrinsics = true;
        let cfg = &mut cc::Build::new();

        // AArch64 GCCs exit with an error condition when they encounter any kind of floating point
        // code if the `nofp` and/or `nosimd` compiler flags have been set.
        //
        // Therefore, evaluate if those flags are present and set a boolean that causes any
        // compiler-rt intrinsics that contain floating point source to be excluded for this target.
        if target_arch == "aarch64" {
            let cflags_key = String::from("CFLAGS_") + &(target.to_owned().replace("-", "_"));
            if let Ok(cflags_value) = env::var(cflags_key) {
                if cflags_value.contains("+nofp") || cflags_value.contains("+nosimd") {
                    consider_float_intrinsics = false;
                }
            }
        }

        cfg.warnings(false);

        if target_env == "msvc" {
            // Don't pull in extra libraries on MSVC
            cfg.flag("/Zl");

            // Emulate C99 and C++11's __func__ for MSVC prior to 2013 CTP
            cfg.define("__func__", Some("__FUNCTION__"));
        } else {
            // Turn off various features of gcc and such, mostly copying
            // compiler-rt's build system already
            cfg.flag("-fno-builtin");
            cfg.flag("-fvisibility=hidden");
            cfg.flag("-ffreestanding");
            // Avoid the following warning appearing once **per file**:
            // clang: warning: optimization flag '-fomit-frame-pointer' is not supported for target 'armv7' [-Wignored-optimization-argument]
            //
            // Note that compiler-rt's build system also checks
            //
            // `check_cxx_compiler_flag(-fomit-frame-pointer COMPILER_RT_HAS_FOMIT_FRAME_POINTER_FLAG)`
            //
            // in https://github.com/rust-lang/compiler-rt/blob/c8fbcb3/cmake/config-ix.cmake#L19.
            cfg.flag_if_supported("-fomit-frame-pointer");
            cfg.define("VISIBILITY_HIDDEN", None);
        }

        let mut sources = Sources::new();
        sources.extend(&[
            ("__absvdi2", "absvdi2.c"),
            ("__absvsi2", "absvsi2.c"),
            ("__addvdi3", "addvdi3.c"),
            ("__addvsi3", "addvsi3.c"),
            ("__clzdi2", "clzdi2.c"),
            ("__clzsi2", "clzsi2.c"),
            ("__cmpdi2", "cmpdi2.c"),
            ("__ctzdi2", "ctzdi2.c"),
            ("__ctzsi2", "ctzsi2.c"),
            ("__int_util", "int_util.c"),
            ("__mulvdi3", "mulvdi3.c"),
            ("__mulvsi3", "mulvsi3.c"),
            ("__negdi2", "negdi2.c"),
            ("__negvdi2", "negvdi2.c"),
            ("__negvsi2", "negvsi2.c"),
            ("__paritydi2", "paritydi2.c"),
            ("__paritysi2", "paritysi2.c"),
            ("__popcountdi2", "popcountdi2.c"),
            ("__popcountsi2", "popcountsi2.c"),
            ("__subvdi3", "subvdi3.c"),
            ("__subvsi3", "subvsi3.c"),
            ("__ucmpdi2", "ucmpdi2.c"),
        ]);

        if consider_float_intrinsics {
            sources.extend(&[
                ("__divdc3", "divdc3.c"),
                ("__divsc3", "divsc3.c"),
                ("__divxc3", "divxc3.c"),
                ("__extendhfsf2", "extendhfsf2.c"),
                ("__muldc3", "muldc3.c"),
                ("__mulsc3", "mulsc3.c"),
                ("__mulxc3", "mulxc3.c"),
                ("__negdf2", "negdf2.c"),
                ("__negsf2", "negsf2.c"),
                ("__powixf2", "powixf2.c"),
                ("__truncdfhf2", "truncdfhf2.c"),
                ("__truncsfhf2", "truncsfhf2.c"),
            ]);
        }

        // When compiling in rustbuild (the rust-lang/rust repo) this library
        // also needs to satisfy intrinsics that jemalloc or C in general may
        // need, so include a few more that aren't typically needed by
        // LLVM/Rust.
        if cfg!(feature = "rustbuild") {
            sources.extend(&[("__ffsdi2", "ffsdi2.c")]);
        }

        // On iOS and 32-bit OSX these are all just empty intrinsics, no need to
        // include them.
        if target_os != "ios"
            && target_os != "watchos"
            && (target_vendor != "apple" || target_arch != "x86")
        {
            sources.extend(&[
                ("__absvti2", "absvti2.c"),
                ("__addvti3", "addvti3.c"),
                ("__clzti2", "clzti2.c"),
                ("__cmpti2", "cmpti2.c"),
                ("__ctzti2", "ctzti2.c"),
                ("__ffsti2", "ffsti2.c"),
                ("__mulvti3", "mulvti3.c"),
                ("__negti2", "negti2.c"),
                ("__parityti2", "parityti2.c"),
                ("__popcountti2", "popcountti2.c"),
                ("__subvti3", "subvti3.c"),
                ("__ucmpti2", "ucmpti2.c"),
            ]);

            if consider_float_intrinsics {
                sources.extend(&[("__negvti2", "negvti2.c")]);
            }
        }

        if target_vendor == "apple" {
            sources.extend(&[
                ("atomic_flag_clear", "atomic_flag_clear.c"),
                ("atomic_flag_clear_explicit", "atomic_flag_clear_explicit.c"),
                ("atomic_flag_test_and_set", "atomic_flag_test_and_set.c"),
                (
                    "atomic_flag_test_and_set_explicit",
                    "atomic_flag_test_and_set_explicit.c",
                ),
                ("atomic_signal_fence", "atomic_signal_fence.c"),
                ("atomic_thread_fence", "atomic_thread_fence.c"),
            ]);
        }

        if target_env == "msvc" {
            if target_arch == "x86_64" {
                sources.extend(&[("__floatdixf", "x86_64/floatdixf.c")]);
            }
        } else {
            // None of these seem to be used on x86_64 windows, and they've all
            // got the wrong ABI anyway, so we want to avoid them.
            if target_os != "windows" {
                if target_arch == "x86_64" {
                    sources.extend(&[
                        ("__floatdixf", "x86_64/floatdixf.c"),
                        ("__floatundixf", "x86_64/floatundixf.S"),
                    ]);
                }
            }

            if target_arch == "x86" {
                sources.extend(&[
                    ("__ashldi3", "i386/ashldi3.S"),
                    ("__ashrdi3", "i386/ashrdi3.S"),
                    ("__divdi3", "i386/divdi3.S"),
                    ("__floatdixf", "i386/floatdixf.S"),
                    ("__floatundixf", "i386/floatundixf.S"),
                    ("__lshrdi3", "i386/lshrdi3.S"),
                    ("__moddi3", "i386/moddi3.S"),
                    ("__muldi3", "i386/muldi3.S"),
                    ("__udivdi3", "i386/udivdi3.S"),
                    ("__umoddi3", "i386/umoddi3.S"),
                ]);
            }
        }

        if target_arch == "arm"
            && target_os != "ios"
            && target_os != "watchos"
            && target_env != "msvc"
        {
            sources.extend(&[
                ("__aeabi_div0", "arm/aeabi_div0.c"),
                ("__aeabi_drsub", "arm/aeabi_drsub.c"),
                ("__aeabi_frsub", "arm/aeabi_frsub.c"),
                ("__bswapdi2", "arm/bswapdi2.S"),
                ("__bswapsi2", "arm/bswapsi2.S"),
                ("__clzdi2", "arm/clzdi2.S"),
                ("__clzsi2", "arm/clzsi2.S"),
                ("__divmodsi4", "arm/divmodsi4.S"),
                ("__divsi3", "arm/divsi3.S"),
                ("__modsi3", "arm/modsi3.S"),
                ("__switch16", "arm/switch16.S"),
                ("__switch32", "arm/switch32.S"),
                ("__switch8", "arm/switch8.S"),
                ("__switchu8", "arm/switchu8.S"),
                ("__sync_synchronize", "arm/sync_synchronize.S"),
                ("__udivmodsi4", "arm/udivmodsi4.S"),
                ("__udivsi3", "arm/udivsi3.S"),
                ("__umodsi3", "arm/umodsi3.S"),
            ]);

            if target_os == "freebsd" {
                sources.extend(&[("__clear_cache", "clear_cache.c")]);
            }

            // First of all aeabi_cdcmp and aeabi_cfcmp are never called by LLVM.
            // Second are little-endian only, so build fail on big-endian targets.
            // Temporally workaround: exclude these files for big-endian targets.
            if !llvm_target[0].starts_with("thumbeb") && !llvm_target[0].starts_with("armeb") {
                sources.extend(&[
                    ("__aeabi_cdcmp", "arm/aeabi_cdcmp.S"),
                    ("__aeabi_cdcmpeq_check_nan", "arm/aeabi_cdcmpeq_check_nan.c"),
                    ("__aeabi_cfcmp", "arm/aeabi_cfcmp.S"),
                    ("__aeabi_cfcmpeq_check_nan", "arm/aeabi_cfcmpeq_check_nan.c"),
                ]);
            }
        }

        if llvm_target[0] == "armv7" {
            sources.extend(&[
                ("__sync_fetch_and_add_4", "arm/sync_fetch_and_add_4.S"),
                ("__sync_fetch_and_add_8", "arm/sync_fetch_and_add_8.S"),
                ("__sync_fetch_and_and_4", "arm/sync_fetch_and_and_4.S"),
                ("__sync_fetch_and_and_8", "arm/sync_fetch_and_and_8.S"),
                ("__sync_fetch_and_max_4", "arm/sync_fetch_and_max_4.S"),
                ("__sync_fetch_and_max_8", "arm/sync_fetch_and_max_8.S"),
                ("__sync_fetch_and_min_4", "arm/sync_fetch_and_min_4.S"),
                ("__sync_fetch_and_min_8", "arm/sync_fetch_and_min_8.S"),
                ("__sync_fetch_and_nand_4", "arm/sync_fetch_and_nand_4.S"),
                ("__sync_fetch_and_nand_8", "arm/sync_fetch_and_nand_8.S"),
                ("__sync_fetch_and_or_4", "arm/sync_fetch_and_or_4.S"),
                ("__sync_fetch_and_or_8", "arm/sync_fetch_and_or_8.S"),
                ("__sync_fetch_and_sub_4", "arm/sync_fetch_and_sub_4.S"),
                ("__sync_fetch_and_sub_8", "arm/sync_fetch_and_sub_8.S"),
                ("__sync_fetch_and_umax_4", "arm/sync_fetch_and_umax_4.S"),
                ("__sync_fetch_and_umax_8", "arm/sync_fetch_and_umax_8.S"),
                ("__sync_fetch_and_umin_4", "arm/sync_fetch_and_umin_4.S"),
                ("__sync_fetch_and_umin_8", "arm/sync_fetch_and_umin_8.S"),
                ("__sync_fetch_and_xor_4", "arm/sync_fetch_and_xor_4.S"),
                ("__sync_fetch_and_xor_8", "arm/sync_fetch_and_xor_8.S"),
            ]);
        }

        if llvm_target.last().unwrap().ends_with("eabihf") {
            if !llvm_target[0].starts_with("thumbv7em")
                && !llvm_target[0].starts_with("thumbv8m.main")
            {
                // The FPU option chosen for these architectures in cc-rs, ie:
                //     -mfpu=fpv4-sp-d16 for thumbv7em
                //     -mfpu=fpv5-sp-d16 for thumbv8m.main
                // do not support double precision floating points conversions so the files
                // that include such instructions are not included for these targets.
                sources.extend(&[
                    ("__fixdfsivfp", "arm/fixdfsivfp.S"),
                    ("__fixunsdfsivfp", "arm/fixunsdfsivfp.S"),
                    ("__floatsidfvfp", "arm/floatsidfvfp.S"),
                    ("__floatunssidfvfp", "arm/floatunssidfvfp.S"),
                ]);
            }

            sources.extend(&[
                ("__fixsfsivfp", "arm/fixsfsivfp.S"),
                ("__fixunssfsivfp", "arm/fixunssfsivfp.S"),
                ("__floatsisfvfp", "arm/floatsisfvfp.S"),
                ("__floatunssisfvfp", "arm/floatunssisfvfp.S"),
                ("__floatunssisfvfp", "arm/floatunssisfvfp.S"),
                ("__restore_vfp_d8_d15_regs", "arm/restore_vfp_d8_d15_regs.S"),
                ("__save_vfp_d8_d15_regs", "arm/save_vfp_d8_d15_regs.S"),
                ("__negdf2vfp", "arm/negdf2vfp.S"),
                ("__negsf2vfp", "arm/negsf2vfp.S"),
            ]);
        }

        if target_arch == "aarch64" && consider_float_intrinsics {
            sources.extend(&[
                ("__comparetf2", "comparetf2.c"),
                ("__extenddftf2", "extenddftf2.c"),
                ("__extendsftf2", "extendsftf2.c"),
                ("__fixtfdi", "fixtfdi.c"),
                ("__fixtfsi", "fixtfsi.c"),
                ("__fixtfti", "fixtfti.c"),
                ("__fixunstfdi", "fixunstfdi.c"),
                ("__fixunstfsi", "fixunstfsi.c"),
                ("__fixunstfti", "fixunstfti.c"),
                ("__floatditf", "floatditf.c"),
                ("__floatsitf", "floatsitf.c"),
                ("__floatunditf", "floatunditf.c"),
                ("__floatunsitf", "floatunsitf.c"),
                ("__trunctfdf2", "trunctfdf2.c"),
                ("__trunctfsf2", "trunctfsf2.c"),
                ("__addtf3", "addtf3.c"),
                ("__multf3", "multf3.c"),
                ("__subtf3", "subtf3.c"),
                ("__divtf3", "divtf3.c"),
                ("__powitf2", "powitf2.c"),
                ("__fe_getround", "fp_mode.c"),
                ("__fe_raise_inexact", "fp_mode.c"),
            ]);

            if target_os != "windows" {
                sources.extend(&[("__multc3", "multc3.c")]);
            }
        }

        if target_arch == "mips" {
            sources.extend(&[("__bswapsi2", "bswapsi2.c")]);
        }

        if target_arch == "mips64" {
            sources.extend(&[
                ("__extenddftf2", "extenddftf2.c"),
                ("__netf2", "comparetf2.c"),
                ("__addtf3", "addtf3.c"),
                ("__multf3", "multf3.c"),
                ("__subtf3", "subtf3.c"),
                ("__fixtfsi", "fixtfsi.c"),
                ("__floatsitf", "floatsitf.c"),
                ("__fixunstfsi", "fixunstfsi.c"),
                ("__floatunsitf", "floatunsitf.c"),
                ("__fe_getround", "fp_mode.c"),
                ("__divtf3", "divtf3.c"),
                ("__trunctfdf2", "trunctfdf2.c"),
            ]);
        }

        // Remove the assembly implementations that won't compile for the target
        if llvm_target[0] == "thumbv6m" || llvm_target[0] == "thumbv8m.base" {
            let mut to_remove = Vec::new();
            for (k, v) in sources.map.iter() {
                if v.ends_with(".S") {
                    to_remove.push(*k);
                }
            }
            sources.remove(&to_remove);

            // But use some generic implementations where possible
            sources.extend(&[("__clzdi2", "clzdi2.c"), ("__clzsi2", "clzsi2.c")])
        }

        if llvm_target[0] == "thumbv7m" || llvm_target[0] == "thumbv7em" {
            sources.remove(&["__aeabi_cdcmp", "__aeabi_cfcmp"]);
        }

        // Android uses emulated TLS so we need a runtime support function.
        if target_os == "android" {
            sources.extend(&[("__emutls_get_address", "emutls.c")]);

            // Work around a bug in the NDK headers (fixed in
            // https://r.android.com/2038949 which will be released in a future
            // NDK version) by providing a definition of LONG_BIT.
            cfg.define("LONG_BIT", "(8 * sizeof(long))");
        }

        // When compiling the C code we require the user to tell us where the
        // source code is, and this is largely done so when we're compiling as
        // part of rust-lang/rust we can use the same llvm-project repository as
        // rust-lang/rust.
        let root = match env::var_os("RUST_COMPILER_RT_ROOT") {
            Some(s) => PathBuf::from(s),
            None => panic!("RUST_COMPILER_RT_ROOT is not set"),
        };
        if !root.exists() {
            panic!("RUST_COMPILER_RT_ROOT={} does not exist", root.display());
        }

        // Support deterministic builds by remapping the __FILE__ prefix if the
        // compiler supports it.  This fixes the nondeterminism caused by the
        // use of that macro in lib/builtins/int_util.h in compiler-rt.
        cfg.flag_if_supported(&format!("-ffile-prefix-map={}=.", root.display()));

        // Include out-of-line atomics for aarch64, which are all generated by supplying different
        // sets of flags to the same source file.
        // Note: Out-of-line aarch64 atomics are not supported by the msvc toolchain (#430).
        let src_dir = root.join("lib/builtins");
        if target_arch == "aarch64" && target_env != "msvc" {
            // See below for why we're building these as separate libraries.
            build_aarch64_out_of_line_atomics_libraries(&src_dir, cfg);

            // Some run-time CPU feature detection is necessary, as well.
            sources.extend(&[("__aarch64_have_lse_atomics", "cpu_model.c")]);
        }

        let mut added_sources = HashSet::new();
        for (sym, src) in sources.map.iter() {
            let src = src_dir.join(src);
            if added_sources.insert(src.clone()) {
                cfg.file(&src);
                println!("cargo:rerun-if-changed={}", src.display());
            }
            println!("cargo:rustc-cfg={}=\"optimized-c\"", sym);
        }

        cfg.compile("libcompiler-rt.a");
    }

    fn build_aarch64_out_of_line_atomics_libraries(builtins_dir: &Path, cfg: &mut cc::Build) {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let outlined_atomics_file = builtins_dir.join("aarch64/lse.S");
        println!("cargo:rerun-if-changed={}", outlined_atomics_file.display());

        cfg.include(&builtins_dir);

        for instruction_type in &["cas", "swp", "ldadd", "ldclr", "ldeor", "ldset"] {
            for size in &[1, 2, 4, 8, 16] {
                if *size == 16 && *instruction_type != "cas" {
                    continue;
                }

                for (model_number, model_name) in
                    &[(1, "relax"), (2, "acq"), (3, "rel"), (4, "acq_rel")]
                {
                    // The original compiler-rt build system compiles the same
                    // source file multiple times with different compiler
                    // options. Here we do something slightly different: we
                    // create multiple .S files with the proper #defines and
                    // then include the original file.
                    //
                    // This is needed because the cc crate doesn't allow us to
                    // override the name of object files and libtool requires
                    // all objects in an archive to have unique names.
                    let path =
                        out_dir.join(format!("lse_{}{}_{}.S", instruction_type, size, model_name));
                    let mut file = File::create(&path).unwrap();
                    writeln!(file, "#define L_{}", instruction_type).unwrap();
                    writeln!(file, "#define SIZE {}", size).unwrap();
                    writeln!(file, "#define MODEL {}", model_number).unwrap();
                    writeln!(
                        file,
                        "#include \"{}\"",
                        outlined_atomics_file.canonicalize().unwrap().display()
                    )
                    .unwrap();
                    drop(file);
                    cfg.file(path);

                    let sym = format!("__aarch64_{}{}_{}", instruction_type, size, model_name);
                    println!("cargo:rustc-cfg={}=\"optimized-c\"", sym);
                }
            }
        }
    }
}
========== build.rs from cortex-m-0.7.4 ============================================================
use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let target = env::var("TARGET").unwrap();
    let host_triple = env::var("HOST").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let name = env::var("CARGO_PKG_NAME").unwrap();

    if host_triple == target {
        println!("cargo:rustc-cfg=native");
    }

    if target.starts_with("thumb") {
        let suffix = if env::var_os("CARGO_FEATURE_LINKER_PLUGIN_LTO").is_some() {
            "-lto"
        } else {
            ""
        };

        fs::copy(
            format!("bin/{}{}.a", target, suffix),
            out_dir.join(format!("lib{}.a", name)),
        )
        .unwrap();

        println!("cargo:rustc-link-lib=static={}", name);
        println!("cargo:rustc-link-search={}", out_dir.display());
    }

    if target.starts_with("thumbv6m-") {
        println!("cargo:rustc-cfg=cortex_m");
        println!("cargo:rustc-cfg=armv6m");
    } else if target.starts_with("thumbv7m-") {
        println!("cargo:rustc-cfg=cortex_m");
        println!("cargo:rustc-cfg=armv7m");
    } else if target.starts_with("thumbv7em-") {
        println!("cargo:rustc-cfg=cortex_m");
        println!("cargo:rustc-cfg=armv7m");
        println!("cargo:rustc-cfg=armv7em"); // (not currently used)
    } else if target.starts_with("thumbv8m.base") {
        println!("cargo:rustc-cfg=cortex_m");
        println!("cargo:rustc-cfg=armv8m");
        println!("cargo:rustc-cfg=armv8m_base");
    } else if target.starts_with("thumbv8m.main") {
        println!("cargo:rustc-cfg=cortex_m");
        println!("cargo:rustc-cfg=armv8m");
        println!("cargo:rustc-cfg=armv8m_main");
    }

    if target.ends_with("-eabihf") {
        println!("cargo:rustc-cfg=has_fpu");
    }
}
========== build.rs from crc-1.8.1 ============================================================
extern crate build_const;

include!("src/util.rs");

#[allow(non_snake_case)]
fn create_constants() {
    let mut crc16 = build_const::ConstWriter::for_build("crc16_constants")
        .unwrap()
        .finish_dependencies();
    let X25: u16 = 0x8408;
    crc16.add_value("X25", "u16", X25);
    crc16.add_array("X25_TABLE", "u16", &make_table_crc16(X25));

    let USB: u16 = 0xa001;
    crc16.add_value("USB", "u16", USB);
    crc16.add_array("USB_TABLE", "u16", &make_table_crc16(USB));

    crc16.finish();

    let mut crc32 = build_const::ConstWriter::for_build("crc32_constants")
        .unwrap()
        .finish_dependencies();
    let CASTAGNOLI: u32 = 0x82f63b78;
    crc32.add_value("CASTAGNOLI", "u32", CASTAGNOLI);
    crc32.add_array("CASTAGNOLI_TABLE", "u32", &make_table_crc32(CASTAGNOLI));

    let IEEE: u32 = 0xedb88320;
    crc32.add_value("IEEE", "u32", IEEE);
    crc32.add_array("IEEE_TABLE", "u32", &make_table_crc32(IEEE));

    let KOOPMAN: u32 = 0xeb31d82e;
    crc32.add_value("KOOPMAN", "u32", KOOPMAN);
    crc32.add_array("KOOPMAN_TABLE", "u32", &make_table_crc32(KOOPMAN));

    crc32.finish();

    let mut crc64 = build_const::ConstWriter::for_build("crc64_constants")
        .unwrap()
        .finish_dependencies();

    let ECMA: u64 = 0xc96c5795d7870f42;
    crc64.add_value("ECMA", "u64", ECMA);
    crc64.add_array("ECMA_TABLE", "u64", &make_table_crc64(ECMA));

    let ISO: u64 = 0xd800000000000000;
    crc64.add_value("ISO", "u64", ISO);
    crc64.add_array("ISO_TABLE", "u64", &make_table_crc64(ISO));

    crc64.finish();
}

fn main() {
    create_constants();
}
========== build.rs from crc32fast-1.3.2 ============================================================
use std::env;
use std::process::Command;
use std::str;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let minor = match rustc_minor_version() {
        Some(n) => n,
        None => return,
    };

    if minor >= 27 {
        println!("cargo:rustc-cfg=crc32fast_stdarchx86");
    }
}

fn rustc_minor_version() -> Option<u32> {
    macro_rules! otry {
        ($e:expr) => {
            match $e {
                Some(e) => e,
                None => return None,
            }
        };
    }
    let rustc = otry!(env::var_os("RUSTC"));
    let output = otry!(Command::new(rustc).arg("--version").output().ok());
    let version = otry!(str::from_utf8(&output.stdout).ok());
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    otry!(pieces.next()).parse().ok()
}
========== build.rs from critical-section-0.2.7 ============================================================
use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();

    if target.starts_with("thumbv") {
        println!("cargo:rustc-cfg=cortex_m");
    }
}
========== build.rs from crossbeam-epoch-0.9.8 ============================================================
// The rustc-cfg listed below are considered public API, but it is *unstable*
// and outside of the normal semver guarantees:
//
// - `crossbeam_no_atomic_cas`
//      Assume the target does *not* support atomic CAS operations.
//      This is usually detected automatically by the build script, but you may
//      need to enable it manually when building for custom targets or using
//      non-cargo build systems that don't run the build script.
//
// With the exceptions mentioned above, the rustc-cfg emitted by the build
// script are *not* public API.

#![warn(rust_2018_idioms)]

use std::env;

include!("no_atomic.rs");

fn main() {
    let target = match env::var("TARGET") {
        Ok(target) => target,
        Err(e) => {
            println!(
                "cargo:warning={}: unable to get TARGET environment variable: {}",
                env!("CARGO_PKG_NAME"),
                e
            );
            return;
        }
    };

    let cfg = match autocfg::AutoCfg::new() {
        Ok(cfg) => cfg,
        Err(e) => {
            println!(
                "cargo:warning={}: unable to determine rustc version: {}",
                env!("CARGO_PKG_NAME"),
                e
            );
            return;
        }
    };

    // Note that this is `no_*`, not `has_*`. This allows treating
    // `cfg(target_has_atomic = "ptr")` as true when the build script doesn't
    // run. This is needed for compatibility with non-cargo build systems that
    // don't run the build script.
    if NO_ATOMIC_CAS.contains(&&*target) {
        println!("cargo:rustc-cfg=crossbeam_no_atomic_cas");
    }

    if cfg.probe_rustc_version(1, 61) {
        // TODO: invert cfg once Rust 1.61 became stable.
        println!("cargo:rustc-cfg=crossbeam_const_fn_trait_bound");
    }

    println!("cargo:rerun-if-changed=no_atomic.rs");
}
========== build.rs from crossbeam-queue-0.3.5 ============================================================
// The rustc-cfg listed below are considered public API, but it is *unstable*
// and outside of the normal semver guarantees:
//
// - `crossbeam_no_atomic_cas`
//      Assume the target does *not* support atomic CAS operations.
//      This is usually detected automatically by the build script, but you may
//      need to enable it manually when building for custom targets or using
//      non-cargo build systems that don't run the build script.
//
// With the exceptions mentioned above, the rustc-cfg emitted by the build
// script are *not* public API.

#![warn(rust_2018_idioms)]

use std::env;

include!("no_atomic.rs");

fn main() {
    let target = match env::var("TARGET") {
        Ok(target) => target,
        Err(e) => {
            println!(
                "cargo:warning={}: unable to get TARGET environment variable: {}",
                env!("CARGO_PKG_NAME"),
                e
            );
            return;
        }
    };

    // Note that this is `no_*`, not `has_*`. This allows treating
    // `cfg(target_has_atomic = "ptr")` as true when the build script doesn't
    // run. This is needed for compatibility with non-cargo build systems that
    // don't run the build script.
    if NO_ATOMIC_CAS.contains(&&*target) {
        println!("cargo:rustc-cfg=crossbeam_no_atomic_cas");
    }

    println!("cargo:rerun-if-changed=no_atomic.rs");
}
========== build.rs from crossbeam-utils-0.8.8 ============================================================
// The rustc-cfg listed below are considered public API, but it is *unstable*
// and outside of the normal semver guarantees:
//
// - `crossbeam_no_atomic_cas`
//      Assume the target does *not* support atomic CAS operations.
//      This is usually detected automatically by the build script, but you may
//      need to enable it manually when building for custom targets or using
//      non-cargo build systems that don't run the build script.
//
// - `crossbeam_no_atomic`
//      Assume the target does *not* support any atomic operations.
//      This is usually detected automatically by the build script, but you may
//      need to enable it manually when building for custom targets or using
//      non-cargo build systems that don't run the build script.
//
// - `crossbeam_no_atomic_64`
//      Assume the target does *not* support AtomicU64/AtomicI64.
//      This is usually detected automatically by the build script, but you may
//      need to enable it manually when building for custom targets or using
//      non-cargo build systems that don't run the build script.
//
// With the exceptions mentioned above, the rustc-cfg emitted by the build
// script are *not* public API.

#![warn(rust_2018_idioms)]

use std::env;

include!("no_atomic.rs");

fn main() {
    let target = match env::var("TARGET") {
        Ok(target) => target,
        Err(e) => {
            println!(
                "cargo:warning={}: unable to get TARGET environment variable: {}",
                env!("CARGO_PKG_NAME"),
                e
            );
            return;
        }
    };

    // Note that this is `no_*`, not `has_*`. This allows treating
    // `cfg(target_has_atomic = "ptr")` as true when the build script doesn't
    // run. This is needed for compatibility with non-cargo build systems that
    // don't run the build script.
    if NO_ATOMIC_CAS.contains(&&*target) {
        println!("cargo:rustc-cfg=crossbeam_no_atomic_cas");
    }
    if NO_ATOMIC.contains(&&*target) {
        println!("cargo:rustc-cfg=crossbeam_no_atomic");
        println!("cargo:rustc-cfg=crossbeam_no_atomic_64");
    } else if NO_ATOMIC_64.contains(&&*target) {
        println!("cargo:rustc-cfg=crossbeam_no_atomic_64");
    } else {
        // Otherwise, assuming `"max-atomic-width" == 64` or `"max-atomic-width" == 128`.
    }

    println!("cargo:rerun-if-changed=no_atomic.rs");
}
========== build.rs from crunchy-0.2.2 ============================================================
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

const LOWER_LIMIT: usize = 16;

fn main() {
    let limit = if cfg!(feature="limit_2048") {
        2048
    } else if cfg!(feature="limit_1024") {
        1024
    } else if cfg!(feature="limit_512") {
        512
    } else if cfg!(feature="limit_256") {
        256
    } else if cfg!(feature="limit_128") {
        128
    } else {
        64
    };

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("lib.rs");
    let mut f = File::create(&dest_path).unwrap();

    let mut output = String::new();

    output.push_str(r#"
/// Unroll the given for loop
///
/// Example:
///
/// ```ignore
/// unroll! {
///   for i in 0..5 {
///     println!("Iteration {}", i);
///   }
/// }
/// ```
///
/// will expand into:
///
/// ```ignore
/// { println!("Iteration {}", 0); }
/// { println!("Iteration {}", 1); }
/// { println!("Iteration {}", 2); }
/// { println!("Iteration {}", 3); }
/// { println!("Iteration {}", 4); }
/// ```
#[macro_export]
macro_rules! unroll {
    (for $v:ident in 0..0 $c:block) => {};

    (for $v:ident < $max:tt in ($start:tt..$end:tt).step_by($val:expr) {$($c:tt)*}) => {
        {
            let step = $val;
            let start = $start;
            let end = start + ($end - start) / step;
            unroll! {
                for val < $max in start..end {
                    let $v: usize = ((val - start) * step) + start;

                    $($c)*
                }
            }
        }
    };

    (for $v:ident in ($start:tt..$end:tt).step_by($val:expr) {$($c:tt)*}) => {
        unroll! {
            for $v < $end in ($start..$end).step_by($val) {$($c)*}
        }
    };

    (for $v:ident in ($start:tt..$end:tt) {$($c:tt)*}) => {
        unroll!{
            for $v in $start..$end {$($c)*}
        }
    };

    (for $v:ident in $start:tt..$end:tt {$($c:tt)*}) => {
        #[allow(non_upper_case_globals)]
        #[allow(unused_comparisons)]
        {
            unroll!(@$v, 0, $end, {
                    if $v >= $start {$($c)*}
                }
            );
        }
    };

    (for $v:ident < $max:tt in $start:tt..$end:tt $c:block) => {
        #[allow(non_upper_case_globals)]
        {
            let range = $start..$end;
            assert!(
                $max >= range.end,
                "`{}` out of range `{:?}`",
                stringify!($max),
                range,
            );
            unroll!(
                @$v,
                0,
                $max,
                {
                    if $v >= range.start && $v < range.end {
                        $c
                    }
                }
            );
        }
    };

    (for $v:ident in 0..$end:tt {$($statement:tt)*}) => {
        #[allow(non_upper_case_globals)]
        { unroll!(@$v, 0, $end, {$($statement)*}); }
    };

"#);

    for i in 0..limit + 1 {
        output.push_str(format!("    (@$v:ident, $a:expr, {}, $c:block) => {{\n", i).as_str());

        if i <= LOWER_LIMIT {
            output.push_str(format!("        {{ const $v: usize = $a; $c }}\n").as_str());

            for a in 1..i {
                output.push_str(format!("        {{ const $v: usize = $a + {}; $c }}\n", a).as_str());
            }
        } else {
            let half = i / 2;

            if i % 2 == 0 {
                output.push_str(format!("        unroll!(@$v, $a, {0}, $c);\n", half).as_str());
                output.push_str(format!("        unroll!(@$v, $a + {0}, {0}, $c);\n", half).as_str());
            } else {
                if half > 1 {
                    output.push_str(format!("        unroll!(@$v, $a, {}, $c);\n", i - 1).as_str())
                }

                output.push_str(format!("        {{ const $v: usize = $a + {}; $c }}\n", i - 1).as_str());
            }
        }

        output.push_str("    };\n\n");
    }

    output.push_str("}\n\n");

    output.push_str(format!(r#"
#[cfg(all(test, feature = "std"))]
mod tests {{
    #[test]
    fn invalid_range() {{
        let mut a: Vec<usize> = vec![];
        unroll! {{
                for i in (5..4) {{
                    a.push(i);
                }}
            }}
        assert_eq!(a, vec![]);
    }}

    #[test]
    fn start_at_one_with_step() {{
        let mut a: Vec<usize> = vec![];
        unroll! {{
                for i in (2..4).step_by(1) {{
                    a.push(i);
                }}
            }}
        assert_eq!(a, vec![2, 3]);
    }}

    #[test]
    fn start_at_one() {{
        let mut a: Vec<usize> = vec![];
        unroll! {{
                for i in 1..4 {{
                    a.push(i);
                }}
            }}
        assert_eq!(a, vec![1, 2, 3]);
    }}

    #[test]
    fn test_all() {{
        {{
            let a: Vec<usize> = vec![];
            unroll! {{
                for i in 0..0 {{
                    a.push(i);
                }}
            }}
            assert_eq!(a, (0..0).collect::<Vec<usize>>());
        }}
        {{
            let mut a: Vec<usize> = vec![];
            unroll! {{
                for i in 0..1 {{
                    a.push(i);
                }}
            }}
            assert_eq!(a, (0..1).collect::<Vec<usize>>());
        }}
        {{
            let mut a: Vec<usize> = vec![];
            unroll! {{
                for i in 0..{0} {{
                    a.push(i);
                }}
            }}
            assert_eq!(a, (0..{0}).collect::<Vec<usize>>());
        }}
        {{
            let mut a: Vec<usize> = vec![];
            let start = {0} / 4;
            let end = start * 3;
            unroll! {{
                for i < {0} in start..end {{
                    a.push(i);
                }}
            }}
            assert_eq!(a, (start..end).collect::<Vec<usize>>());
        }}
        {{
            let mut a: Vec<usize> = vec![];
            unroll! {{
                for i in (0..{0}).step_by(2) {{
                    a.push(i);
                }}
            }}
            assert_eq!(a, (0..{0} / 2).map(|x| x * 2).collect::<Vec<usize>>());
        }}
        {{
            let mut a: Vec<usize> = vec![];
            let start = {0} / 4;
            let end = start * 3;
            unroll! {{
                for i < {0} in (start..end).step_by(2) {{
                    a.push(i);
                }}
            }}
            assert_eq!(a, (start..end).filter(|x| x % 2 == 0).collect::<Vec<usize>>());
        }}
    }}
}}
"#, limit).as_str());

    f.write_all(output.as_bytes()).unwrap();
}
========== build.rs from defmt-0.3.5 ============================================================
use std::{env, error::Error, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    // Put the linker script somewhere the linker can find it
    let out = &PathBuf::from(env::var("OUT_DIR")?);
    let linker_script = fs::read_to_string("defmt.x.in")?;
    fs::write(out.join("defmt.x"), linker_script)?;
    println!("cargo:rustc-link-search={}", out.display());
    let target = env::var("TARGET")?;

    // `"atomic-cas": false` in `--print target-spec-json`
    // last updated: rust 1.48.0
    match &target[..] {
        "avr-gnu-base"
        | "msp430-none-elf"
        | "riscv32i-unknown-none-elf"
        | "riscv32imc-unknown-none-elf"
        | "thumbv4t-none-eabi"
        | "thumbv6m-none-eabi" => {
            println!("cargo:rustc-cfg=no_cas");
        }
        _ => {}
    }
    Ok(())
}
========== build.rs from defmt-macros-0.3.6 ============================================================
fn main() {
    println!("cargo:rerun-if-env-changed=DEFMT_LOG");
}
========== build.rs from errno-dragonfly-0.1.2 ============================================================
fn main() {
    cc::Build::new().file("src/errno.c").compile("liberrno.a");
}
========== build.rs from eyre-0.6.8 ============================================================
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::str;

// This code exercises the surface area that we expect of the std Backtrace
// type. If the current toolchain is able to compile it, we go ahead and use
// backtrace in eyre.
const BACKTRACE_PROBE: &str = r#"
    #![feature(backtrace)]
    #![allow(dead_code)]

    use std::backtrace::{Backtrace, BacktraceStatus};
    use std::error::Error;
    use std::fmt::{self, Display};

    #[derive(Debug)]
    struct E;

    impl Display for E {
        fn fmt(&self, _formatter: &mut fmt::Formatter) -> fmt::Result {
            unimplemented!()
        }
    }

    impl Error for E {
        fn backtrace(&self) -> Option<&Backtrace> {
            let backtrace = Backtrace::capture();
            match backtrace.status() {
                BacktraceStatus::Captured | BacktraceStatus::Disabled | _ => {}
            }
            unimplemented!()
        }
    }
"#;

const TRACK_CALLER_PROBE: &str = r#"
    #![allow(dead_code)]

    #[track_caller]
    fn foo() {
        let _location = std::panic::Location::caller();
    }
"#;

fn main() {
    match compile_probe(BACKTRACE_PROBE) {
        Some(status) if status.success() => println!("cargo:rustc-cfg=backtrace"),
        _ => {}
    }

    match compile_probe(TRACK_CALLER_PROBE) {
        Some(status) if status.success() => println!("cargo:rustc-cfg=track_caller"),
        _ => {}
    }

    let rustc = match rustc_minor_version() {
        Some(rustc) => rustc,
        None => return,
    };

    if rustc < 52 {
        println!("cargo:rustc-cfg=eyre_no_fmt_arguments_as_str");
    }

    if rustc < 58 {
        println!("cargo:rustc-cfg=eyre_no_fmt_args_capture");
    }
}

fn compile_probe(probe: &str) -> Option<ExitStatus> {
    let rustc = env::var_os("RUSTC")?;
    let out_dir = env::var_os("OUT_DIR")?;
    let probefile = Path::new(&out_dir).join("probe.rs");
    fs::write(&probefile, probe).ok()?;
    Command::new(rustc)
        .arg("--edition=2018")
        .arg("--crate-name=eyre_build")
        .arg("--crate-type=lib")
        .arg("--emit=metadata")
        .arg("--out-dir")
        .arg(out_dir)
        .arg(probefile)
        .status()
        .ok()
}

fn rustc_minor_version() -> Option<u32> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    pieces.next()?.parse().ok()
}
========== build.rs from futures-channel-0.3.21 ============================================================
// The rustc-cfg listed below are considered public API, but it is *unstable*
// and outside of the normal semver guarantees:
//
// - `futures_no_atomic_cas`
//      Assume the target does *not* support atomic CAS operations.
//      This is usually detected automatically by the build script, but you may
//      need to enable it manually when building for custom targets or using
//      non-cargo build systems that don't run the build script.
//
// With the exceptions mentioned above, the rustc-cfg emitted by the build
// script are *not* public API.

#![warn(rust_2018_idioms, single_use_lifetimes)]

use std::env;

include!("no_atomic_cas.rs");

fn main() {
    let target = match env::var("TARGET") {
        Ok(target) => target,
        Err(e) => {
            println!(
                "cargo:warning={}: unable to get TARGET environment variable: {}",
                env!("CARGO_PKG_NAME"),
                e
            );
            return;
        }
    };

    // Note that this is `no_*`, not `has_*`. This allows treating
    // `cfg(target_has_atomic = "ptr")` as true when the build script doesn't
    // run. This is needed for compatibility with non-cargo build systems that
    // don't run the build script.
    if NO_ATOMIC_CAS.contains(&&*target) {
        println!("cargo:rustc-cfg=futures_no_atomic_cas");
    }

    println!("cargo:rerun-if-changed=no_atomic_cas.rs");
}
========== build.rs from futures-core-0.3.21 ============================================================
// The rustc-cfg listed below are considered public API, but it is *unstable*
// and outside of the normal semver guarantees:
//
// - `futures_no_atomic_cas`
//      Assume the target does *not* support atomic CAS operations.
//      This is usually detected automatically by the build script, but you may
//      need to enable it manually when building for custom targets or using
//      non-cargo build systems that don't run the build script.
//
// With the exceptions mentioned above, the rustc-cfg emitted by the build
// script are *not* public API.

#![warn(rust_2018_idioms, single_use_lifetimes)]

use std::env;

include!("no_atomic_cas.rs");

fn main() {
    let target = match env::var("TARGET") {
        Ok(target) => target,
        Err(e) => {
            println!(
                "cargo:warning={}: unable to get TARGET environment variable: {}",
                env!("CARGO_PKG_NAME"),
                e
            );
            return;
        }
    };

    // Note that this is `no_*`, not `has_*`. This allows treating
    // `cfg(target_has_atomic = "ptr")` as true when the build script doesn't
    // run. This is needed for compatibility with non-cargo build systems that
    // don't run the build script.
    if NO_ATOMIC_CAS.contains(&&*target) {
        println!("cargo:rustc-cfg=futures_no_atomic_cas");
    }

    println!("cargo:rerun-if-changed=no_atomic_cas.rs");
}
========== build.rs from futures-task-0.3.21 ============================================================
// The rustc-cfg listed below are considered public API, but it is *unstable*
// and outside of the normal semver guarantees:
//
// - `futures_no_atomic_cas`
//      Assume the target does *not* support atomic CAS operations.
//      This is usually detected automatically by the build script, but you may
//      need to enable it manually when building for custom targets or using
//      non-cargo build systems that don't run the build script.
//
// With the exceptions mentioned above, the rustc-cfg emitted by the build
// script are *not* public API.

#![warn(rust_2018_idioms, single_use_lifetimes)]

use std::env;

include!("no_atomic_cas.rs");

fn main() {
    let target = match env::var("TARGET") {
        Ok(target) => target,
        Err(e) => {
            println!(
                "cargo:warning={}: unable to get TARGET environment variable: {}",
                env!("CARGO_PKG_NAME"),
                e
            );
            return;
        }
    };

    // Note that this is `no_*`, not `has_*`. This allows treating
    // `cfg(target_has_atomic = "ptr")` as true when the build script doesn't
    // run. This is needed for compatibility with non-cargo build systems that
    // don't run the build script.
    if NO_ATOMIC_CAS.contains(&&*target) {
        println!("cargo:rustc-cfg=futures_no_atomic_cas");
    }

    println!("cargo:rerun-if-changed=no_atomic_cas.rs");
}
========== build.rs from futures-util-0.3.21 ============================================================
// The rustc-cfg listed below are considered public API, but it is *unstable*
// and outside of the normal semver guarantees:
//
// - `futures_no_atomic_cas`
//      Assume the target does *not* support atomic CAS operations.
//      This is usually detected automatically by the build script, but you may
//      need to enable it manually when building for custom targets or using
//      non-cargo build systems that don't run the build script.
//
// With the exceptions mentioned above, the rustc-cfg emitted by the build
// script are *not* public API.

#![warn(rust_2018_idioms, single_use_lifetimes)]

use std::env;

include!("no_atomic_cas.rs");

fn main() {
    let target = match env::var("TARGET") {
        Ok(target) => target,
        Err(e) => {
            println!(
                "cargo:warning={}: unable to get TARGET environment variable: {}",
                env!("CARGO_PKG_NAME"),
                e
            );
            return;
        }
    };

    // Note that this is `no_*`, not `has_*`. This allows treating
    // `cfg(target_has_atomic = "ptr")` as true when the build script doesn't
    // run. This is needed for compatibility with non-cargo build systems that
    // don't run the build script.
    if NO_ATOMIC_CAS.contains(&&*target) {
        println!("cargo:rustc-cfg=futures_no_atomic_cas");
    }

    println!("cargo:rerun-if-changed=no_atomic_cas.rs");
}
========== build.rs from generic-array-0.14.5 ============================================================
fn main() {
    if version_check::is_min_version("1.41.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=relaxed_coherence");
    }
}
========== build.rs from getrandom-0.1.16 ============================================================
#![deny(warnings)]

use std::env;

fn main() {
    let target = env::var("TARGET").expect("TARGET was not set");
    if target.contains("-uwp-windows-") {
        // for BCryptGenRandom
        println!("cargo:rustc-link-lib=bcrypt");
        // to work around unavailability of `target_vendor` on Rust 1.33
        println!("cargo:rustc-cfg=getrandom_uwp");
    } else if target.contains("windows") {
        // for RtlGenRandom (aka SystemFunction036)
        println!("cargo:rustc-link-lib=advapi32");
    } else if target.contains("apple-ios") {
        // for SecRandomCopyBytes and kSecRandomDefault
        println!("cargo:rustc-link-lib=framework=Security");
    }
}
========== build.rs from heapless-0.7.13 ============================================================
#![deny(warnings)]

use std::{env, error::Error};

use rustc_version::Channel;

fn main() -> Result<(), Box<dyn Error>> {
    let target = env::var("TARGET")?;

    if target.starts_with("thumbv6m-") {
        println!("cargo:rustc-cfg=armv6m");
    } else if target.starts_with("thumbv7m-") {
        println!("cargo:rustc-cfg=armv7m");
    } else if target.starts_with("thumbv7em-") {
        println!("cargo:rustc-cfg=armv7m");
    } else if target.starts_with("armv7r-") | target.starts_with("armebv7r-") {
        println!("cargo:rustc-cfg=armv7r");
    } else if target.starts_with("thumbv8m.base") {
        println!("cargo:rustc-cfg=armv8m_base");
    } else if target.starts_with("thumbv8m.main") {
        println!("cargo:rustc-cfg=armv8m_main");
    } else if target.starts_with("armv7-") | target.starts_with("armv7a-") {
        println!("cargo:rustc-cfg=armv7a");
    }

    // built-in targets with no atomic / CAS support as of nightly-2022-01-13
    // AND not supported by the atomic-polyfill crate
    // see the `no-atomics.sh` / `no-cas.sh` script sitting next to this file
    match &target[..] {
        "avr-unknown-gnu-atmega328"
        | "bpfeb-unknown-none"
        | "bpfel-unknown-none"
        | "msp430-none-elf"
        // | "riscv32i-unknown-none-elf"    // supported by atomic-polyfill
        // | "riscv32imc-unknown-none-elf"  // supported by atomic-polyfill
        | "thumbv4t-none-eabi"
        // | "thumbv6m-none-eabi"           // supported by atomic-polyfill
         => {}

        _ => {
            println!("cargo:rustc-cfg=has_cas");
        }
    };

    match &target[..] {
        "avr-unknown-gnu-atmega328"
        | "msp430-none-elf"
        // | "riscv32i-unknown-none-elf"    // supported by atomic-polyfill
        // | "riscv32imc-unknown-none-elf"  // supported by atomic-polyfill
        => {}

        _ => {
            println!("cargo:rustc-cfg=has_atomics");
        }
    };

    // Let the code know if it should use atomic-polyfill or not, and what aspects
    // of polyfill it requires
    match &target[..] {
        "riscv32i-unknown-none-elf" | "riscv32imc-unknown-none-elf" => {
            println!("cargo:rustc-cfg=full_atomic_polyfill");
            println!("cargo:rustc-cfg=cas_atomic_polyfill");
        }

        "thumbv6m-none-eabi" => {
            println!("cargo:rustc-cfg=cas_atomic_polyfill");
        }
        _ => {}
    }

    if !matches!(
        rustc_version::version_meta().unwrap().channel,
        Channel::Stable | Channel::Beta
    ) {
        println!("cargo:rustc-cfg=unstable_channel");
    }

    Ok(())
}
========== build.rs from hidapi-1.4.1 ============================================================
// **************************************************************************
// Copyright (c) 2015 Roland Ruckerbauer All Rights Reserved.
//
// This file is part of hidapi_rust.
//
// hidapi_rust is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// hidapi_rust is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with hidapi_rust.  If not, see <http://www.gnu.org/licenses/>.
// *************************************************************************

extern crate cc;
extern crate pkg_config;

use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();

    if target.contains("linux") {
        compile_linux();
    } else if target.contains("windows") {
        compile_windows();
    } else if target.contains("darwin") {
        compile_macos();
    } else if target.contains("freebsd") {
        compile_freebsd();
    } else if target.contains("openbsd") {
        compile_openbsd();
    } else if target.contains("illumos") {
        compile_illumos();
    } else {
        panic!("Unsupported target os for hidapi-rs");
    }
}

fn compile_linux() {
    // First check the features enabled for the crate.
    // Only one linux backend should be enabled at a time.

    let avail_backends: [(&'static str, Box<dyn Fn()>); 4] = [
        (
            "LINUX_STATIC_HIDRAW",
            Box::new(|| {
                let mut config = cc::Build::new();
                config
                    .file("etc/hidapi/linux/hid.c")
                    .include("etc/hidapi/hidapi");
                pkg_config::probe_library("libudev").expect("Unable to find libudev");
                config.compile("libhidapi.a");
            }),
        ),
        (
            "LINUX_STATIC_LIBUSB",
            Box::new(|| {
                let mut config = cc::Build::new();
                config
                    .file("etc/hidapi/libusb/hid.c")
                    .include("etc/hidapi/hidapi");
                let lib =
                    pkg_config::find_library("libusb-1.0").expect("Unable to find libusb-1.0");
                for path in lib.include_paths {
                    config.include(
                        path.to_str()
                            .expect("Failed to convert include path to str"),
                    );
                }
                config.compile("libhidapi.a");
            }),
        ),
        (
            "LINUX_SHARED_HIDRAW",
            Box::new(|| {
                pkg_config::probe_library("hidapi-hidraw").expect("Unable to find hidapi-hidraw");
            }),
        ),
        (
            "LINUX_SHARED_LIBUSB",
            Box::new(|| {
                pkg_config::probe_library("hidapi-libusb").expect("Unable to find hidapi-libusb");
            }),
        ),
    ];

    let mut backends = avail_backends
        .iter()
        .filter(|f| env::var(format!("CARGO_FEATURE_{}", f.0)).is_ok());

    if backends.clone().count() != 1 {
        panic!("Exactly one linux hidapi backend must be selected.");
    }

    // Build it!
    (backends.next().unwrap().1)();
}

//#[cfg(all(feature = "shared-libusb", not(feature = "shared-hidraw")))]
//fn compile_linux() {
//
//}
//
//#[cfg(all(feature = "shared-hidraw"))]
//fn compile_linux() {
//
//}

fn compile_freebsd() {
    pkg_config::probe_library("hidapi").expect("Unable to find hidapi");
}

fn compile_openbsd() {
    pkg_config::probe_library("hidapi-libusb").expect("Unable to find hidapi");
}

fn compile_illumos() {
    // First check the features enabled for the crate.
    // Only one illumos backend should be enabled at a time.

    let avail_backends: [(&'static str, Box<dyn Fn()>); 2] = [
        (
            "ILLUMOS_STATIC_LIBUSB",
            Box::new(|| {
                let mut config = cc::Build::new();
                config
                    .file("etc/hidapi/libusb/hid.c")
                    .include("etc/hidapi/hidapi");
                let lib =
                    pkg_config::find_library("libusb-1.0").expect("Unable to find libusb-1.0");
                for path in lib.include_paths {
                    config.include(
                        path.to_str()
                            .expect("Failed to convert include path to str"),
                    );
                }
                config.compile("libhidapi.a");
            }),
        ),
        (
            "ILLUMOS_SHARED_LIBUSB",
            Box::new(|| {
                pkg_config::probe_library("hidapi-libusb").expect("Unable to find hidapi-libusb");
            }),
        ),
    ];

    let mut backends = avail_backends
        .iter()
        .filter(|f| env::var(format!("CARGO_FEATURE_{}", f.0)).is_ok());

    if backends.clone().count() != 1 {
        panic!("Exactly one illumos hidapi backend must be selected.");
    }

    // Build it!
    (backends.next().unwrap().1)();
}

fn compile_windows() {
    let linkage = env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or(String::new());

    let mut cc = cc::Build::new();
    cc.file("etc/hidapi/windows/hid.c")
        .include("etc/hidapi/hidapi");

    if linkage.contains("crt-static") {
        // https://doc.rust-lang.org/reference/linkage.html#static-and-dynamic-c-runtimes
        cc.static_crt(true);
    }
    cc.compile("libhidapi.a");
    println!("cargo:rustc-link-lib=setupapi");
}

fn compile_macos() {
    cc::Build::new()
        .file("etc/hidapi/mac/hid.c")
        .include("etc/hidapi/hidapi")
        .compile("libhidapi.a");
    println!("cargo:rustc-link-lib=framework=IOKit");
    println!("cargo:rustc-link-lib=framework=CoreFoundation");
    println!("cargo:rustc-link-lib=framework=AppKit")
}
========== build.rs from httparse-1.7.1 ============================================================
use std::env;
//use std::ffi::OsString;
//use std::process::Command;

fn main() {
    // We don't currently need to check the Version anymore...
    // But leaving this in place in case we need to in the future.
    /*
    let rustc = env::var_os("RUSTC").unwrap_or(OsString::from("rustc"));
    let output = Command::new(&rustc)
        .arg("--version")
        .output()
        .expect("failed to check 'rustc --version'")
        .stdout;

    let version = String::from_utf8(output)
        .expect("rustc version output should be utf-8");
    */

    enable_new_features(/*&version*/);
}

fn enable_new_features(/*raw_version: &str*/) {
    /*
    let version = match Version::parse(raw_version) {
        Ok(version) => version,
        Err(err) => {
            println!("cargo:warning=failed to parse `rustc --version`: {}", err);
            return;
        }
    };
    */

    enable_simd(/*version*/);
}

fn enable_simd(/*version: Version*/) {
    if env::var_os("CARGO_FEATURE_STD").is_none() {
        println!("cargo:warning=building for no_std disables httparse SIMD");
        return;
    }
    if env::var_os("CARGO_CFG_MIRI").is_some() {
        println!("cargo:warning=building for Miri disables httparse SIMD");
        return;
    }

    let env_disable = "CARGO_CFG_HTTPARSE_DISABLE_SIMD";
    if var_is(env_disable, "1") {
        println!("cargo:warning=detected {} environment variable, disabling SIMD", env_disable);
        return;
    }

    println!("cargo:rustc-cfg=httparse_simd");

    // cfg(target_feature) isn't stable yet, but CARGO_CFG_TARGET_FEATURE has
    // a list... We aren't doing anything unsafe, since the is_x86_feature_detected
    // macro still checks in the actual lib, BUT!
    //
    // By peeking at the list here, we can change up slightly how we do feature
    // detection in the lib. If our features aren't in the feature list, we
    // stick with a cached runtime detection strategy.
    //
    // But if the features *are* in the list, we benefit from removing our cache,
    // since the compiler will eliminate several branches with its internal
    // cfg(target_feature) usage.


    let env_runtime_only = "CARGO_CFG_HTTPARSE_DISABLE_SIMD_COMPILETIME";
    if var_is(env_runtime_only, "1") {
        println!("cargo:warning=detected {} environment variable, using runtime SIMD detection only", env_runtime_only);
        return;
    }
    let feature_list = match env::var_os("CARGO_CFG_TARGET_FEATURE") {
        Some(var) => match var.into_string() {
            Ok(s) => s,
            Err(_) => {
                println!("cargo:warning=CARGO_CFG_TARGET_FEATURE was not valid utf-8");
                return;
            },
        },
        None => {
            println!("cargo:warning=CARGO_CFG_TARGET_FEATURE was not set");
            return
        },
    };

    let mut saw_sse42 = false;
    let mut saw_avx2 = false;

    for feature in feature_list.split(',') {
        let feature = feature.trim();
        if !saw_sse42 && feature == "sse4.2" {
            saw_sse42 = true;
            println!("cargo:rustc-cfg=httparse_simd_target_feature_sse42");
        }

        if !saw_avx2 && feature == "avx2" {
            saw_avx2 = true;
            println!("cargo:rustc-cfg=httparse_simd_target_feature_avx2");
        }
    }
}

/*
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
struct Version {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Version {
    fn parse(mut s: &str) -> Result<Version, String> {
        if !s.starts_with("rustc ") {
            return Err(format!("unrecognized version string: {}", s));
        }
        s = &s["rustc ".len()..];

        let parts: Vec<&str> = s.split(".").collect();
        if parts.len() < 3 {
            return Err(format!("not enough version parts: {:?}", parts));
        }

        let mut num = String::new();
        for c in parts[0].chars() {
            if !c.is_digit(10) {
                break;
            }
            num.push(c);
        }
        let major = num.parse::<u32>().map_err(|e| e.to_string())?;

        num.clear();
        for c in parts[1].chars() {
            if !c.is_digit(10) {
                break;
            }
            num.push(c);
        }
        let minor = num.parse::<u32>().map_err(|e| e.to_string())?;

        num.clear();
        for c in parts[2].chars() {
            if !c.is_digit(10) {
                break;
            }
            num.push(c);
        }
        let patch = num.parse::<u32>().map_err(|e| e.to_string())?;

        Ok(Version {
            major: major,
            minor: minor,
            patch: patch,
        })
    }
}
*/

fn var_is(key: &str, val: &str) -> bool {
    match env::var(key) {
        Ok(v) => v == val,
        Err(_) => false,
    }
}
========== build.rs from indexmap-1.9.1 ============================================================
fn main() {
    // If "std" is explicitly requested, don't bother probing the target for it.
    match std::env::var_os("CARGO_FEATURE_STD") {
        Some(_) => autocfg::emit("has_std"),
        None => autocfg::new().emit_sysroot_crate("std"),
    }
    autocfg::rerun_path("build.rs");
}
========== build.rs from libc-0.2.147 ============================================================
use std::env;
use std::process::Command;
use std::str;
use std::string::String;

// List of cfgs this build script is allowed to set. The list is needed to support check-cfg, as we
// need to know all the possible cfgs that this script will set. If you need to set another cfg
// make sure to add it to this list as well.
const ALLOWED_CFGS: &'static [&'static str] = &[
    "freebsd10",
    "freebsd11",
    "freebsd12",
    "freebsd13",
    "freebsd14",
    "libc_align",
    "libc_cfg_target_vendor",
    "libc_const_extern_fn",
    "libc_const_extern_fn_unstable",
    "libc_const_size_of",
    "libc_core_cvoid",
    "libc_deny_warnings",
    "libc_int128",
    "libc_long_array",
    "libc_non_exhaustive",
    "libc_packedN",
    "libc_priv_mod_use",
    "libc_ptr_addr_of",
    "libc_thread_local",
    "libc_underscore_const_names",
    "libc_union",
];

// Extra values to allow for check-cfg.
const CHECK_CFG_EXTRA: &'static [(&'static str, &'static [&'static str])] = &[
    ("target_os", &["switch", "aix", "ohos"]),
    ("target_env", &["illumos", "wasi", "aix", "ohos"]),
    ("target_arch", &["loongarch64"]),
];

fn main() {
    // Avoid unnecessary re-building.
    println!("cargo:rerun-if-changed=build.rs");

    let (rustc_minor_ver, is_nightly) = rustc_minor_nightly();
    let rustc_dep_of_std = env::var("CARGO_FEATURE_RUSTC_DEP_OF_STD").is_ok();
    let align_cargo_feature = env::var("CARGO_FEATURE_ALIGN").is_ok();
    let const_extern_fn_cargo_feature = env::var("CARGO_FEATURE_CONST_EXTERN_FN").is_ok();
    let libc_ci = env::var("LIBC_CI").is_ok();
    let libc_check_cfg = env::var("LIBC_CHECK_CFG").is_ok();

    if env::var("CARGO_FEATURE_USE_STD").is_ok() {
        println!(
            "cargo:warning=\"libc's use_std cargo feature is deprecated since libc 0.2.55; \
             please consider using the `std` cargo feature instead\""
        );
    }

    // The ABI of libc used by libstd is backward compatible with FreeBSD 10.
    // The ABI of libc from crates.io is backward compatible with FreeBSD 11.
    //
    // On CI, we detect the actual FreeBSD version and match its ABI exactly,
    // running tests to ensure that the ABI is correct.
    match which_freebsd() {
        Some(10) if libc_ci || rustc_dep_of_std => set_cfg("freebsd10"),
        Some(11) if libc_ci => set_cfg("freebsd11"),
        Some(12) if libc_ci => set_cfg("freebsd12"),
        Some(13) if libc_ci => set_cfg("freebsd13"),
        Some(14) if libc_ci => set_cfg("freebsd14"),
        Some(_) | None => set_cfg("freebsd11"),
    }

    // On CI: deny all warnings
    if libc_ci {
        set_cfg("libc_deny_warnings");
    }

    // Rust >= 1.15 supports private module use:
    if rustc_minor_ver >= 15 || rustc_dep_of_std {
        set_cfg("libc_priv_mod_use");
    }

    // Rust >= 1.19 supports unions:
    if rustc_minor_ver >= 19 || rustc_dep_of_std {
        set_cfg("libc_union");
    }

    // Rust >= 1.24 supports const mem::size_of:
    if rustc_minor_ver >= 24 || rustc_dep_of_std {
        set_cfg("libc_const_size_of");
    }

    // Rust >= 1.25 supports repr(align):
    if rustc_minor_ver >= 25 || rustc_dep_of_std || align_cargo_feature {
        set_cfg("libc_align");
    }

    // Rust >= 1.26 supports i128 and u128:
    if rustc_minor_ver >= 26 || rustc_dep_of_std {
        set_cfg("libc_int128");
    }

    // Rust >= 1.30 supports `core::ffi::c_void`, so libc can just re-export it.
    // Otherwise, it defines an incompatible type to retaining
    // backwards-compatibility.
    if rustc_minor_ver >= 30 || rustc_dep_of_std {
        set_cfg("libc_core_cvoid");
    }

    // Rust >= 1.33 supports repr(packed(N)) and cfg(target_vendor).
    if rustc_minor_ver >= 33 || rustc_dep_of_std {
        set_cfg("libc_packedN");
        set_cfg("libc_cfg_target_vendor");
    }

    // Rust >= 1.40 supports #[non_exhaustive].
    if rustc_minor_ver >= 40 || rustc_dep_of_std {
        set_cfg("libc_non_exhaustive");
    }

    // Rust >= 1.47 supports long array:
    if rustc_minor_ver >= 47 || rustc_dep_of_std {
        set_cfg("libc_long_array");
    }

    if rustc_minor_ver >= 51 || rustc_dep_of_std {
        set_cfg("libc_ptr_addr_of");
    }

    // Rust >= 1.37.0 allows underscores as anonymous constant names.
    if rustc_minor_ver >= 37 || rustc_dep_of_std {
        set_cfg("libc_underscore_const_names");
    }

    // #[thread_local] is currently unstable
    if rustc_dep_of_std {
        set_cfg("libc_thread_local");
    }

    // Rust >= 1.62.0 allows to use `const_extern_fn` for "Rust" and "C".
    if rustc_minor_ver >= 62 {
        set_cfg("libc_const_extern_fn");
    } else {
        // Rust < 1.62.0 requires a crate feature and feature gate.
        if const_extern_fn_cargo_feature {
            if !is_nightly || rustc_minor_ver < 40 {
                panic!("const-extern-fn requires a nightly compiler >= 1.40");
            }
            set_cfg("libc_const_extern_fn_unstable");
            set_cfg("libc_const_extern_fn");
        }
    }

    // check-cfg is a nightly cargo/rustc feature to warn when unknown cfgs are used across the
    // codebase. libc can configure it if the appropriate environment variable is passed. Since
    // rust-lang/rust enforces it, this is useful when using a custom libc fork there.
    //
    // https://doc.rust-lang.org/nightly/cargo/reference/unstable.html#check-cfg
    if libc_check_cfg {
        for cfg in ALLOWED_CFGS {
            println!("cargo:rustc-check-cfg=values({})", cfg);
        }
        for &(name, values) in CHECK_CFG_EXTRA {
            let values = values.join("\",\"");
            println!("cargo:rustc-check-cfg=values({},\"{}\")", name, values);
        }
    }
}

fn rustc_minor_nightly() -> (u32, bool) {
    macro_rules! otry {
        ($e:expr) => {
            match $e {
                Some(e) => e,
                None => panic!("Failed to get rustc version"),
            }
        };
    }

    let rustc = otry!(env::var_os("RUSTC"));
    let output = Command::new(rustc)
        .arg("--version")
        .output()
        .ok()
        .expect("Failed to get rustc version");
    if !output.status.success() {
        panic!(
            "failed to run rustc: {}",
            String::from_utf8_lossy(output.stderr.as_slice())
        );
    }

    let version = otry!(str::from_utf8(&output.stdout).ok());
    let mut pieces = version.split('.');

    if pieces.next() != Some("rustc 1") {
        panic!("Failed to get rustc version");
    }

    let minor = pieces.next();

    // If `rustc` was built from a tarball, its version string
    // will have neither a git hash nor a commit date
    // (e.g. "rustc 1.39.0"). Treat this case as non-nightly,
    // since a nightly build should either come from CI
    // or a git checkout
    let nightly_raw = otry!(pieces.next()).split('-').nth(1);
    let nightly = nightly_raw
        .map(|raw| raw.starts_with("dev") || raw.starts_with("nightly"))
        .unwrap_or(false);
    let minor = otry!(otry!(minor).parse().ok());

    (minor, nightly)
}

fn which_freebsd() -> Option<i32> {
    let output = std::process::Command::new("freebsd-version").output().ok();
    if output.is_none() {
        return None;
    }
    let output = output.unwrap();
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok();
    if stdout.is_none() {
        return None;
    }
    let stdout = stdout.unwrap();

    match &stdout {
        s if s.starts_with("10") => Some(10),
        s if s.starts_with("11") => Some(11),
        s if s.starts_with("12") => Some(12),
        s if s.starts_with("13") => Some(13),
        s if s.starts_with("14") => Some(14),
        _ => None,
    }
}

fn set_cfg(cfg: &str) {
    if !ALLOWED_CFGS.contains(&cfg) {
        panic!("trying to set cfg {}, but it is not in ALLOWED_CFGS", cfg);
    }
    println!("cargo:rustc-cfg={}", cfg);
}
========== build.rs from libm-0.1.4 ============================================================
use std::env;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    #[cfg(feature = "musl-reference-tests")]
    musl_reference_tests::generate();

    if !cfg!(feature = "checked") {
        let lvl = env::var("OPT_LEVEL").unwrap();
        if lvl != "0" {
            println!("cargo:rustc-cfg=assert_no_panic");
        }
    }
}

#[cfg(feature = "musl-reference-tests")]
mod musl_reference_tests {
    use rand::seq::SliceRandom;
    use rand::Rng;
    use std::fs;
    use std::process::Command;

    // Number of tests to generate for each function
    const NTESTS: usize = 500;

    // These files are all internal functions or otherwise miscellaneous, not
    // defining a function we want to test.
    const IGNORED_FILES: &[&str] = &["fenv.rs"];

    struct Function {
        name: String,
        args: Vec<Ty>,
        ret: Vec<Ty>,
        tests: Vec<Test>,
    }

    enum Ty {
        F32,
        F64,
        I32,
        Bool,
    }

    struct Test {
        inputs: Vec<i64>,
        outputs: Vec<i64>,
    }

    pub fn generate() {
        let files = fs::read_dir("src/math")
            .unwrap()
            .map(|f| f.unwrap().path())
            .collect::<Vec<_>>();

        let mut math = Vec::new();
        for file in files {
            if IGNORED_FILES.iter().any(|f| file.ends_with(f)) {
                continue;
            }

            println!("generating musl reference tests in {:?}", file);

            let contents = fs::read_to_string(file).unwrap();
            let mut functions = contents.lines().filter(|f| f.starts_with("pub fn"));
            while let Some(function_to_test) = functions.next() {
                math.push(parse(function_to_test));
            }
        }

        // Generate a bunch of random inputs for each function. This will
        // attempt to generate a good set of uniform test cases for exercising
        // all the various functionality.
        generate_random_tests(&mut math, &mut rand::thread_rng());

        // After we have all our inputs, use the x86_64-unknown-linux-musl
        // target to generate the expected output.
        generate_test_outputs(&mut math);
        //panic!("Boo");
        // ... and now that we have both inputs and expected outputs, do a bunch
        // of codegen to create the unit tests which we'll actually execute.
        generate_unit_tests(&math);
    }

    /// A "poor man's" parser for the signature of a function
    fn parse(s: &str) -> Function {
        let s = eat(s, "pub fn ");
        let pos = s.find('(').unwrap();
        let name = &s[..pos];
        let s = &s[pos + 1..];
        let end = s.find(')').unwrap();
        let args = s[..end]
            .split(',')
            .map(|arg| {
                let colon = arg.find(':').unwrap();
                parse_ty(arg[colon + 1..].trim())
            })
            .collect::<Vec<_>>();
        let tail = &s[end + 1..];
        let tail = eat(tail, " -> ");
        let ret = parse_retty(tail.replace("{", "").trim());

        return Function {
            name: name.to_string(),
            args,
            ret,
            tests: Vec::new(),
        };

        fn parse_ty(s: &str) -> Ty {
            match s {
                "f32" => Ty::F32,
                "f64" => Ty::F64,
                "i32" => Ty::I32,
                "bool" => Ty::Bool,
                other => panic!("unknown type `{}`", other),
            }
        }

        fn parse_retty(s: &str) -> Vec<Ty> {
            match s {
                "(f32, f32)" => vec![Ty::F32, Ty::F32],
                "(f32, i32)" => vec![Ty::F32, Ty::I32],
                "(f64, f64)" => vec![Ty::F64, Ty::F64],
                "(f64, i32)" => vec![Ty::F64, Ty::I32],
                other => vec![parse_ty(other)],
            }
        }

        fn eat<'a>(s: &'a str, prefix: &str) -> &'a str {
            if s.starts_with(prefix) {
                &s[prefix.len()..]
            } else {
                panic!("{:?} didn't start with {:?}", s, prefix)
            }
        }
    }

    fn generate_random_tests<R: Rng>(functions: &mut [Function], rng: &mut R) {
        for function in functions {
            for _ in 0..NTESTS {
                function.tests.push(generate_test(function, rng));
            }
        }

        fn generate_test<R: Rng>(function: &Function, rng: &mut R) -> Test {
            let mut inputs = function
                .args
                .iter()
                .map(|ty| ty.gen_i64(rng))
                .collect::<Vec<_>>();

            // First argument to this function appears to be a number of
            // iterations, so passing in massive random numbers causes it to
            // take forever to execute, so make sure we're not running random
            // math code until the heat death of the universe.
            if function.name == "jn" || function.name == "jnf" {
                inputs[0] &= 0xffff;
            }

            Test {
                inputs,
                // zero output for now since we'll generate it later
                outputs: vec![],
            }
        }
    }

    impl Ty {
        fn gen_i64<R: Rng>(&self, r: &mut R) -> i64 {
            use std::f32;
            use std::f64;

            return match self {
                Ty::F32 => {
                    if r.gen_range(0, 20) < 1 {
                        let i = *[f32::NAN, f32::INFINITY, f32::NEG_INFINITY]
                            .choose(r)
                            .unwrap();
                        i.to_bits().into()
                    } else {
                        r.gen::<f32>().to_bits().into()
                    }
                }
                Ty::F64 => {
                    if r.gen_range(0, 20) < 1 {
                        let i = *[f64::NAN, f64::INFINITY, f64::NEG_INFINITY]
                            .choose(r)
                            .unwrap();
                        i.to_bits() as i64
                    } else {
                        r.gen::<f64>().to_bits() as i64
                    }
                }
                Ty::I32 => {
                    if r.gen_range(0, 10) < 1 {
                        let i = *[i32::max_value(), 0, i32::min_value()].choose(r).unwrap();
                        i.into()
                    } else {
                        r.gen::<i32>().into()
                    }
                }
                Ty::Bool => r.gen::<bool>() as i64,
            };
        }

        fn libc_ty(&self) -> &'static str {
            match self {
                Ty::F32 => "f32",
                Ty::F64 => "f64",
                Ty::I32 => "i32",
                Ty::Bool => "i32",
            }
        }

        fn libc_pty(&self) -> &'static str {
            match self {
                Ty::F32 => "*mut f32",
                Ty::F64 => "*mut f64",
                Ty::I32 => "*mut i32",
                Ty::Bool => "*mut i32",
            }
        }

        fn default(&self) -> &'static str {
            match self {
                Ty::F32 => "0_f32",
                Ty::F64 => "0_f64",
                Ty::I32 => "0_i32",
                Ty::Bool => "false",
            }
        }

        fn to_i64(&self) -> &'static str {
            match self {
                Ty::F32 => ".to_bits() as i64",
                Ty::F64 => ".to_bits() as i64",
                Ty::I32 => " as i64",
                Ty::Bool => " as i64",
            }
        }
    }

    fn generate_test_outputs(functions: &mut [Function]) {
        let mut src = String::new();
        let dst = std::env::var("OUT_DIR").unwrap();

        // Generate a program which will run all tests with all inputs in
        // `functions`. This program will write all outputs to stdout (in a
        // binary format).
        src.push_str("use std::io::Write;");
        src.push_str("fn main() {");
        src.push_str("let mut result = Vec::new();");
        for function in functions.iter_mut() {
            src.push_str("unsafe {");
            src.push_str("extern { fn ");
            src.push_str(&function.name);
            src.push_str("(");

            let (ret, retptr) = match function.name.as_str() {
                "sincos" | "sincosf" => (None, &function.ret[..]),
                _ => (Some(&function.ret[0]), &function.ret[1..]),
            };
            for (i, arg) in function.args.iter().enumerate() {
                src.push_str(&format!("arg{}: {},", i, arg.libc_ty()));
            }
            for (i, ret) in retptr.iter().enumerate() {
                src.push_str(&format!("argret{}: {},", i, ret.libc_pty()));
            }
            src.push_str(")");
            if let Some(ty) = ret {
                src.push_str(" -> ");
                src.push_str(ty.libc_ty());
            }
            src.push_str("; }");

            src.push_str(&format!("static TESTS: &[[i64; {}]]", function.args.len()));
            src.push_str(" = &[");
            for test in function.tests.iter() {
                src.push_str("[");
                for val in test.inputs.iter() {
                    src.push_str(&val.to_string());
                    src.push_str(",");
                }
                src.push_str("],");
            }
            src.push_str("];");

            src.push_str("for test in TESTS {");
            for (i, arg) in retptr.iter().enumerate() {
                src.push_str(&format!("let mut argret{} = {};", i, arg.default()));
            }
            src.push_str("let output = ");
            src.push_str(&function.name);
            src.push_str("(");
            for (i, arg) in function.args.iter().enumerate() {
                src.push_str(&match arg {
                    Ty::F32 => format!("f32::from_bits(test[{}] as u32)", i),
                    Ty::F64 => format!("f64::from_bits(test[{}] as u64)", i),
                    Ty::I32 => format!("test[{}] as i32", i),
                    Ty::Bool => format!("test[{}] as i32", i),
                });
                src.push_str(",");
            }
            for (i, _) in retptr.iter().enumerate() {
                src.push_str(&format!("&mut argret{},", i));
            }
            src.push_str(");");
            if let Some(ty) = &ret {
                src.push_str(&format!("let output = output{};", ty.to_i64()));
                src.push_str("result.extend_from_slice(&output.to_le_bytes());");
            }

            for (i, ret) in retptr.iter().enumerate() {
                src.push_str(&format!(
                    "result.extend_from_slice(&(argret{}{}).to_le_bytes());",
                    i,
                    ret.to_i64(),
                ));
            }
            src.push_str("}");

            src.push_str("}");
        }

        src.push_str("std::io::stdout().write_all(&result).unwrap();");

        src.push_str("}");

        let path = format!("{}/gen.rs", dst);
        fs::write(&path, src).unwrap();

        // Make it somewhat pretty if something goes wrong
        drop(Command::new("rustfmt").arg(&path).status());

        // Compile and execute this tests for the musl target, assuming we're an
        // x86_64 host effectively.
        let status = Command::new("rustc")
            .current_dir(&dst)
            .arg(&path)
            .arg("--target=x86_64-unknown-linux-musl")
            .status()
            .unwrap();
        assert!(status.success());
        let output = Command::new("./gen").current_dir(&dst).output().unwrap();
        assert!(output.status.success());
        assert!(output.stderr.is_empty());

        // Map all the output bytes back to an `i64` and then shove it all into
        // the expected results.
        let mut results = output.stdout.chunks_exact(8).map(|buf| {
            let mut exact = [0; 8];
            exact.copy_from_slice(buf);
            i64::from_le_bytes(exact)
        });

        for f in functions.iter_mut() {
            for test in f.tests.iter_mut() {
                test.outputs = (0..f.ret.len()).map(|_| results.next().unwrap()).collect();
            }
        }
        assert!(results.next().is_none());
    }

    /// Codegens a file which has a ton of `#[test]` annotations for all the
    /// tests that we generated above.
    fn generate_unit_tests(functions: &[Function]) {
        let mut src = String::new();
        let dst = std::env::var("OUT_DIR").unwrap();

        for function in functions {
            src.push_str("#[test]");
            src.push_str("fn ");
            src.push_str(&function.name);
            src.push_str("_matches_musl() {");
            src.push_str(&format!(
                "static TESTS: &[([i64; {}], [i64; {}])]",
                function.args.len(),
                function.ret.len(),
            ));
            src.push_str(" = &[");
            for test in function.tests.iter() {
                src.push_str("([");
                for val in test.inputs.iter() {
                    src.push_str(&val.to_string());
                    src.push_str(",");
                }
                src.push_str("],");
                src.push_str("[");
                for val in test.outputs.iter() {
                    src.push_str(&val.to_string());
                    src.push_str(",");
                }
                src.push_str("],");
                src.push_str("),");
            }
            src.push_str("];");

            src.push_str("for (test, expected) in TESTS {");
            src.push_str("let output = ");
            src.push_str(&function.name);
            src.push_str("(");
            for (i, arg) in function.args.iter().enumerate() {
                src.push_str(&match arg {
                    Ty::F32 => format!("f32::from_bits(test[{}] as u32)", i),
                    Ty::F64 => format!("f64::from_bits(test[{}] as u64)", i),
                    Ty::I32 => format!("test[{}] as i32", i),
                    Ty::Bool => format!("test[{}] as i32", i),
                });
                src.push_str(",");
            }
            src.push_str(");");

            for (i, ret) in function.ret.iter().enumerate() {
                let get = if function.ret.len() == 1 {
                    String::new()
                } else {
                    format!(".{}", i)
                };
                src.push_str(&(match ret {
                    Ty::F32 => format!("if _eqf(output{}, f32::from_bits(expected[{}] as u32)).is_ok() {{ continue }}", get, i),
                    Ty::F64 => format!("if _eq(output{}, f64::from_bits(expected[{}] as u64)).is_ok() {{ continue }}", get, i),
                    Ty::I32 => format!("if output{} as i64 == expected[{}] {{ continue }}", get, i),
                    Ty::Bool => unreachable!(),
                }));
            }

            src.push_str(
                r#"
                panic!("INPUT: {:?} EXPECTED: {:?} ACTUAL {:?}", test, expected, output);
            "#,
            );
            src.push_str("}");

            src.push_str("}");
        }

        let path = format!("{}/musl-tests.rs", dst);
        fs::write(&path, src).unwrap();

        // Try to make it somewhat pretty
        drop(Command::new("rustfmt").arg(&path).status());
    }
}
========== build.rs from lock_api-0.4.7 ============================================================
fn main() {
    let cfg = autocfg::new();

    if cfg.probe_rustc_version(1, 61) {
        println!("cargo:rustc-cfg=has_const_fn_trait_bound");
    }
}
========== build.rs from log-0.4.17 ============================================================
//! This build script detects target platforms that lack proper support for
//! atomics and sets `cfg` flags accordingly.

use std::env;
use std::str;

fn main() {
    let target = match rustc_target() {
        Some(target) => target,
        None => return,
    };

    if target_has_atomic_cas(&target) {
        println!("cargo:rustc-cfg=atomic_cas");
    }

    if target_has_atomics(&target) {
        println!("cargo:rustc-cfg=has_atomics");
    }

    println!("cargo:rerun-if-changed=build.rs");
}

fn target_has_atomic_cas(target: &str) -> bool {
    match &target[..] {
        "thumbv6m-none-eabi"
        | "msp430-none-elf"
        | "riscv32i-unknown-none-elf"
        | "riscv32imc-unknown-none-elf" => false,
        _ => true,
    }
}

fn target_has_atomics(target: &str) -> bool {
    match &target[..] {
        "thumbv4t-none-eabi"
        | "msp430-none-elf"
        | "riscv32i-unknown-none-elf"
        | "riscv32imc-unknown-none-elf" => false,
        _ => true,
    }
}

fn rustc_target() -> Option<String> {
    env::var("TARGET").ok()
}
========== build.rs from memchr-2.5.0 ============================================================
use std::env;

fn main() {
    enable_simd_optimizations();
    enable_libc();
}

// This adds various simd cfgs if this compiler and target support it.
//
// This can be disabled with RUSTFLAGS="--cfg memchr_disable_auto_simd", but
// this is generally only intended for testing.
//
// On targets which don't feature SSE2, this is disabled, as LLVM wouln't know
// how to work with SSE2 operands. Enabling SSE4.2 and AVX on SSE2-only targets
// is not a problem. In that case, the fastest option will be chosen at
// runtime.
fn enable_simd_optimizations() {
    if is_env_set("CARGO_CFG_MEMCHR_DISABLE_AUTO_SIMD") {
        return;
    }
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    match &arch[..] {
        "x86_64" => {
            if !target_has_feature("sse2") {
                return;
            }
            println!("cargo:rustc-cfg=memchr_runtime_simd");
            println!("cargo:rustc-cfg=memchr_runtime_sse2");
            println!("cargo:rustc-cfg=memchr_runtime_sse42");
            println!("cargo:rustc-cfg=memchr_runtime_avx");
        }
        "wasm32" | "wasm64" => {
            if !target_has_feature("simd128") {
                return;
            }
            println!("cargo:rustc-cfg=memchr_runtime_simd");
            println!("cargo:rustc-cfg=memchr_runtime_wasm128");
        }
        _ => {}
    }
}

// This adds a `memchr_libc` cfg if and only if libc can be used, if no other
// better option is available.
//
// This could be performed in the source code, but it's simpler to do it once
// here and consolidate it into one cfg knob.
//
// Basically, we use libc only if its enabled and if we aren't targeting a
// known bad platform. For example, wasm32 doesn't have a libc and the
// performance of memchr on Windows is seemingly worse than the fallback
// implementation.
fn enable_libc() {
    const NO_ARCH: &'static [&'static str] = &["wasm32", "windows"];
    const NO_ENV: &'static [&'static str] = &["sgx"];

    if !is_feature_set("LIBC") {
        return;
    }

    let arch = match env::var("CARGO_CFG_TARGET_ARCH") {
        Err(_) => return,
        Ok(arch) => arch,
    };
    let env = match env::var("CARGO_CFG_TARGET_ENV") {
        Err(_) => return,
        Ok(env) => env,
    };
    if NO_ARCH.contains(&&*arch) || NO_ENV.contains(&&*env) {
        return;
    }

    println!("cargo:rustc-cfg=memchr_libc");
}

fn is_feature_set(name: &str) -> bool {
    is_env_set(&format!("CARGO_FEATURE_{}", name))
}

fn is_env_set(name: &str) -> bool {
    env::var_os(name).is_some()
}

fn target_has_feature(feature: &str) -> bool {
    env::var("CARGO_CFG_TARGET_FEATURE")
        .map(|features| features.contains(feature))
        .unwrap_or(false)
}
========== build.rs from memoffset-0.6.5 ============================================================
extern crate autocfg;

fn main() {
    let ac = autocfg::new();

    // Check for a minimum version for a few features
    if ac.probe_rustc_version(1, 20) {
        println!("cargo:rustc-cfg=tuple_ty");
    }
    if ac.probe_rustc_version(1, 31) {
        println!("cargo:rustc-cfg=allow_clippy");
    }
    if ac.probe_rustc_version(1, 36) {
        println!("cargo:rustc-cfg=maybe_uninit");
    }
    if ac.probe_rustc_version(1, 40) {
        println!("cargo:rustc-cfg=doctests");
    }
    if ac.probe_rustc_version(1, 51) {
        println!("cargo:rustc-cfg=raw_ref_macros");
    }
}
========== build.rs from minifb-0.23.0 ============================================================
use std::env;
extern crate cc;

//cargo build --target=wasm32-unknown-unknown --verbose --no-default-features --features web

fn main() {
    /*
    println!("Environment configuration:");
    for (key, value) in env::vars() {
        if key.starts_with("CARGO_CFG_") {
            println!("{}: {:?}", key, value);
        }
    }
    println!("OS: {:?}", env::var("OS").unwrap_or("".to_string()));
    println!("FAMILY: {:?}", env::var("FAMILY").unwrap_or("".to_string()));
    println!("ARCH: {:?}", env::var("ARCH").unwrap_or("".to_string()));
    println!("TARGET: {:?}", env::var("TARGET").unwrap_or("".to_string()));
    */
    // target_arch is not working? OS FAMILY and ARCH variables were empty too
    // I think the cross-compilation is broken. We could take these from the environment,
    // since the build script seems to have a different target_arch than the destination.
    let target = env::var("TARGET").unwrap_or("".to_string());
    if target != "wasm32-unknown-unknown"
        && cfg!(not(any(
            target_os = "macos",
            target_os = "windows",
            target_os = "redox",
            target_arch = "wasm32", // this is ignored. Why?
        )))
        && cfg!(not(any(feature = "wayland", feature = "x11")))
    {
        panic!("At least one of the x11 or wayland features must be enabled");
    }

    let env = env::var("TARGET").unwrap();
    if env.contains("darwin") {
        cc::Build::new()
            .flag("-mmacosx-version-min=10.10")
            .file("src/native/macosx/MacMiniFB.m")
            .file("src/native/macosx/OSXWindow.m")
            .file("src/native/macosx/OSXWindowFrameView.m")
            .compile("libminifb_native.a");
        println!("cargo:rustc-link-lib=framework=Metal");
        println!("cargo:rustc-link-lib=framework=MetalKit");
    } else if !env.contains("windows") && !env.contains("wasm32") {
        // build scalar on non-windows and non-mac
        cc::Build::new()
            .file("src/native/posix/scalar.cpp")
            .opt_level(3) // always build with opts for scaler so it's fast in debug also
            .compile("libscalar.a")
    }
}
========== build.rs from miniz_oxide-0.4.4 ============================================================
#![forbid(unsafe_code)]
use autocfg;

fn main() {
    autocfg::new().emit_sysroot_crate("alloc");
}
========== build.rs from num-bigint-0.4.3 ============================================================
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let pointer_width = env::var("CARGO_CFG_TARGET_POINTER_WIDTH");
    let u64_digit = pointer_width.as_ref().map(String::as_str) == Ok("64");
    if u64_digit {
        autocfg::emit("u64_digit");
    }
    let ac = autocfg::new();
    let std = if ac.probe_sysroot_crate("std") {
        "std"
    } else {
        "core"
    };
    if ac.probe_path(&format!("{}::convert::TryFrom", std)) {
        autocfg::emit("has_try_from");
    }

    if let Ok(target_arch) = env::var("CARGO_CFG_TARGET_ARCH") {
        if target_arch == "x86_64" || target_arch == "x86" {
            let digit = if u64_digit { "u64" } else { "u32" };

            let addcarry = format!("{}::arch::{}::_addcarry_{}", std, target_arch, digit);
            if ac.probe_path(&addcarry) {
                autocfg::emit("use_addcarry");
            }
        }
    }

    autocfg::rerun_path("build.rs");

    write_radix_bases().unwrap();
}

/// Write tables of the greatest power of each radix for the given bit size.  These are returned
/// from `biguint::get_radix_base` to batch the multiplication/division of radix conversions on
/// full `BigUint` values, operating on primitive integers as much as possible.
///
/// e.g. BASES_16[3] = (59049, 10) // 3¹⁰ fits in u16, but 3¹¹ is too big
///      BASES_32[3] = (3486784401, 20)
///      BASES_64[3] = (12157665459056928801, 40)
///
/// Powers of two are not included, just zeroed, as they're implemented with shifts.
fn write_radix_bases() -> Result<(), Box<dyn Error>> {
    let out_dir = env::var("OUT_DIR")?;
    let dest_path = Path::new(&out_dir).join("radix_bases.rs");
    let mut f = File::create(&dest_path)?;

    for &bits in &[16, 32, 64] {
        let max = if bits < 64 {
            (1 << bits) - 1
        } else {
            std::u64::MAX
        };

        writeln!(f, "#[deny(overflowing_literals)]")?;
        writeln!(
            f,
            "pub(crate) static BASES_{bits}: [(u{bits}, usize); 257] = [",
            bits = bits
        )?;
        for radix in 0u64..257 {
            let (base, power) = if radix == 0 || radix.is_power_of_two() {
                (0, 0)
            } else {
                let mut power = 1;
                let mut base = radix;

                while let Some(b) = base.checked_mul(radix) {
                    if b > max {
                        break;
                    }
                    base = b;
                    power += 1;
                }
                (base, power)
            };
            writeln!(f, "    ({}, {}), // {}", base, power, radix)?;
        }
        writeln!(f, "];")?;
    }

    Ok(())
}
========== build.rs from num-integer-0.1.45 ============================================================
extern crate autocfg;

use std::env;

fn main() {
    // If the "i128" feature is explicity requested, don't bother probing for it.
    // It will still cause a build error if that was set improperly.
    if env::var_os("CARGO_FEATURE_I128").is_some() || autocfg::new().probe_type("i128") {
        autocfg::emit("has_i128");
    }

    autocfg::rerun_path("build.rs");
}
========== build.rs from num-iter-0.1.43 ============================================================
extern crate autocfg;

use std::env;

fn main() {
    let autocfg = autocfg::new();

    // If the "i128" feature is explicity requested, don't bother probing for it.
    // It will still cause a build error if that was set improperly.
    if env::var_os("CARGO_FEATURE_I128").is_some() || autocfg.probe_type("i128") {
        autocfg::emit("has_i128");
    }

    // The RangeBounds trait was stabilized in 1.28, so from that version onwards we
    // implement that trait.
    autocfg.emit_rustc_version(1, 28);

    autocfg::rerun_path("build.rs");
}
========== build.rs from num-rational-0.3.2 ============================================================
fn main() {
    let ac = autocfg::new();
    if ac.probe_expression("format!(\"{:e}\", 0_isize)") {
        println!("cargo:rustc-cfg=has_int_exp_fmt");
    }

    autocfg::rerun_path("build.rs");
}
========== build.rs from num-traits-0.2.15 ============================================================
extern crate autocfg;

use std::env;

fn main() {
    let ac = autocfg::new();

    // If the "i128" feature is explicity requested, don't bother probing for it.
    // It will still cause a build error if that was set improperly.
    if env::var_os("CARGO_FEATURE_I128").is_some() || ac.probe_type("i128") {
        autocfg::emit("has_i128");
    }

    ac.emit_expression_cfg(
        "unsafe { 1f64.to_int_unchecked::<i32>() }",
        "has_to_int_unchecked",
    );

    ac.emit_expression_cfg("1u32.reverse_bits()", "has_reverse_bits");
    ac.emit_expression_cfg("1u32.trailing_ones()", "has_leading_trailing_ones");
    ac.emit_expression_cfg("{ let mut x = 1; x += &2; }", "has_int_assignop_ref");
    ac.emit_expression_cfg("1u32.div_euclid(1u32)", "has_div_euclid");

    if env::var_os("CARGO_FEATURE_STD").is_some() {
        ac.emit_expression_cfg("1f64.copysign(-1f64)", "has_copysign");
    }

    autocfg::rerun_path("build.rs");
}
========== build.rs from oid-registry-0.6.1 ============================================================
use std::env;

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/load.rs"));

fn main() -> Result<()> {
    println!("cargo:rerun-if-changed=assets/oid_db.txt");

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("oid_db.rs");

    let m = load_file("assets/oid_db.txt")?;
    generate_file(&m, dest_path)?;

    Ok(())
}
========== build.rs from packed_simd_2-0.3.7 ============================================================
fn main() {
    let target = std::env::var("TARGET").expect("TARGET environment variable not defined");
    if target.contains("neon") {
        println!("cargo:rustc-cfg=libcore_neon");
    }
}
========== build.rs from packed_struct-0.10.0 ============================================================
// build.rs

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generate_bytes_and_bits.rs");
    let mut f = File::create(&dest_path).unwrap();

    let up_to_bytes = 
        if cfg!(feature = "byte_types_256") {
            256
        } else if cfg!(feature = "byte_types_64") {
            64
        } else {
            32
        };

    // bits
    for i in 1..(up_to_bytes * 8) {
        let b = format!("bits_type!(Bits::<{}>, {}, Bytes::<{}>, {});\r\n", i, i, (i as f32 / 8.0).ceil() as usize, if (i % 8) == 0 {
            "BitsFullBytes"
        } else {
            "BitsPartialBytes"
        });
        f.write_all(b.as_bytes()).unwrap();
    }
}========== build.rs from parking_lot_core-0.9.8 ============================================================
// Automatically detect tsan in a way that's compatible with both stable (which
// doesn't support sanitizers) and nightly (which does). Works because build
// scripts gets `cfg` info, even if the cfg is unstable.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let santizer_list = std::env::var("CARGO_CFG_SANITIZE").unwrap_or_default();
    if santizer_list.contains("thread") {
        println!("cargo:rustc-cfg=tsan_enabled");
    }
}
========== build.rs from paste-1.0.12 ============================================================
use std::env;
use std::process::Command;
use std::str;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let version = match rustc_version() {
        Some(version) => version,
        None => return,
    };

    if version.minor < 54 {
        // https://github.com/rust-lang/rust/pull/84717
        println!("cargo:rustc-cfg=no_literal_fromstr");
    }
}

struct RustcVersion {
    minor: u32,
}

fn rustc_version() -> Option<RustcVersion> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    let minor = pieces.next()?.parse().ok()?;
    Some(RustcVersion { minor })
}
========== build.rs from pio-parser-0.2.2 ============================================================
fn main() {
    lalrpop::process_root().unwrap();
}
========== build.rs from proc-macro-error-1.0.4 ============================================================
fn main() {
    if !version_check::is_feature_flaggable().unwrap_or(false) {
        println!("cargo:rustc-cfg=use_fallback");
    }

    if version_check::is_max_version("1.38.0").unwrap_or(false)
        || !version_check::Channel::read().unwrap().is_stable()
    {
        println!("cargo:rustc-cfg=skip_ui_tests");
    }
}
========== build.rs from proc-macro-error-attr-1.0.4 ============================================================
fn main() {
    if version_check::is_max_version("1.36.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=always_assert_unwind");
    }
}
========== build.rs from proc-macro-hack-0.5.19 ============================================================
use std::env;
use std::process::Command;
use std::str;

// The rustc-cfg strings below are *not* public API. Please let us know by
// opening a GitHub issue if your build environment requires some way to enable
// these cfgs other than by executing our build script.
fn main() {
    let minor = match rustc_minor_version() {
        Some(minor) => minor,
        None => return,
    };

    // Function-like procedural macros in expressions, patterns, and statements
    // stabilized in Rust 1.45:
    // https://blog.rust-lang.org/2020/07/16/Rust-1.45.0.html#stabilizing-function-like-procedural-macros-in-expressions-patterns-and-statements
    if minor < 45 {
        println!("cargo:rustc-cfg=need_proc_macro_hack");
    }
}

fn rustc_minor_version() -> Option<u32> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    pieces.next()?.parse().ok()
}
========== build.rs from proc-macro2-1.0.63 ============================================================
// rustc-cfg emitted by the build script:
//
// "wrap_proc_macro"
//     Wrap types from libproc_macro rather than polyfilling the whole API.
//     Enabled on rustc 1.29+ as long as procmacro2_semver_exempt is not set,
//     because we can't emulate the unstable API without emulating everything
//     else. Also enabled unconditionally on nightly, in which case the
//     procmacro2_semver_exempt surface area is implemented by using the
//     nightly-only proc_macro API.
//
// "hygiene"
//    Enable Span::mixed_site() and non-dummy behavior of Span::resolved_at
//    and Span::located_at. Enabled on Rust 1.45+.
//
// "proc_macro_span"
//     Enable non-dummy behavior of Span::start and Span::end methods which
//     requires an unstable compiler feature. Enabled when building with
//     nightly, unless `-Z allow-feature` in RUSTFLAGS disallows unstable
//     features.
//
// "super_unstable"
//     Implement the semver exempt API in terms of the nightly-only proc_macro
//     API. Enabled when using procmacro2_semver_exempt on a nightly compiler.
//
// "span_locations"
//     Provide methods Span::start and Span::end which give the line/column
//     location of a token. Enabled by procmacro2_semver_exempt or the
//     "span-locations" Cargo cfg. This is behind a cfg because tracking
//     location inside spans is a performance hit.
//
// "is_available"
//     Use proc_macro::is_available() to detect if the proc macro API is
//     available or needs to be polyfilled instead of trying to use the proc
//     macro API and catching a panic if it isn't available. Enabled on Rust
//     1.57+.

use std::env;
use std::process::{self, Command};
use std::str;
use std::u32;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let version = rustc_version().unwrap_or(RustcVersion {
        minor: u32::MAX,
        nightly: false,
    });

    if version.minor < 31 {
        eprintln!("Minimum supported rustc version is 1.31");
        process::exit(1);
    }

    let docs_rs = env::var_os("DOCS_RS").is_some();
    let semver_exempt = cfg!(procmacro2_semver_exempt) || docs_rs;
    if semver_exempt {
        // https://github.com/dtolnay/proc-macro2/issues/147
        println!("cargo:rustc-cfg=procmacro2_semver_exempt");
    }

    if semver_exempt || cfg!(feature = "span-locations") {
        println!("cargo:rustc-cfg=span_locations");
    }

    if version.minor < 32 {
        println!("cargo:rustc-cfg=no_libprocmacro_unwind_safe");
    }

    if version.minor < 34 {
        println!("cargo:rustc-cfg=no_try_from");
    }

    if version.minor < 39 {
        println!("cargo:rustc-cfg=no_bind_by_move_pattern_guard");
    }

    if version.minor < 44 {
        println!("cargo:rustc-cfg=no_lexerror_display");
    }

    if version.minor < 45 {
        println!("cargo:rustc-cfg=no_hygiene");
    }

    if version.minor < 47 {
        println!("cargo:rustc-cfg=no_ident_new_raw");
    }

    if version.minor < 54 {
        println!("cargo:rustc-cfg=no_literal_from_str");
    }

    if version.minor < 55 {
        println!("cargo:rustc-cfg=no_group_open_close");
    }

    if version.minor < 57 {
        println!("cargo:rustc-cfg=no_is_available");
    }

    if version.minor < 66 {
        println!("cargo:rustc-cfg=no_source_text");
    }

    if !cfg!(feature = "proc-macro") {
        return;
    }

    if version.nightly || !semver_exempt {
        println!("cargo:rustc-cfg=wrap_proc_macro");
    }

    if version.nightly && feature_allowed("proc_macro_span") {
        println!("cargo:rustc-cfg=proc_macro_span");
    }

    if semver_exempt && version.nightly {
        println!("cargo:rustc-cfg=super_unstable");
    }
}

struct RustcVersion {
    minor: u32,
    nightly: bool,
}

fn rustc_version() -> Option<RustcVersion> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let nightly = version.contains("nightly") || version.contains("dev");
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    let minor = pieces.next()?.parse().ok()?;
    Some(RustcVersion { minor, nightly })
}

fn feature_allowed(feature: &str) -> bool {
    // Recognized formats:
    //
    //     -Z allow-features=feature1,feature2
    //
    //     -Zallow-features=feature1,feature2

    let flags_var;
    let flags_var_string;
    let flags = if let Some(encoded_rustflags) = env::var_os("CARGO_ENCODED_RUSTFLAGS") {
        flags_var = encoded_rustflags;
        flags_var_string = flags_var.to_string_lossy();
        flags_var_string.split('\x1f')
    } else {
        return true;
    };

    for mut flag in flags {
        if flag.starts_with("-Z") {
            flag = &flag["-Z".len()..];
        }
        if flag.starts_with("allow-features=") {
            flag = &flag["allow-features=".len()..];
            return flag.split(',').any(|allowed| allowed == feature);
        }
    }

    // No allow-features= flag, allowed by default.
    true
}
========== build.rs from protobuf-3.1.0 ============================================================
use std::env;
use std::env::VarError;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::process;

// % rustc +stable --version
// rustc 1.26.0 (a77568041 2018-05-07)
// % rustc +beta --version
// rustc 1.27.0-beta.1 (03fb2f447 2018-05-09)
// % rustc +nightly --version
// rustc 1.27.0-nightly (acd3871ba 2018-05-10)
fn version_is_nightly(version: &str) -> bool {
    version.contains("nightly")
}

fn cfg_rust_version() {
    let rustc = env::var("RUSTC").expect("RUSTC unset");

    let mut child = process::Command::new(rustc)
        .args(&["--version"])
        .stdin(process::Stdio::null())
        .stdout(process::Stdio::piped())
        .spawn()
        .expect("spawn rustc");

    let mut rustc_version = String::new();

    child
        .stdout
        .as_mut()
        .expect("stdout")
        .read_to_string(&mut rustc_version)
        .expect("read_to_string");
    assert!(child.wait().expect("wait").success());

    if version_is_nightly(&rustc_version) {
        println!("cargo:rustc-cfg=rustc_nightly");
    }
}

fn cfg_serde() {
    match env::var("CARGO_FEATURE_WITH_SERDE") {
        Ok(_) => {
            println!("cargo:rustc-cfg=serde");
        }
        Err(VarError::NotUnicode(..)) => panic!(),
        Err(VarError::NotPresent) => {}
    }
}

fn out_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"))
}

fn version() -> String {
    env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION")
}

fn write_version() {
    let version = version();
    let version_ident = format!(
        "VERSION_{}",
        version.replace(".", "_").replace("-", "_").to_uppercase()
    );
    let mut file = File::create(Path::join(&out_dir(), "version.rs")).expect("open");
    writeln!(file, "/// protobuf crate version").unwrap();
    writeln!(file, "pub const VERSION: &'static str = \"{}\";", version).unwrap();
    writeln!(file, "/// This symbol is used by codegen").unwrap();
    writeln!(file, "#[doc(hidden)]").unwrap();
    writeln!(
        file,
        "pub const VERSION_IDENT: &'static str = \"{}\";",
        version_ident
    )
    .unwrap();
    writeln!(
        file,
        "/// This symbol can be referenced to assert that proper version of crate is used"
    )
    .unwrap();
    writeln!(file, "pub const {}: () = ();", version_ident).unwrap();
    file.flush().unwrap();
}

fn main() {
    cfg_rust_version();
    cfg_serde();
    write_version();
}
========== build.rs from quote-1.0.29 ============================================================
use std::env;
use std::process::{self, Command};
use std::str;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let version = match rustc_version() {
        Some(version) => version,
        None => return,
    };

    if version.minor < 31 {
        eprintln!("Minimum supported rustc version is 1.31");
        process::exit(1);
    }

    if version.minor < 53 {
        // https://github.com/rust-lang/rust/issues/43081
        println!("cargo:rustc-cfg=needs_invalid_span_workaround");
    }
}

struct RustcVersion {
    minor: u32,
}

fn rustc_version() -> Option<RustcVersion> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    let minor = pieces.next()?.parse().ok()?;
    Some(RustcVersion { minor })
}
========== build.rs from radium-0.6.2 ============================================================
//! Target detection
//!
//! This build script translates the target for which `radium` is being compiled
//! into a set of directives that the crate can use to control which atomic
//! symbols it attempts to name.
//!
//! The compiler maintains its store of target information here:
//! <https://github.com/rust-lang/rust/tree/be28b6235e64e0f662b96b710bf3af9de169215c/compiler/rustc_target/src/spec>
//!
//! That module is not easily extracted into something that can be loaded here,
//! so we are replicating it through string matching on the target name until
//! we are able to uniquely identify targets through `cfg` checks.
//!
//! Use `rustc --print target-list` to enumerate the full list of targets
//! available, and `rustc --print cfg` (optionally with `-Z unstable-options`)
//! to see what `cfg` values are produced for a target.
//!
//! The missing `cfg` checks required for conditional compilation, rather than a
//! build script, are:
//!
//! - [`accessible`](https://github.com/rust-lang/rust/issues/64797)
//! - [`target_feature`](https://github.com/rust-lang/rust/issues/69098)
//! - [`target_has_atomic`](https://github.com/rust-lang/rust/issues/32976)
//!
//! Once any of these becomes usable on the stable series, we can switch to a
//! set of `cfg` checks instead of a build script.

/// Collection of flags indicating whether the target processor supports atomic
/// instructions for a certain width.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct Atomics {
    /// Target supports 8-bit atomics
    has_8: bool,
    /// Target supports 16-bit atomics
    has_16: bool,
    /// Target supports 32-bit atomics
    has_32: bool,
    /// Target supports 64-bit atomics
    has_64: bool,
    /// Target supports word-width atomics
    has_ptr: bool,
}

impl Atomics {
    const ALL: Self = Self {
        has_8: true,
        has_16: true,
        has_32: true,
        has_64: true,
        has_ptr: true,
    };
    const NONE: Self = Self {
        has_8: false,
        has_16: false,
        has_32: false,
        has_64: false,
        has_ptr: false,
    };
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut atomics = Atomics::ALL;

    let target = std::env::var("TARGET")?;
    // Add new target strings here with their atomic availability.
    #[allow(clippy::match_single_binding, clippy::single_match)]
    match &*target {
        "arm-linux-androideabi" => atomics.has_64 = false,
        _ => {}
    }

    let arch = target.split('-').next().ok_or("Invalid target triple")?;
    // Add new architecture sections here with their atomic availability.
    #[allow(clippy::match_single_binding, clippy::single_match)]
    match arch {
        "armv5te" | "mips" | "mipsel" | "powerpc" | "riscv32imac" | "thumbv7em" | "thumbv7m"
        | "thumbv8m.main" | "armebv7r" | "armv7r" => atomics.has_64 = false,
        // These ARMv7 targets have 32-bit pointers and 64-bit atomics.
        "armv7" | "armv7a" | "armv7s" => atomics.has_64 = true,
        // "riscv32imc-unknown-none-elf" and "riscv32imac-unknown-none-elf" are
        // both `target_arch = "riscv32", and have no stable `cfg`-discoverable
        // distinction. As such, the non-atomic RISC-V targets must be
        // discovered here.
        "riscv32i" | "riscv32imc" | "thumbv6m" => atomics = Atomics::NONE,
        _ => {}
    }

    if atomics.has_8 {
        println!("cargo:rustc-cfg=radium_atomic_8");
    }
    if atomics.has_16 {
        println!("cargo:rustc-cfg=radium_atomic_16");
    }
    if atomics.has_32 {
        println!("cargo:rustc-cfg=radium_atomic_32");
    }
    if atomics.has_64 {
        println!("cargo:rustc-cfg=radium_atomic_64");
    }
    if atomics.has_ptr {
        println!("cargo:rustc-cfg=radium_atomic_ptr");
    }

    Ok(())
}
========== build.rs from rayon-1.5.3 ============================================================
fn main() {
    let ac = autocfg::new();
    if ac.probe_expression("(0..10).step_by(2).rev()") {
        autocfg::emit("has_step_by_rev");
    }
    if ac.probe_expression("{ fn _foo<const N: usize>() {} }") {
        autocfg::emit("has_min_const_generics");
    }
    if ac.probe_path("std::ops::ControlFlow") {
        autocfg::emit("has_control_flow");
    }
}
========== build.rs from rayon-core-1.9.3 ============================================================
// We need a build script to use `link = "rayon-core"`.  But we're not
// *actually* linking to anything, just making sure that we're the only
// rayon-core in use.
fn main() {
    // we don't need to rebuild for anything else
    println!("cargo:rerun-if-changed=build.rs");
}
========== build.rs from riscv-0.7.0 ============================================================
extern crate riscv_target;

use riscv_target::Target;
use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let target = env::var("TARGET").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let name = env::var("CARGO_PKG_NAME").unwrap();

    if target.starts_with("riscv") && env::var_os("CARGO_FEATURE_INLINE_ASM").is_none() {
        let mut target = Target::from_target_str(&target);
        target.retain_extensions("ifdc");

        let target = target.to_string();

        fs::copy(
            format!("bin/{}.a", target),
            out_dir.join(format!("lib{}.a", name)),
        )
        .unwrap();

        println!("cargo:rustc-link-lib=static={}", name);
        println!("cargo:rustc-link-search={}", out_dir.display());
    }

    if target.starts_with("riscv32") {
        println!("cargo:rustc-cfg=riscv");
        println!("cargo:rustc-cfg=riscv32");
    } else if target.starts_with("riscv64") {
        println!("cargo:rustc-cfg=riscv");
        println!("cargo:rustc-cfg=riscv64");
    }
}
========== build.rs from rkyv-0.4.3 ============================================================
use std::env;

fn main() {
    let target = env::var("TARGET").unwrap();

    let emscripten = target == "asmjs-unknown-emscripten" || target == "wasm32-unknown-emscripten";

    let has_atomic64 = target.starts_with("x86_64")
        || target.starts_with("i686")
        || target.starts_with("aarch64")
        || target.starts_with("powerpc64")
        || target.starts_with("sparc64")
        || target.starts_with("mips64el");
    let has_atomic32 = has_atomic64 || emscripten;

    if has_atomic64 {
        println!("cargo:rustc-cfg=rkyv_atomic_64");
    }

    if has_atomic32 {
        println!("cargo:rustc-cfg=rkyv_atomic");
    }
}
========== build.rs from rustix-0.38.4 ============================================================
use std::env::var;
use std::io::Write;

/// The directory for inline asm.
const ASM_PATH: &str = "src/backend/linux_raw/arch/asm";

fn main() {
    // Don't rerun this on changes other than build.rs, as we only depend on
    // the rustc version.
    println!("cargo:rerun-if-changed=build.rs");

    use_feature_or_nothing("rustc_attrs");

    // Features only used in no-std configurations.
    #[cfg(not(feature = "std"))]
    {
        use_feature_or_nothing("core_c_str");
        use_feature_or_nothing("core_ffi_c");
        use_feature_or_nothing("alloc_c_string");
        use_feature_or_nothing("alloc_ffi");
    }

    // Gather target information.
    let arch = var("CARGO_CFG_TARGET_ARCH").unwrap();
    let inline_asm_name = format!("{}/{}.rs", ASM_PATH, arch);
    let inline_asm_name_present = std::fs::metadata(inline_asm_name).is_ok();
    let target_os = var("CARGO_CFG_TARGET_OS").unwrap();
    let pointer_width = var("CARGO_CFG_TARGET_POINTER_WIDTH").unwrap();
    let endian = var("CARGO_CFG_TARGET_ENDIAN").unwrap();

    // Check for special target variants.
    let is_x32 = arch == "x86_64" && pointer_width == "32";
    let is_arm64_ilp32 = arch == "aarch64" && pointer_width == "32";
    let is_powerpc64be = arch == "powerpc64" && endian == "big";
    let is_mipseb = arch == "mips" && endian == "big";
    let is_mips64eb = arch == "mips64" && endian == "big";
    let is_unsupported_abi = is_x32 || is_arm64_ilp32 || is_powerpc64be || is_mipseb || is_mips64eb;

    // Check for `--features=use-libc`. This allows crate users to enable the
    // libc backend.
    let feature_use_libc = var("CARGO_FEATURE_USE_LIBC").is_ok();

    // Check for `RUSTFLAGS=--cfg=rustix_use_libc`. This allows end users to
    // enable the libc backend even if rustix is depended on transitively.
    let cfg_use_libc = var("CARGO_CFG_RUSTIX_USE_LIBC").is_ok();

    // Check for eg. `RUSTFLAGS=--cfg=rustix_use_experimental_asm`. This is a
    // rustc flag rather than a cargo feature flag because it's experimental
    // and not something we want accidentally enabled via `--all-features`.
    let rustix_use_experimental_asm = var("CARGO_CFG_RUSTIX_USE_EXPERIMENTAL_ASM").is_ok();

    // Miri doesn't support inline asm, and has builtin support for recognizing
    // libc FFI calls, so if we're running under miri, use the libc backend.
    let miri = var("CARGO_CFG_MIRI").is_ok();

    // If the libc backend is requested, or if we're not on a platform for
    // which we have linux_raw support, use the libc backend.
    //
    // For now Android uses the libc backend; in theory it could use the
    // linux_raw backend, but to do that we'll need to figure out how to
    // install the toolchain for it.
    if feature_use_libc
        || cfg_use_libc
        || target_os != "linux"
        || !inline_asm_name_present
        || is_unsupported_abi
        || miri
        || ((arch == "powerpc64" || arch == "mips" || arch == "mips64")
            && !rustix_use_experimental_asm)
    {
        // Use the libc backend.
        use_feature("libc");
    } else {
        // Use the linux_raw backend.
        use_feature("linux_raw");
        use_feature_or_nothing("core_intrinsics");
        if rustix_use_experimental_asm {
            use_feature("asm_experimental_arch");
        }
    }

    // Detect whether the compiler requires us to use thumb mode on ARM.
    if arch == "arm" && use_thumb_mode() {
        use_feature("thumb_mode");
    }

    // Rust's libc crate groups some OS's together which have similar APIs;
    // create similarly-named features to make `cfg` tests more concise.
    if target_os == "freebsd" || target_os == "dragonfly" {
        use_feature("freebsdlike");
    }
    if target_os == "openbsd" || target_os == "netbsd" {
        use_feature("netbsdlike");
    }
    if target_os == "macos" || target_os == "ios" || target_os == "tvos" || target_os == "watchos" {
        use_feature("apple");
    }
    if target_os == "linux"
        || target_os == "l4re"
        || target_os == "android"
        || target_os == "emscripten"
    {
        use_feature("linux_like");
    }
    if target_os == "solaris" || target_os == "illumos" {
        use_feature("solarish");
    }
    if target_os == "macos"
        || target_os == "ios"
        || target_os == "tvos"
        || target_os == "watchos"
        || target_os == "freebsd"
        || target_os == "dragonfly"
        || target_os == "openbsd"
        || target_os == "netbsd"
    {
        use_feature("bsd");
    }

    // Add some additional common target combinations.
    if target_os == "android" || target_os == "linux" {
        use_feature("linux_kernel");
    }

    if target_os == "wasi" {
        use_feature_or_nothing("wasi_ext");
    }

    println!("cargo:rerun-if-env-changed=CARGO_CFG_RUSTIX_USE_EXPERIMENTAL_ASM");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_RUSTIX_USE_LIBC");

    // Rerun this script if any of our features or configuration flags change,
    // or if the toolchain we used for feature detection changes.
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_USE_LIBC");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_RUSTC_DEP_OF_STD");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_MIRI");
}

fn use_thumb_mode() -> bool {
    // In thumb mode, r7 is reserved.
    !can_compile("pub unsafe fn f() { core::arch::asm!(\"udf #16\", in(\"r7\") 0); }")
}

fn use_feature_or_nothing(feature: &str) {
    if has_feature(feature) {
        use_feature(feature);
    }
}

fn use_feature(feature: &str) {
    println!("cargo:rustc-cfg={}", feature);
}

/// Test whether the rustc at `var("RUSTC")` supports the given feature.
fn has_feature(feature: &str) -> bool {
    can_compile(format!(
        "#![allow(stable_features)]\n#![feature({})]",
        feature
    ))
}

/// Test whether the rustc at `var("RUSTC")` can compile the given code.
fn can_compile<T: AsRef<str>>(test: T) -> bool {
    use std::process::Stdio;

    let out_dir = var("OUT_DIR").unwrap();
    let rustc = var("RUSTC").unwrap();
    let target = var("TARGET").unwrap();

    // Use `RUSTC_WRAPPER` if it's set, unless it's set to an empty string, as
    // documented [here].
    // [here]: https://doc.rust-lang.org/cargo/reference/environment-variables.html#environment-variables-cargo-reads
    let wrapper = var("RUSTC_WRAPPER")
        .ok()
        .and_then(|w| if w.is_empty() { None } else { Some(w) });

    let mut cmd = if let Some(wrapper) = wrapper {
        let mut cmd = std::process::Command::new(wrapper);
        // The wrapper's first argument is supposed to be the path to rustc.
        cmd.arg(rustc);
        cmd
    } else {
        std::process::Command::new(rustc)
    };

    cmd.arg("--crate-type=rlib") // Don't require `main`.
        .arg("--emit=metadata") // Do as little as possible but still parse.
        .arg("--target")
        .arg(target)
        .arg("--out-dir")
        .arg(out_dir); // Put the output somewhere inconsequential.

    // If Cargo wants to set RUSTFLAGS, use that.
    if let Ok(rustflags) = var("CARGO_ENCODED_RUSTFLAGS") {
        if !rustflags.is_empty() {
            for arg in rustflags.split('\x1f') {
                cmd.arg(arg);
            }
        }
    }

    let mut child = cmd
        .arg("-") // Read from stdin.
        .stdin(Stdio::piped()) // Stdin is a pipe.
        .stderr(Stdio::null()) // Errors from feature detection aren't interesting and can be confusing.
        .spawn()
        .unwrap();

    writeln!(child.stdin.take().unwrap(), "{}", test.as_ref()).unwrap();

    child.wait().unwrap().success()
}
========== build.rs from rustls-0.20.6 ============================================================
/// This build script allows us to enable the `read_buf` language feature only
/// for Rust Nightly.
///
/// See the comment in lib.rs to understand why we need this.

#[cfg_attr(feature = "read_buf", rustversion::not(nightly))]
fn main() {}

#[cfg(feature = "read_buf")]
#[rustversion::nightly]
fn main() {
    println!("cargo:rustc-cfg=read_buf");
}
========== build.rs from rustls-0.21.2 ============================================================
/// This build script allows us to enable the `read_buf` language feature only
/// for Rust Nightly.
///
/// See the comment in lib.rs to understand why we need this.

#[cfg_attr(feature = "read_buf", rustversion::not(nightly))]
fn main() {}

#[cfg(feature = "read_buf")]
#[rustversion::nightly]
fn main() {
    println!("cargo:rustc-cfg=read_buf");
}
========== build.rs from sdl2-0.35.2 ============================================================
fn main() {
    #[cfg(any(target_os = "openbsd", target_os = "freebsd"))]
    println!(r"cargo:rustc-link-search=/usr/local/lib");
}
========== build.rs from sdl2-sys-0.35.2 ============================================================
#![allow(unused_imports, dead_code, unused_variables)]

#[cfg(feature = "bindgen")]
extern crate bindgen;
#[macro_use]
extern crate cfg_if;
#[cfg(feature = "bundled")]
extern crate cmake;
#[cfg(feature = "pkg-config")]
extern crate pkg_config;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs, io};

#[cfg(feature = "bindgen")]
macro_rules! add_msvc_includes_to_bindings {
    ($bindings:expr) => {
        $bindings = $bindings.clang_arg(format!(
            "-IC:/Program Files (x86)/Windows Kits/8.1/Include/shared"
        ));
        $bindings = $bindings.clang_arg(format!("-IC:/Program Files/LLVM/lib/clang/5.0.0/include"));
        $bindings = $bindings.clang_arg(format!(
            "-IC:/Program Files (x86)/Windows Kits/10/Include/10.0.10240.0/ucrt"
        ));
        $bindings = $bindings.clang_arg(format!(
            "-IC:/Program Files (x86)/Microsoft Visual Studio 14.0/VC/include"
        ));
        $bindings = $bindings.clang_arg(format!(
            "-IC:/Program Files (x86)/Windows Kits/8.1/Include/um"
        ));
    };
}

fn init_submodule(sdl_path: &Path) {
    if !sdl_path.join("CMakeLists.txt").exists() {
        Command::new("git")
            .args(&["submodule", "update", "--init"])
            .current_dir(sdl_path.clone())
            .status()
            .expect("Git is needed to retrieve the SDL source files");
    }
}

#[cfg(feature = "use-pkgconfig")]
fn pkg_config_print(statik: bool, lib_name: &str) {
    pkg_config::Config::new()
        .statik(statik)
        .probe(lib_name)
        .unwrap();
}

#[cfg(feature = "use-pkgconfig")]
fn get_pkg_config() {
    let statik: bool = if cfg!(feature = "static-link") {
        true
    } else {
        false
    };

    pkg_config_print(statik, "sdl2");
    if cfg!(feature = "image") {
        pkg_config_print(statik, "SDL2_image");
    }
    if cfg!(feature = "ttf") {
        pkg_config_print(statik, "SDL2_ttf");
    }
    if cfg!(feature = "mixer") {
        pkg_config_print(statik, "SDL2_mixer");
    }
    if cfg!(feature = "gfx") {
        pkg_config_print(statik, "SDL2_gfx");
    }
}

#[cfg(feature = "use-vcpkg")]
fn get_vcpkg_config() {
    vcpkg::find_package("sdl2").unwrap();
    if cfg!(feature = "image") {
        vcpkg::find_package("sdl2-image").unwrap();
    }
    if cfg!(feature = "ttf") {
        vcpkg::find_package("sdl2-ttf").unwrap();
    }
    if cfg!(feature = "mixer") {
        vcpkg::find_package("sdl2-mixer").unwrap();
    }
    if cfg!(feature = "gfx") {
        vcpkg::find_package("sdl2-gfx").unwrap();
    }
}

// compile a shared or static lib depending on the feature
#[cfg(feature = "bundled")]
fn compile_sdl2(sdl2_build_path: &Path, target_os: &str) -> PathBuf {
    let mut cfg = cmake::Config::new(sdl2_build_path);
    if let Ok(profile) = env::var("SDL2_BUILD_PROFILE") {
        cfg.profile(&profile);
    } else {
        cfg.profile("release");
    }

    // Allow specifying custom toolchain specifically for SDL2.
    if let Ok(toolchain) = env::var("SDL2_TOOLCHAIN") {
        cfg.define("CMAKE_TOOLCHAIN_FILE", &toolchain);
    } else {
        // Override __FLTUSED__ to keep the _fltused symbol from getting defined in the static build.
        // This conflicts and fails to link properly when building statically on Windows, likely due to
        // COMDAT conflicts/breakage happening somewhere.
        #[cfg(feature = "static-link")]
        cfg.cflag("-D__FLTUSED__");

        #[cfg(target_os = "linux")]
        {
            // Add common flag for affected version and above
            use version_compare::{compare_to, Cmp};
            if let Ok(version) = std::process::Command::new("cc")
                .arg("-dumpversion")
                .output()
            {
                let affected =
                    compare_to(std::str::from_utf8(&version.stdout).unwrap(), "10", Cmp::Ge)
                        .unwrap_or(true);
                if affected {
                    cfg.cflag("-fcommon");
                }
            }
        }
    }

    if target_os == "windows-gnu" {
        cfg.define("VIDEO_OPENGLES", "OFF");
    }

    if cfg!(feature = "static-link") {
        cfg.define("SDL_SHARED", "OFF");
        cfg.define("SDL_STATIC", "ON");
    } else {
        cfg.define("SDL_SHARED", "ON");
        cfg.define("SDL_STATIC", "OFF");
    }

    cfg.build()
}

#[cfg(not(feature = "bundled"))]
fn compute_include_paths(fallback_path: String) -> Vec<String> {
    let mut include_paths: Vec<String> = vec![];

    if let Ok(include_path) = env::var("SDL2_INCLUDE_PATH") {
        include_paths.push(include_path);
    };

    #[cfg(feature = "pkg-config")]
    {
        // don't print the "cargo:xxx" directives, we're just trying to get the include paths here
        let pkg_config_library = pkg_config::Config::new()
            .print_system_libs(false)
            .probe("sdl2")
            .unwrap();
        for path in pkg_config_library.include_paths {
            include_paths.push(format!("{}", path.display()));
        }
    }

    #[cfg(feature = "vcpkg")]
    {
        // don't print the "cargo:xxx" directives, we're just trying to get the include paths here
        let vcpkg_library = vcpkg::Config::new()
            .cargo_metadata(false)
            .probe("sdl2")
            .unwrap();
        for path in vcpkg_library.include_paths {
            include_paths.push(format!("{}", path.display()));
        }
    }

    if include_paths.is_empty() {
        include_paths.push(fallback_path);
    }

    include_paths
}

fn link_sdl2(target_os: &str) {
    #[cfg(all(feature = "use-pkgconfig", not(feature = "bundled")))]
    {
        // prints the appropriate linking parameters when using pkg-config
        // useless when using "bundled"
        get_pkg_config();
    }

    #[cfg(all(feature = "use-vcpkg", not(feature = "bundled")))]
    {
        // prints the appropriate linking parameters when using pkg-config
        // useless when using "bundled"
        get_vcpkg_config();
    }

    #[cfg(not(feature = "static-link"))]
    {
        if target_os == "ios" {
            // iOS requires additional linking to function properly
            println!("cargo:rustc-flags=-l framework=AVFoundation");
            println!("cargo:rustc-flags=-l framework=AudioToolbox");
            println!("cargo:rustc-flags=-l framework=CoreAudio");
            println!("cargo:rustc-flags=-l framework=CoreGraphics");
            println!("cargo:rustc-flags=-l framework=CoreMotion");
            println!("cargo:rustc-flags=-l framework=Foundation");
            println!("cargo:rustc-flags=-l framework=GameController");
            println!("cargo:rustc-flags=-l framework=OpenGLES");
            println!("cargo:rustc-flags=-l framework=QuartzCore");
            println!("cargo:rustc-flags=-l framework=UIKit");
        }

        // pkg-config automatically prints this output when probing,
        // however pkg_config isn't used with the feature "bundled"
        if cfg!(feature = "bundled") || cfg!(not(feature = "use-pkgconfig")) {
            if cfg!(feature = "use_mac_framework") && target_os == "darwin" {
                println!("cargo:rustc-flags=-l framework=SDL2");
            } else if target_os != "emscripten" {
                println!("cargo:rustc-flags=-l SDL2");
            }
        }
    }

    #[cfg(feature = "static-link")]
    {
        if cfg!(feature = "bundled")
            || (cfg!(feature = "use-pkgconfig") == false && cfg!(feature = "use-vcpkg") == false)
        {
            println!("cargo:rustc-link-lib=static=SDL2main");
            println!("cargo:rustc-link-lib=static=SDL2");
        }

        // Also linked to any required libraries for each supported platform
        if target_os.contains("windows") {
            println!("cargo:rustc-link-lib=shell32");
            println!("cargo:rustc-link-lib=user32");
            println!("cargo:rustc-link-lib=gdi32");
            println!("cargo:rustc-link-lib=winmm");
            println!("cargo:rustc-link-lib=imm32");
            println!("cargo:rustc-link-lib=ole32");
            println!("cargo:rustc-link-lib=oleaut32");
            println!("cargo:rustc-link-lib=version");
            println!("cargo:rustc-link-lib=uuid");
            println!("cargo:rustc-link-lib=dinput8");
            println!("cargo:rustc-link-lib=dxguid");
            println!("cargo:rustc-link-lib=setupapi");
        } else if target_os == "darwin" {
            println!("cargo:rustc-link-lib=framework=Cocoa");
            println!("cargo:rustc-link-lib=framework=IOKit");
            println!("cargo:rustc-link-lib=framework=Carbon");
            println!("cargo:rustc-link-lib=framework=ForceFeedback");
            println!("cargo:rustc-link-lib=framework=GameController");
            println!("cargo:rustc-link-lib=framework=CoreVideo");
            println!("cargo:rustc-link-lib=framework=CoreAudio");
            println!("cargo:rustc-link-lib=framework=AudioToolbox");
            println!("cargo:rustc-link-lib=framework=Metal");
            println!("cargo:rustc-link-lib=iconv");
        } else if target_os == "android" {
            println!("cargo:rustc-link-lib=android");
            println!("cargo:rustc-link-lib=dl");
            println!("cargo:rustc-link-lib=GLESv1_CM");
            println!("cargo:rustc-link-lib=GLESv2");
            println!("cargo:rustc-link-lib=hidapi");
            println!("cargo:rustc-link-lib=log");
            println!("cargo:rustc-link-lib=OpenSLES");
        } else {
            // TODO: Add other platform linker options here.
        }
    }
    // SDL libraries seem to not be packed with pkgconfig file on all distros,
    // and in the same distros (fedora at least) a symlink is also missing.
    //
    // Linking directly with file is not possible with cargo since the
    // ':filename' syntax is used for renaming of libraries, which basically
    // leaves it up to the user to make a symlink to the shared object so
    // -lSDL2_mixer can find it.
    #[cfg(all(not(feature = "use-pkgconfig"), not(feature = "static-link")))]
    {
        if cfg!(feature = "mixer") {
            if target_os.contains("linux")
                || target_os.contains("freebsd")
                || target_os.contains("openbsd")
            {
                println!("cargo:rustc-flags=-l SDL2_mixer");
            } else if target_os.contains("windows") {
                println!("cargo:rustc-flags=-l SDL2_mixer");
            } else if target_os.contains("darwin") {
                if cfg!(any(mac_framework, feature = "use_mac_framework")) {
                    println!("cargo:rustc-flags=-l framework=SDL2_mixer");
                } else {
                    println!("cargo:rustc-flags=-l SDL2_mixer");
                }
            }
        }
        if cfg!(feature = "image") {
            if target_os.contains("linux")
                || target_os.contains("freebsd")
                || target_os.contains("openbsd")
            {
                println!("cargo:rustc-flags=-l SDL2_image");
            } else if target_os.contains("windows") {
                println!("cargo:rustc-flags=-l SDL2_image");
            } else if target_os.contains("darwin") {
                if cfg!(any(mac_framework, feature = "use_mac_framework")) {
                    println!("cargo:rustc-flags=-l framework=SDL2_image");
                } else {
                    println!("cargo:rustc-flags=-l SDL2_image");
                }
            }
        }
        if cfg!(feature = "ttf") {
            if target_os.contains("linux")
                || target_os.contains("freebsd")
                || target_os.contains("openbsd")
            {
                println!("cargo:rustc-flags=-l SDL2_ttf");
            } else if target_os.contains("windows") {
                println!("cargo:rustc-flags=-l SDL2_ttf");
            } else if target_os.contains("darwin") {
                if cfg!(any(mac_framework, feature = "use_mac_framework")) {
                    println!("cargo:rustc-flags=-l framework=SDL2_ttf");
                } else {
                    println!("cargo:rustc-flags=-l SDL2_ttf");
                }
            }
        }
        if cfg!(feature = "gfx") {
            if target_os.contains("linux")
                || target_os.contains("freebsd")
                || target_os.contains("openbsd")
            {
                println!("cargo:rustc-flags=-l SDL2_gfx");
            } else if target_os.contains("windows") {
                println!("cargo:rustc-flags=-l SDL2_gfx");
            } else if target_os.contains("darwin") {
                if cfg!(any(mac_framework, feature = "use_mac_framework")) {
                    println!("cargo:rustc-flags=-l framework=SDL2_gfx");
                } else {
                    println!("cargo:rustc-flags=-l SDL2_gfx");
                }
            }
        }
    }
}

fn find_cargo_target_dir() -> PathBuf {
    // Infer the top level cargo target dir from the OUT_DIR by searching
    // upwards until we get to $CARGO_TARGET_DIR/build/ (which is always one
    // level up from the deepest directory containing our package name)
    let pkg_name = env::var("CARGO_PKG_NAME").unwrap();
    let mut out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    loop {
        {
            let final_path_segment = out_dir.file_name().unwrap();
            if final_path_segment.to_string_lossy().contains(&pkg_name) {
                break;
            }
        }
        if !out_dir.pop() {
            panic!("Malformed build path: {}", out_dir.to_string_lossy());
        }
    }
    out_dir.pop();
    out_dir.pop();
    out_dir
}

#[cfg(unix)]
fn copy_library_symlink(src_path: &Path, target_path: &Path) {
    if let Ok(link_path) = fs::read_link(src_path) {
        // Copy symlinks to:
        //  * target dir: as a product ship product of the build,
        //  * deps directory: as comment example testing doesn't pick up the library search path
        //    otherwise and fails.
        let deps_path = target_path.join("deps");
        for path in &[target_path, &deps_path] {
            let dst_path = path.join(src_path.file_name().expect("Path missing filename"));
            // Silently drop errors here, in case the symlink already exists.
            let _ = std::os::unix::fs::symlink(&link_path, &dst_path);
        }
    }
}

#[cfg(not(unix))]
fn copy_library_symlink(src_path: &Path, target_path: &Path) {}

fn copy_library_file(src_path: &Path, target_path: &Path) {
    // Copy the shared libs to:
    //  * target dir: as a product ship product of the build,
    //  * deps directory: as comment example testing doesn't pick up the library search path
    //    otherwise and fails.
    let deps_path = target_path.join("deps");
    for path in &[target_path, &deps_path] {
        let dst_path = path.join(src_path.file_name().expect("Path missing filename"));

        fs::copy(&src_path, &dst_path).expect(&format!(
            "Failed to copy SDL2 dynamic library from {} to {}",
            src_path.to_string_lossy(),
            dst_path.to_string_lossy()
        ));
    }
}

fn copy_dynamic_libraries(sdl2_compiled_path: &PathBuf, target_os: &str) {
    let target_path = find_cargo_target_dir();

    // Windows binaries do not embed library search paths, so successfully
    // linking the DLL isn't sufficient to find it at runtime -- it must be
    // either on PATH or in the current working directory when we run binaries
    // linked against it. In other words, to run the test suite we need to
    // copy sdl2.dll out of its build tree and down to the top level cargo
    // binary output directory.
    if target_os.contains("windows") {
        let sdl2_dll_name = "SDL2.dll";
        let sdl2_bin_path = sdl2_compiled_path.join("bin");
        let src_dll_path = sdl2_bin_path.join(sdl2_dll_name);

        copy_library_file(&src_dll_path, &target_path);
    } else if target_os != "emscripten" {
        // Find all libraries build and copy them, symlinks included.
        let mut found = false;
        let lib_dirs = &["lib", "lib64"];
        for lib_dir in lib_dirs {
            let lib_path = sdl2_compiled_path.join(lib_dir);
            if lib_path.exists() {
                found = true;
                for entry in std::fs::read_dir(&lib_path)
                    .unwrap_or_else(|_| panic!("Couldn't readdir {}", lib_dir))
                {
                    let entry = entry.expect("Error looking at lib dir");
                    if let Ok(file_type) = entry.file_type() {
                        if file_type.is_symlink() {
                            copy_library_symlink(&entry.path(), &target_path);
                        } else if file_type.is_file() {
                            copy_library_file(&entry.path(), &target_path)
                        }
                    }
                }
                break;
            }
        }
        if !found {
            panic!("Failed to find CMake output dir");
        }
    }
}

fn main() {
    let target = env::var("TARGET").expect("Cargo build scripts always have TARGET");
    let host = env::var("HOST").expect("Cargo build scripts always have HOST");
    let target_os = get_os_from_triple(target.as_str()).unwrap();

    let sdl2_source_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("SDL");
    init_submodule(sdl2_source_path.as_path());

    let sdl2_compiled_path: PathBuf;
    #[cfg(feature = "bundled")]
    {
        sdl2_compiled_path = compile_sdl2(sdl2_source_path.as_path(), target_os);

        let sdl2_compiled_lib_path = sdl2_compiled_path.join("lib");
        println!(
            "cargo:rustc-link-search={}",
            sdl2_compiled_lib_path.display()
        );
    }

    let sdl2_includes = sdl2_source_path
        .join("include")
        .to_str()
        .unwrap()
        .to_string();

    #[cfg(feature = "bindgen")]
    {
        let include_paths: Vec<String>;
        #[cfg(feature = "bundled")]
        {
            include_paths = vec![sdl2_includes];
        }
        #[cfg(not(feature = "bundled"))]
        {
            include_paths = compute_include_paths(sdl2_includes)
        }
        generate_bindings(target.as_str(), host.as_str(), include_paths.as_slice());
        println!("cargo:include={}", include_paths.join(":"));
    }

    #[cfg(not(feature = "bindgen"))]
    {
        copy_pregenerated_bindings();
        println!("cargo:include={}", sdl2_includes);
    }

    link_sdl2(target_os);

    // Android builds shared libhidapi.so even for static builds.
    #[cfg(all(
        feature = "bundled",
        any(not(feature = "static-link"), target_os = "android")
    ))]
    {
        copy_dynamic_libraries(&sdl2_compiled_path, target_os);
    }
}

#[cfg(not(feature = "bindgen"))]
fn copy_pregenerated_bindings() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let crate_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    fs::copy(
        crate_path.join("sdl_bindings.rs"),
        out_path.join("sdl_bindings.rs"),
    )
    .expect("Couldn't find pregenerated bindings!");

    if cfg!(feature = "image") {
        fs::copy(
            crate_path.join("sdl_image_bindings.rs"),
            out_path.join("sdl_image_bindings.rs"),
        )
        .expect("Couldn't find pregenerated SDL_image bindings!");
    }
    if cfg!(feature = "ttf") {
        fs::copy(
            crate_path.join("sdl_ttf_bindings.rs"),
            out_path.join("sdl_ttf_bindings.rs"),
        )
        .expect("Couldn't find pregenerated SDL_ttf bindings!");
    }
    if cfg!(feature = "mixer") {
        fs::copy(
            crate_path.join("sdl_mixer_bindings.rs"),
            out_path.join("sdl_mixer_bindings.rs"),
        )
        .expect("Couldn't find pregenerated SDL_mixer bindings!");
    }

    if cfg!(feature = "gfx") {
        fs::copy(
            crate_path.join("sdl_gfx_framerate_bindings.rs"),
            out_path.join("sdl_gfx_framerate_bindings.rs"),
        )
        .expect("Couldn't find pregenerated SDL_gfx framerate bindings!");

        fs::copy(
            crate_path.join("sdl_gfx_primitives_bindings.rs"),
            out_path.join("sdl_gfx_primitives_bindings.rs"),
        )
        .expect("Couldn't find pregenerated SDL_gfx primitives bindings!");

        fs::copy(
            crate_path.join("sdl_gfx_imagefilter_bindings.rs"),
            out_path.join("sdl_gfx_imagefilter_bindings.rs"),
        )
        .expect("Couldn't find pregenerated SDL_gfx imagefilter bindings!");

        fs::copy(
            crate_path.join("sdl_gfx_rotozoom_bindings.rs"),
            out_path.join("sdl_gfx_rotozoom_bindings.rs"),
        )
        .expect("Couldn't find pregenerated SDL_gfx rotozoom bindings!");
    }
}

#[cfg(feature = "bindgen")]
// headers_path is a list of directories where the SDL2 headers are expected
// to be found by bindgen (should point to the include/ directories)
fn generate_bindings(target: &str, host: &str, headers_paths: &[String]) {
    let target_os = get_os_from_triple(target).unwrap();
    let mut bindings = bindgen::Builder::default()
        // enable no_std-friendly output by only using core definitions
        .use_core()
        .default_enum_style(bindgen::EnumVariation::Rust {
            non_exhaustive: false,
        })
        .ctypes_prefix("libc");

    let mut image_bindings = bindgen::Builder::default()
        .use_core()
        .raw_line("use crate::*;")
        .ctypes_prefix("libc");

    let mut ttf_bindings = bindgen::Builder::default()
        .use_core()
        .raw_line("use crate::*;")
        .ctypes_prefix("libc");

    let mut mixer_bindings = bindgen::Builder::default()
        .use_core()
        .raw_line("use crate::*;")
        .ctypes_prefix("libc");

    let mut gfx_framerate_bindings = bindgen::Builder::default().use_core().ctypes_prefix("libc");
    let mut gfx_primitives_bindings = bindgen::Builder::default()
        .use_core()
        .raw_line("use crate::*;")
        .ctypes_prefix("libc");
    let mut gfx_imagefilter_bindings = bindgen::Builder::default().use_core().ctypes_prefix("libc");
    let mut gfx_rotozoom_bindings = bindgen::Builder::default()
        .use_core()
        .raw_line("use crate::*;")
        .ctypes_prefix("libc");

    // Set correct target triple for bindgen when cross-compiling
    if target != host {
        bindings = bindings.clang_arg("-target");
        bindings = bindings.clang_arg(target.clone());

        if cfg!(feature = "image") {
            image_bindings = image_bindings.clang_arg("-target");
            image_bindings = image_bindings.clang_arg(target.clone());
        }

        if cfg!(feature = "ttf") {
            ttf_bindings = ttf_bindings.clang_arg("-target");
            ttf_bindings = ttf_bindings.clang_arg(target.clone());
        }

        if cfg!(feature = "mixer") {
            mixer_bindings = mixer_bindings.clang_arg("-target");
            mixer_bindings = mixer_bindings.clang_arg(target.clone());
        }

        if cfg!(feature = "gfx") {
            gfx_framerate_bindings = gfx_framerate_bindings.clang_arg("-target");
            gfx_framerate_bindings = gfx_framerate_bindings.clang_arg(target.clone());

            gfx_primitives_bindings = gfx_primitives_bindings.clang_arg("-target");
            gfx_primitives_bindings = gfx_primitives_bindings.clang_arg(target.clone());

            gfx_imagefilter_bindings = gfx_imagefilter_bindings.clang_arg("-target");
            gfx_imagefilter_bindings = gfx_imagefilter_bindings.clang_arg(target.clone());

            gfx_rotozoom_bindings = gfx_rotozoom_bindings.clang_arg("-target");
            gfx_rotozoom_bindings = gfx_rotozoom_bindings.clang_arg(target.clone());
        }
    }

    for headers_path in headers_paths {
        bindings = bindings.clang_arg(format!("-I{}", headers_path));
        if cfg!(feature = "image") {
            image_bindings = image_bindings.clang_arg(format!("-I{}", headers_path));
        }
        if cfg!(feature = "ttf") {
            ttf_bindings = ttf_bindings.clang_arg(format!("-I{}", headers_path));
        }
        if cfg!(feature = "mixer") {
            mixer_bindings = mixer_bindings.clang_arg(format!("-I{}", headers_path));
        }
        if cfg!(feature = "gfx") {
            gfx_framerate_bindings =
                gfx_framerate_bindings.clang_arg(format!("-I{}", headers_path));
            gfx_primitives_bindings =
                gfx_primitives_bindings.clang_arg(format!("-I{}", headers_path));
            gfx_imagefilter_bindings =
                gfx_imagefilter_bindings.clang_arg(format!("-I{}", headers_path));
            gfx_rotozoom_bindings = gfx_rotozoom_bindings.clang_arg(format!("-I{}", headers_path));
        }
    }

    if target_os == "windows-msvc" {
        add_msvc_includes_to_bindings!(bindings);
        if cfg!(feature = "image") {
            add_msvc_includes_to_bindings!(image_bindings);
        }
        if cfg!(feature = "ttf") {
            add_msvc_includes_to_bindings!(ttf_bindings);
        }
        if cfg!(feature = "mixer") {
            add_msvc_includes_to_bindings!(mixer_bindings);
        }
        if cfg!(feature = "gfx") {
            add_msvc_includes_to_bindings!(gfx_framerate_bindings);
            add_msvc_includes_to_bindings!(gfx_primitives_bindings);
            add_msvc_includes_to_bindings!(gfx_imagefilter_bindings);
            add_msvc_includes_to_bindings!(gfx_rotozoom_bindings);
        }
    };

    // SDL2 hasn't a default configuration for Linux
    if target_os == "linux-gnu" {
        bindings = bindings.clang_arg("-DSDL_VIDEO_DRIVER_X11");
        bindings = bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
        if cfg!(feature = "image") {
            image_bindings = image_bindings.clang_arg("-DSDL_VIDEO_DRIVER_X11");
            image_bindings = image_bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
        }
        if cfg!(feature = "ttf") {
            ttf_bindings = ttf_bindings.clang_arg("-DSDL_VIDEO_DRIVER_X11");
            ttf_bindings = ttf_bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
        }
        if cfg!(feature = "mixer") {
            mixer_bindings = mixer_bindings.clang_arg("-DSDL_VIDEO_DRIVER_X11");
            mixer_bindings = mixer_bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
        }
        if cfg!(feature = "gfx") {
            gfx_framerate_bindings = gfx_framerate_bindings.clang_arg("-DSDL_VIDEO_DRIVER_X11");
            gfx_framerate_bindings = gfx_framerate_bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
            gfx_primitives_bindings = gfx_primitives_bindings.clang_arg("-DSDL_VIDEO_DRIVER_X11");
            gfx_primitives_bindings =
                gfx_primitives_bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
            gfx_imagefilter_bindings = gfx_imagefilter_bindings.clang_arg("-DSDL_VIDEO_DRIVER_X11");
            gfx_imagefilter_bindings =
                gfx_imagefilter_bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
            gfx_rotozoom_bindings = gfx_rotozoom_bindings.clang_arg("-DSDL_VIDEO_DRIVER_X11");
            gfx_rotozoom_bindings = gfx_rotozoom_bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
        }
    }

    let bindings = bindings
        .header("wrapper.h")
        .blacklist_type("FP_NAN")
        .blacklist_type("FP_INFINITE")
        .blacklist_type("FP_ZERO")
        .blacklist_type("FP_SUBNORMAL")
        .blacklist_type("FP_NORMAL")
        .derive_debug(false)
        .generate()
        .expect("Unable to generate bindings!");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    bindings
        .write_to_file(out_path.join("sdl_bindings.rs"))
        .expect("Couldn't write bindings!");

    if cfg!(feature = "image") {
        let image_bindings = image_bindings
            .header("wrapper_image.h")
            .blacklist_type("FP_NAN")
            .blacklist_type("FP_INFINITE")
            .blacklist_type("FP_ZERO")
            .blacklist_type("FP_SUBNORMAL")
            .blacklist_type("FP_NORMAL")
            .whitelist_type("IMG.*")
            .whitelist_function("IMG.*")
            .whitelist_var("IMG.*")
            .blacklist_type("SDL_.*")
            .blacklist_type("_IO.*|FILE")
            .generate()
            .expect("Unable to generate image_bindings!");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

        image_bindings
            .write_to_file(out_path.join("sdl_image_bindings.rs"))
            .expect("Couldn't write image_bindings!");
    }

    if cfg!(feature = "ttf") {
        let ttf_bindings = ttf_bindings
            .header("wrapper_ttf.h")
            .blacklist_type("FP_NAN")
            .blacklist_type("FP_INFINITE")
            .blacklist_type("FP_ZERO")
            .blacklist_type("FP_SUBNORMAL")
            .blacklist_type("FP_NORMAL")
            .whitelist_type("TTF.*")
            .whitelist_function("TTF.*")
            .whitelist_var("TTF.*")
            .blacklist_type("SDL_.*")
            .blacklist_type("_IO.*|FILE")
            .generate()
            .expect("Unable to generate ttf_bindings!");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

        ttf_bindings
            .write_to_file(out_path.join("sdl_ttf_bindings.rs"))
            .expect("Couldn't write ttf_bindings!");
    }

    if cfg!(feature = "mixer") {
        let mixer_bindings = mixer_bindings
            .header("wrapper_mixer.h")
            .blacklist_type("FP_NAN")
            .blacklist_type("FP_INFINITE")
            .blacklist_type("FP_ZERO")
            .blacklist_type("FP_SUBNORMAL")
            .blacklist_type("FP_NORMAL")
            .whitelist_type("MIX.*")
            .whitelist_type("Mix.*")
            .whitelist_type("MUS.*")
            .whitelist_function("Mix.*")
            .whitelist_var("MIX.*")
            .whitelist_var("MUS.*")
            .blacklist_type("SDL_.*")
            .blacklist_type("_IO.*|FILE")
            .generate()
            .expect("Unable to generate mixer_bindings!");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

        mixer_bindings
            .write_to_file(out_path.join("sdl_mixer_bindings.rs"))
            .expect("Couldn't write mixer_bindings!");
    }

    if cfg!(feature = "gfx") {
        let gfx_framerate_bindings = gfx_framerate_bindings
            .header("wrapper_gfx_framerate.h")
            .blacklist_type("FP_NAN")
            .blacklist_type("FP_INFINITE")
            .blacklist_type("FP_ZERO")
            .blacklist_type("FP_SUBNORMAL")
            .blacklist_type("FP_NORMAL")
            .whitelist_type("FPS.*")
            .whitelist_function("SDL_.*rame.*")
            .whitelist_var("FPS.*")
            .blacklist_type("_IO.*|FILE")
            .generate()
            .expect("Unable to generate gfx_framerate_bindings!");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

        gfx_framerate_bindings
            .write_to_file(out_path.join("sdl_gfx_framerate_bindings.rs"))
            .expect("Couldn't write gfx_framerate_bindings!");

        let gfx_primitives_bindings = gfx_primitives_bindings
            .header("wrapper_gfx_primitives.h")
            .blacklist_type("FP_NAN")
            .blacklist_type("FP_INFINITE")
            .blacklist_type("FP_ZERO")
            .blacklist_type("FP_SUBNORMAL")
            .blacklist_type("FP_NORMAL")
            .blacklist_type("SDL_.*")
            .whitelist_function("pixel.*")
            .whitelist_function("rectangle.*")
            .whitelist_function("rounded.*")
            .whitelist_function("box.*")
            .whitelist_function(".*line(Color|RGBA).*")
            .whitelist_function("thick.*")
            .whitelist_function(".*circle.*")
            .whitelist_function("arc.*")
            .whitelist_function("filled.*")
            .whitelist_function(".*ellipse.*")
            .whitelist_function("pie.*")
            .whitelist_function(".*trigon.*")
            .whitelist_function(".*polygon.*")
            .whitelist_function("textured.*")
            .whitelist_function("bezier.*")
            .whitelist_function("character.*")
            .whitelist_function("string.*")
            .whitelist_function("gfx.*")
            .blacklist_type("_IO.*|FILE")
            .generate()
            .expect("Unable to generate gfx_primitives_bindings!");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

        gfx_primitives_bindings
            .write_to_file(out_path.join("sdl_gfx_primitives_bindings.rs"))
            .expect("Couldn't write gfx_primitives_bindings!");

        let gfx_imagefilter_bindings = gfx_imagefilter_bindings
            .header("wrapper_gfx_imagefilter.h")
            .whitelist_function("SDL_image.*")
            .blacklist_type("FP_NAN")
            .blacklist_type("FP_INFINITE")
            .blacklist_type("FP_ZERO")
            .blacklist_type("FP_SUBNORMAL")
            .blacklist_type("FP_NORMAL")
            .blacklist_type("_IO.*|FILE")
            .generate()
            .expect("Unable to generate gfx_imagefilter_bindings!");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

        gfx_imagefilter_bindings
            .write_to_file(out_path.join("sdl_gfx_imagefilter_bindings.rs"))
            .expect("Couldn't write gfx_imagefilter_bindings!");

        let gfx_rotozoom_bindings = gfx_rotozoom_bindings
            .header("wrapper_gfx_rotozoom.h")
            .blacklist_type("SDL_.*")
            .whitelist_function("rotozoom.*")
            .whitelist_function("zoom.*")
            .whitelist_function("shrink.*")
            .whitelist_function("rotate.*")
            .blacklist_type("FP_NAN")
            .blacklist_type("FP_INFINITE")
            .blacklist_type("FP_ZERO")
            .blacklist_type("FP_SUBNORMAL")
            .blacklist_type("FP_NORMAL")
            .blacklist_type("_IO.*|FILE")
            .generate()
            .expect("Unable to generate gfx_rotozoom_bindings!");

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

        gfx_rotozoom_bindings
            .write_to_file(out_path.join("sdl_gfx_rotozoom_bindings.rs"))
            .expect("Couldn't write gfx_rotozoom_bindings!");
    }
}

fn get_os_from_triple(triple: &str) -> Option<&str> {
    triple.splitn(3, "-").nth(2)
}
========== build.rs from semver-1.0.9 ============================================================
use std::env;
use std::process::Command;
use std::str;

fn main() {
    let compiler = match rustc_minor_version() {
        Some(compiler) => compiler,
        None => return,
    };

    if compiler < 33 {
        // Exhaustive integer patterns. On older compilers, a final `_` arm is
        // required even if every possible integer value is otherwise covered.
        // https://github.com/rust-lang/rust/issues/50907
        println!("cargo:rustc-cfg=no_exhaustive_int_match");
    }

    if compiler < 36 {
        // extern crate alloc.
        // https://blog.rust-lang.org/2019/07/04/Rust-1.36.0.html#the-alloc-crate-is-stable
        println!("cargo:rustc-cfg=no_alloc_crate");
    }

    if compiler < 39 {
        // const Vec::new.
        // https://doc.rust-lang.org/std/vec/struct.Vec.html#method.new
        println!("cargo:rustc-cfg=no_const_vec_new");
    }

    if compiler < 40 {
        // #[non_exhaustive].
        // https://blog.rust-lang.org/2019/12/19/Rust-1.40.0.html#non_exhaustive-structs-enums-and-variants
        println!("cargo:rustc-cfg=no_non_exhaustive");
    }

    if compiler < 45 {
        // String::strip_prefix.
        // https://doc.rust-lang.org/std/primitive.str.html#method.repeat
        println!("cargo:rustc-cfg=no_str_strip_prefix");
    }

    if compiler < 46 {
        // #[track_caller].
        // https://blog.rust-lang.org/2020/08/27/Rust-1.46.0.html#track_caller
        println!("cargo:rustc-cfg=no_track_caller");
    }

    if compiler < 52 {
        // #![deny(unsafe_op_in_unsafe_fn)].
        // https://github.com/rust-lang/rust/issues/71668
        println!("cargo:rustc-cfg=no_unsafe_op_in_unsafe_fn_lint");
    }

    if compiler < 53 {
        // Efficient intrinsics for count-leading-zeros and count-trailing-zeros
        // on NonZero integers stabilized in 1.53.0. On many architectures these
        // are more efficient than counting zeros on ordinary zeroable integers.
        // https://doc.rust-lang.org/std/num/struct.NonZeroU64.html#method.leading_zeros
        // https://doc.rust-lang.org/std/num/struct.NonZeroU64.html#method.trailing_zeros
        println!("cargo:rustc-cfg=no_nonzero_bitscan");
    }
}

fn rustc_minor_version() -> Option<u32> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    pieces.next()?.parse().ok()
}
========== build.rs from serde-1.0.139 ============================================================
use std::env;
use std::process::Command;
use std::str::{self, FromStr};

// The rustc-cfg strings below are *not* public API. Please let us know by
// opening a GitHub issue if your build environment requires some way to enable
// these cfgs other than by executing our build script.
fn main() {
    let minor = match rustc_minor_version() {
        Some(minor) => minor,
        None => return,
    };

    let target = env::var("TARGET").unwrap();
    let emscripten = target == "asmjs-unknown-emscripten" || target == "wasm32-unknown-emscripten";

    // std::collections::Bound was stabilized in Rust 1.17
    // but it was moved to core::ops later in Rust 1.26:
    // https://doc.rust-lang.org/core/ops/enum.Bound.html
    if minor < 26 {
        println!("cargo:rustc-cfg=no_ops_bound");
        if minor < 17 {
            println!("cargo:rustc-cfg=no_collections_bound");
        }
    }

    // core::cmp::Reverse stabilized in Rust 1.19:
    // https://doc.rust-lang.org/stable/core/cmp/struct.Reverse.html
    if minor < 19 {
        println!("cargo:rustc-cfg=no_core_reverse");
    }

    // CString::into_boxed_c_str and PathBuf::into_boxed_path stabilized in Rust 1.20:
    // https://doc.rust-lang.org/std/ffi/struct.CString.html#method.into_boxed_c_str
    // https://doc.rust-lang.org/std/path/struct.PathBuf.html#method.into_boxed_path
    if minor < 20 {
        println!("cargo:rustc-cfg=no_de_boxed_c_str");
        println!("cargo:rustc-cfg=no_de_boxed_path");
    }

    // From<Box<T>> for Rc<T> / Arc<T> stabilized in Rust 1.21:
    // https://doc.rust-lang.org/std/rc/struct.Rc.html#impl-From<Box<T>>
    // https://doc.rust-lang.org/std/sync/struct.Arc.html#impl-From<Box<T>>
    if minor < 21 {
        println!("cargo:rustc-cfg=no_de_rc_dst");
    }

    // Duration available in core since Rust 1.25:
    // https://blog.rust-lang.org/2018/03/29/Rust-1.25.html#library-stabilizations
    if minor < 25 {
        println!("cargo:rustc-cfg=no_core_duration");
    }

    // 128-bit integers stabilized in Rust 1.26:
    // https://blog.rust-lang.org/2018/05/10/Rust-1.26.html
    //
    // Disabled on Emscripten targets before Rust 1.40 since
    // Emscripten did not support 128-bit integers until Rust 1.40
    // (https://github.com/rust-lang/rust/pull/65251)
    if minor < 26 || emscripten && minor < 40 {
        println!("cargo:rustc-cfg=no_integer128");
    }

    // Inclusive ranges methods stabilized in Rust 1.27:
    // https://github.com/rust-lang/rust/pull/50758
    // Also Iterator::try_for_each:
    // https://blog.rust-lang.org/2018/06/21/Rust-1.27.html#library-stabilizations
    if minor < 27 {
        println!("cargo:rustc-cfg=no_range_inclusive");
        println!("cargo:rustc-cfg=no_iterator_try_fold");
    }

    // Non-zero integers stabilized in Rust 1.28:
    // https://blog.rust-lang.org/2018/08/02/Rust-1.28.html#library-stabilizations
    if minor < 28 {
        println!("cargo:rustc-cfg=no_num_nonzero");
    }

    // Current minimum supported version of serde_derive crate is Rust 1.31.
    if minor < 31 {
        println!("cargo:rustc-cfg=no_serde_derive");
    }

    // TryFrom, Atomic types, non-zero signed integers, and SystemTime::checked_add
    // stabilized in Rust 1.34:
    // https://blog.rust-lang.org/2019/04/11/Rust-1.34.0.html#tryfrom-and-tryinto
    // https://blog.rust-lang.org/2019/04/11/Rust-1.34.0.html#library-stabilizations
    if minor < 34 {
        println!("cargo:rustc-cfg=no_core_try_from");
        println!("cargo:rustc-cfg=no_num_nonzero_signed");
        println!("cargo:rustc-cfg=no_systemtime_checked_add");
    }

    // Whitelist of archs that support std::sync::atomic module. Ideally we
    // would use #[cfg(target_has_atomic = "...")] but it is not stable yet.
    // Instead this is based on rustc's compiler/rustc_target/src/spec/*.rs.
    let has_atomic64 = target.starts_with("x86_64")
        || target.starts_with("i686")
        || target.starts_with("aarch64")
        || target.starts_with("powerpc64")
        || target.starts_with("sparc64")
        || target.starts_with("mips64el")
        || target.starts_with("riscv64");
    let has_atomic32 = has_atomic64 || emscripten;
    if minor < 34 || !has_atomic64 {
        println!("cargo:rustc-cfg=no_std_atomic64");
    }
    if minor < 34 || !has_atomic32 {
        println!("cargo:rustc-cfg=no_std_atomic");
    }
}

fn rustc_minor_version() -> Option<u32> {
    let rustc = match env::var_os("RUSTC") {
        Some(rustc) => rustc,
        None => return None,
    };

    let output = match Command::new(rustc).arg("--version").output() {
        Ok(output) => output,
        Err(_) => return None,
    };

    let version = match str::from_utf8(&output.stdout) {
        Ok(version) => version,
        Err(_) => return None,
    };

    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }

    let next = match pieces.next() {
        Some(next) => next,
        None => return None,
    };

    u32::from_str(next).ok()
}
========== build.rs from serde_derive-1.0.139 ============================================================
use std::env;
use std::process::Command;
use std::str;

// The rustc-cfg strings below are *not* public API. Please let us know by
// opening a GitHub issue if your build environment requires some way to enable
// these cfgs other than by executing our build script.
fn main() {
    let minor = match rustc_minor_version() {
        Some(minor) => minor,
        None => return,
    };

    // Underscore const names stabilized in Rust 1.37:
    // https://blog.rust-lang.org/2019/08/15/Rust-1.37.0.html#using-unnamed-const-items-for-macros
    if minor >= 37 {
        println!("cargo:rustc-cfg=underscore_consts");
    }

    // The ptr::addr_of! macro stabilized in Rust 1.51:
    // https://blog.rust-lang.org/2021/03/25/Rust-1.51.0.html#stabilized-apis
    if minor >= 51 {
        println!("cargo:rustc-cfg=ptr_addr_of");
    }
}

fn rustc_minor_version() -> Option<u32> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    pieces.next()?.parse().ok()
}
========== build.rs from serde_json-1.0.82 ============================================================
use std::env;
use std::process::Command;
use std::str::{self, FromStr};

fn main() {
    // Decide ideal limb width for arithmetic in the float parser. Refer to
    // src/lexical/math.rs for where this has an effect.
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    match target_arch.as_str() {
        "aarch64" | "mips64" | "powerpc64" | "x86_64" => {
            println!("cargo:rustc-cfg=limb_width_64");
        }
        _ => {
            println!("cargo:rustc-cfg=limb_width_32");
        }
    }

    let minor = match rustc_minor_version() {
        Some(minor) => minor,
        None => return,
    };

    // BTreeMap::get_key_value
    // https://blog.rust-lang.org/2019/12/19/Rust-1.40.0.html#additions-to-the-standard-library
    if minor < 40 {
        println!("cargo:rustc-cfg=no_btreemap_get_key_value");
    }

    // BTreeMap::remove_entry
    // https://blog.rust-lang.org/2020/07/16/Rust-1.45.0.html#library-changes
    if minor < 45 {
        println!("cargo:rustc-cfg=no_btreemap_remove_entry");
    }

    // BTreeMap::retain
    // https://blog.rust-lang.org/2021/06/17/Rust-1.53.0.html#stabilized-apis
    if minor < 53 {
        println!("cargo:rustc-cfg=no_btreemap_retain");
    }
}

fn rustc_minor_version() -> Option<u32> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    let next = pieces.next()?;
    u32::from_str(next).ok()
}
========== build.rs from syn-1.0.103 ============================================================
use std::env;
use std::process::Command;
use std::str;

// The rustc-cfg strings below are *not* public API. Please let us know by
// opening a GitHub issue if your build environment requires some way to enable
// these cfgs other than by executing our build script.
fn main() {
    let compiler = match rustc_version() {
        Some(compiler) => compiler,
        None => return,
    };

    if compiler.minor < 36 {
        println!("cargo:rustc-cfg=syn_omit_await_from_token_macro");
    }

    if compiler.minor < 39 {
        println!("cargo:rustc-cfg=syn_no_const_vec_new");
    }

    if compiler.minor < 40 {
        println!("cargo:rustc-cfg=syn_no_non_exhaustive");
    }

    if compiler.minor < 56 {
        println!("cargo:rustc-cfg=syn_no_negative_literal_parse");
    }

    if !compiler.nightly {
        println!("cargo:rustc-cfg=syn_disable_nightly_tests");
    }
}

struct Compiler {
    minor: u32,
    nightly: bool,
}

fn rustc_version() -> Option<Compiler> {
    let rustc = env::var_os("RUSTC")?;
    let output = Command::new(rustc).arg("--version").output().ok()?;
    let version = str::from_utf8(&output.stdout).ok()?;
    let mut pieces = version.split('.');
    if pieces.next() != Some("rustc 1") {
        return None;
    }
    let minor = pieces.next()?.parse().ok()?;
    let nightly = version.contains("nightly") || version.ends_with("-dev");
    Some(Compiler { minor, nightly })
}
========== build.rs from tiny-keccak-2.0.2 ============================================================
#[cfg(not(any(
    feature = "keccak",
    feature = "shake",
    feature = "sha3",
    feature = "cshake",
    feature = "kmac",
    feature = "tuple_hash",
    feature = "parallel_hash",
    feature = "k12",
    feature = "fips202",
    feature = "sp800"
)))]
compile_error!(
    "You need to specify at least one hash function you intend to use. \
    Available options:\n\
    keccak, shake, sha3, cshake, kmac, tuple_hash, parallel_hash, k12, fips202, sp800\n\
    e.g.\n\
    tiny-keccak = { version = \"2.0.0\", features = [\"sha3\"] }"
);

fn main() {
}
========== build.rs from valuable-0.1.0 ============================================================
#![warn(rust_2018_idioms, single_use_lifetimes)]

use std::env;

include!("no_atomic.rs");

// The rustc-cfg strings below are *not* public API. Please let us know by
// opening a GitHub issue if your build environment requires some way to enable
// these cfgs other than by executing our build script.
fn main() {
    let target = match env::var("TARGET") {
        Ok(target) => target,
        Err(e) => {
            println!(
                "cargo:warning=valuable: unable to get TARGET environment variable: {}",
                e
            );
            return;
        }
    };

    // Note that this is `no_*`, not `has_*`. This allows treating
    // `cfg(target_has_atomic = "ptr")` as true when the build script doesn't
    // run. This is needed for compatibility with non-cargo build systems that
    // don't run the build script.
    if NO_ATOMIC_CAS.contains(&&*target) {
        println!("cargo:rustc-cfg=valuable_no_atomic_cas");
    }
    if NO_ATOMIC.contains(&&*target) {
        println!("cargo:rustc-cfg=valuable_no_atomic");
        println!("cargo:rustc-cfg=valuable_no_atomic_64");
    } else if NO_ATOMIC_64.contains(&&*target) {
        println!("cargo:rustc-cfg=valuable_no_atomic_64");
    } else {
        // Otherwise, assuming `"max-atomic-width" == 64`.
    }

    println!("cargo:rerun-if-changed=no_atomic.rs");
}
========== build.rs from wasm-bindgen-0.2.80 ============================================================
// Empty `build.rs` so that `[package] links = ...` works in `Cargo.toml`.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
========== build.rs from wasm-bindgen-shared-0.2.80 ============================================================
use std::collections::hash_map::DefaultHasher;
use std::env;
use std::hash::Hasher;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    set_schema_version_env_var();

    let rev = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .ok()
        .map(|s| s.stdout)
        .and_then(|s| String::from_utf8(s).ok());
    if let Some(rev) = rev {
        if rev.len() >= 9 {
            println!("cargo:rustc-env=WBG_VERSION={}", &rev[..9]);
        }
    }
}

fn set_schema_version_env_var() {
    let cargo_manifest_dir = env::var("CARGO_MANIFEST_DIR").expect(
        "The `CARGO_MANIFEST_DIR` environment variable is needed to locate the schema file",
    );
    let schema_file = PathBuf::from(cargo_manifest_dir).join("src/lib.rs");
    let schema_file = std::fs::read(schema_file).unwrap();

    let mut hasher = DefaultHasher::new();
    hasher.write(&schema_file);

    println!("cargo:rustc-env=SCHEMA_FILE_HASH={}", hasher.finish());
}
========== build.rs from wayland-client-0.29.4 ============================================================
extern crate wayland_scanner;

use std::env::var;
use std::path::Path;
use wayland_scanner::*;

fn main() {
    let protocol_file = "./wayland.xml";

    let out_dir_str = var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_str);

    println!("cargo:rerun-if-changed={}", protocol_file);
    generate_code_with_destructor_events(
        protocol_file,
        out_dir.join("wayland_api.rs"),
        Side::Client,
        &[("wl_callback", "done")],
    );
}
========== build.rs from wayland-protocols-0.29.4 ============================================================
extern crate wayland_scanner;

use std::env::var;
use std::path::Path;
use wayland_scanner::*;

#[rustfmt::skip]
type StableProtocol<'a> =    (&'a str,                &'a [(&'a str, &'a str)]);
type VersionedProtocol<'a> = (&'a str, &'a [(&'a str, &'a [(&'a str, &'a str)])]);
//                            ^        ^         ^        ^     ^        ^
//                            |        |         |        |     |        |
//                            Name     |         |        |     |        Name of event to specify as
//                                     Versions  |        |     |        destructor
//                                               Version  |     |
//                                                        |     Interface the event is belongs to
//                                                        |
//                                                        Events to specify as destructors

static STABLE_PROTOCOLS: &[StableProtocol] =
    &[("presentation-time", &[]), ("viewporter", &[]), ("xdg-shell", &[])];

static STAGING_PROTOCOLS: &[VersionedProtocol] = &[("xdg-activation", &[("v1", &[])])];

static UNSTABLE_PROTOCOLS: &[VersionedProtocol] = &[
    ("fullscreen-shell", &[("v1", &[])]),
    ("idle-inhibit", &[("v1", &[])]),
    ("input-method", &[("v1", &[])]),
    ("input-timestamps", &[("v1", &[])]),
    ("keyboard-shortcuts-inhibit", &[("v1", &[])]),
    ("linux-dmabuf", &[("v1", &[])]),
    (
        "linux-explicit-synchronization",
        &[(
            "v1",
            &[
                ("zwp_linux_buffer_release_v1", "fenced_release"),
                ("zwp_linux_buffer_release_v1", "immediate_release"),
            ],
        )],
    ),
    ("pointer-constraints", &[("v1", &[])]),
    ("pointer-gestures", &[("v1", &[])]),
    ("primary-selection", &[("v1", &[])]),
    ("relative-pointer", &[("v1", &[])]),
    ("tablet", &[("v1", &[]), ("v2", &[])]),
    ("text-input", &[("v1", &[]), ("v3", &[])]),
    ("xdg-decoration", &[("v1", &[])]),
    ("xdg-foreign", &[("v1", &[]), ("v2", &[])]),
    ("xdg-output", &[("v1", &[])]),
    ("xdg-shell", &[("v5", &[]), ("v6", &[])]),
    ("xwayland-keyboard-grab", &[("v1", &[])]),
];

static WLR_UNSTABLE_PROTOCOLS: &[VersionedProtocol] = &[
    ("wlr-data-control", &[("v1", &[])]),
    ("wlr-export-dmabuf", &[("v1", &[])]),
    ("wlr-foreign-toplevel-management", &[("v1", &[])]),
    ("wlr-gamma-control", &[("v1", &[])]),
    ("wlr-input-inhibitor", &[("v1", &[])]),
    ("wlr-layer-shell", &[("v1", &[])]),
    ("wlr-output-management", &[("v1", &[])]),
    ("wlr-output-power-management", &[("v1", &[])]),
    ("wlr-screencopy", &[("v1", &[])]),
    ("wlr-virtual-pointer", &[("v1", &[])]),
];

static MISC_PROTOCOLS: &[StableProtocol] = &[
    ("gtk-primary-selection", &[]),
    ("input-method-unstable-v2", &[]),
    ("server-decoration", &[]),
];

fn generate_protocol(
    name: &str,
    protocol_file: &Path,
    out_dir: &Path,
    client: bool,
    server: bool,
    dest_events: &[(&str, &str)],
) {
    println!("cargo:rerun-if-changed={}", protocol_file.display());

    if client {
        generate_code_with_destructor_events(
            &protocol_file,
            out_dir.join(&format!("{}_client_api.rs", name)),
            Side::Client,
            dest_events,
        );
    }
    if server {
        generate_code_with_destructor_events(
            &protocol_file,
            out_dir.join(&format!("{}_server_api.rs", name)),
            Side::Server,
            dest_events,
        );
    }
}

fn main() {
    println!("cargo:rerun-if-changed-env=CARGO_FEATURE_CLIENT");
    println!("cargo:rerun-if-changed-env=CARGO_FEATURE_SERVER");
    println!("cargo:rerun-if-changed-env=CARGO_FEATURE_UNSTABLE_PROTOCOLS");

    let out_dir_str = var("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_str);

    let client = var("CARGO_FEATURE_CLIENT").ok().is_some();
    let server = var("CARGO_FEATURE_SERVER").ok().is_some();

    for &(name, dest_events) in STABLE_PROTOCOLS {
        let file = format!("{name}/{name}.xml", name = name);
        generate_protocol(
            name,
            &Path::new("./protocols/stable").join(&file),
            out_dir,
            client,
            server,
            dest_events,
        );
    }

    if var("CARGO_FEATURE_STAGING_PROTOCOLS").ok().is_some() {
        for &(name, versions) in STAGING_PROTOCOLS {
            for &(version, dest_events) in versions {
                let file = format!("{name}/{name}-{version}.xml", name = name, version = version);
                generate_protocol(
                    &format!("{name}-{version}", name = name, version = version),
                    &Path::new("./protocols/staging").join(&file),
                    out_dir,
                    client,
                    server,
                    dest_events,
                );
            }
        }
    }

    for &(name, dest_events) in MISC_PROTOCOLS {
        let file = format!("{name}.xml", name = name);
        generate_protocol(
            name,
            &Path::new("./misc").join(&file),
            out_dir,
            client,
            server,
            dest_events,
        );
    }

    if var("CARGO_FEATURE_UNSTABLE_PROTOCOLS").ok().is_some() {
        for &(name, versions) in UNSTABLE_PROTOCOLS {
            for &(version, dest_events) in versions {
                let file =
                    format!("{name}/{name}-unstable-{version}.xml", name = name, version = version);
                generate_protocol(
                    &format!("{name}-{version}", name = name, version = version),
                    &Path::new("./protocols/unstable").join(file),
                    out_dir,
                    client,
                    server,
                    dest_events,
                );
            }
        }
        for &(name, versions) in WLR_UNSTABLE_PROTOCOLS {
            for &(version, dest_events) in versions {
                let file = format!("{name}-unstable-{version}.xml", name = name, version = version);
                generate_protocol(
                    &format!("{name}-{version}", name = name, version = version),
                    &Path::new("./wlr-protocols/unstable").join(file),
                    out_dir,
                    client,
                    server,
                    dest_events,
                );
            }
        }
    }
}
========== build.rs from wayland-sys-0.29.4 ============================================================
use pkg_config::Config;

fn main() {
    if std::env::var_os("CARGO_FEATURE_DLOPEN").is_some() {
        // Do not link to anything
        return;
    }

    if std::env::var_os("CARGO_FEATURE_CLIENT").is_some() {
        Config::new().probe("wayland-client").unwrap();
    }
    if std::env::var_os("CARGO_FEATURE_CURSOR").is_some() {
        Config::new().probe("wayland-cursor").unwrap();
    }
    if std::env::var_os("CARGO_FEATURE_EGL").is_some() {
        Config::new().probe("wayland-egl").unwrap();
    }
    if std::env::var_os("CARGO_FEATURE_SERVER").is_some() {
        Config::new().probe("wayland-server").unwrap();
    }
}
========== build.rs from winapi-0.3.9 ============================================================
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
use std::cell::Cell;
use std::collections::HashMap;
use std::env::var;
// (header name, &[header dependencies], &[library dependencies])
const DATA: &'static [(&'static str, &'static [&'static str], &'static [&'static str])] = &[
    // km
    ("d3dkmthk", &["basetsd", "d3dukmdt", "minwindef", "ntdef", "windef"], &[]),
    // mmos
    // shared
    ("basetsd", &[], &[]),
    ("bcrypt", &["minwindef", "winnt"], &["bcrypt"]),
    ("bthdef", &["bthsdpdef", "guiddef", "minwindef", "ntdef"], &[]),
    ("bthioctl", &["bthdef", "bthsdpdef", "minwindef", "ntdef", "winioctl"], &[]),
    ("bthsdpdef", &["guiddef", "minwindef", "ntdef"], &[]),
    ("bugcodes", &["ntdef"], &[]),
    ("cderr", &["minwindef"], &[]),
    ("cfg", &["minwindef"], &[]),
    ("d3d9", &["basetsd", "d3d9caps", "d3d9types", "guiddef", "minwindef", "unknwnbase", "windef", "wingdi", "winnt"], &["d3d9"]),
    ("d3d9caps", &["d3d9types", "guiddef", "minwindef", "winnt"], &[]),
    ("d3d9types", &["basetsd", "guiddef", "minwindef", "windef", "winnt"], &[]),
    ("d3dkmdt", &["basetsd", "minwindef", "ntdef"], &[]),
    ("d3dukmdt", &["basetsd", "guiddef", "minwindef", "ntdef"], &[]),
    ("dcomptypes", &["dxgitype", "minwindef", "winnt"], &[]),
    ("devguid", &[], &[]),
    ("devpkey", &["devpropdef"], &[]),
    ("devpropdef", &["guiddef", "minwindef", "winnt"], &[]),
    ("dinputd", &[], &[]),
    ("dxgi", &["basetsd", "dxgiformat", "dxgitype", "guiddef", "minwindef", "unknwnbase", "windef", "winnt"], &["dxgi"]),
    ("dxgi1_2", &["basetsd", "dxgi", "dxgiformat", "dxgitype", "guiddef", "minwinbase", "minwindef", "unknwnbase", "windef", "winnt"], &[]),
    ("dxgi1_3", &["dxgi", "dxgi1_2", "dxgiformat", "guiddef", "minwindef", "unknwnbase", "windef", "winnt"], &["dxgi"]),
    ("dxgi1_4", &["basetsd", "dxgi1_2", "dxgi1_3", "dxgiformat", "dxgitype", "guiddef", "minwindef", "unknwnbase", "winnt"], &[]),
    ("dxgi1_5", &["basetsd", "dxgi", "dxgi1_2", "dxgi1_3", "dxgi1_4", "dxgiformat", "minwindef", "unknwnbase", "winnt"], &[]),
    ("dxgi1_6", &["basetsd", "dxgi1_2", "dxgi1_4", "dxgi1_5", "dxgitype", "guiddef", "minwindef", "windef", "winnt"], &[]),
    ("dxgiformat", &[], &[]),
    ("dxgitype", &["d3d9types", "dxgiformat", "minwindef"], &[]),
    ("enclaveapi", &["basetsd", "minwinbase", "minwindef", "ntdef", "winnt"], &["kernel32"]),
    ("evntprov", &["basetsd", "guiddef", "minwindef", "winnt"], &["advapi32"]),
    ("evntrace", &["basetsd", "evntcons", "evntprov", "guiddef", "handleapi", "minwindef", "timezoneapi", "vadefs", "winnt", "wmistr"], &["advapi32"]),
    ("guiddef", &[], &[]),
    ("hidclass", &["guiddef", "minwindef", "winioctl", "winnt"], &[]),
    ("hidpi", &["hidusage", "minwindef", "ntdef", "ntstatus", "winnt"], &["hid"]),
    ("hidsdi", &["guiddef", "hidpi", "minwindef", "winnt"], &["hid"]),
    ("hidusage", &["minwindef"], &[]),
    ("ifdef", &["basetsd", "guiddef", "ntdef"], &[]),
    ("ifmib", &["ifdef", "ipifcons", "minwindef", "ntdef"], &[]),
    ("in6addr", &["minwindef"], &[]),
    ("inaddr", &["minwindef"], &[]),
    ("intsafe", &[], &[]),
    ("ipifcons", &["minwindef"], &[]),
    ("ipmib", &["ifdef", "ifmib", "minwindef", "nldef", "ntdef"], &[]),
    ("iprtrmib", &["ipmib", "minwindef", "ntdef"], &[]),
    ("ks", &[], &[]),
    ("ksmedia", &["minwindef"], &[]),
    ("ktmtypes", &["guiddef", "minwindef", "winnt"], &[]),
    ("lmcons", &["minwindef", "winnt"], &[]),
    ("minwindef", &["basetsd", "ntdef"], &[]),
    ("mmreg", &["guiddef", "minwindef"], &[]),
    ("mprapidef", &[], &[]),
    ("mstcpip", &["basetsd", "guiddef", "in6addr", "inaddr", "minwindef", "winnt", "ws2def"], &["ntdll"]),
    ("mswsockdef", &["minwindef", "winnt", "ws2def"], &[]),
    ("netioapi", &["basetsd", "guiddef", "ifdef", "ipifcons", "minwindef", "nldef", "ntddndis", "ntdef", "ws2def", "ws2ipdef"], &["iphlpapi"]),
    ("nldef", &["basetsd", "minwindef", "ntdef"], &[]),
    ("ntddndis", &["ifdef", "minwindef"], &[]),
    ("ntddscsi", &["basetsd", "minwindef", "ntdef", "winioctl", "winnt"], &[]),
    ("ntddser", &["devpropdef"], &[]),
    ("ntdef", &["basetsd", "guiddef"], &[]),
    ("ntstatus", &["ntdef"], &[]),
    ("qos", &["minwindef"], &[]),
    ("rpc", &[], &[]),
    ("rpcdce", &["guiddef", "minwindef", "rpc"], &[]),
    ("rpcndr", &[], &[]),
    ("sddl", &["basetsd", "minwindef", "winnt"], &["advapi32"]),
    ("sspi", &["basetsd", "guiddef", "minwindef", "subauth", "wincred", "winnt"], &["credui", "secur32"]),
    ("stralign", &["vcruntime", "winnt"], &["kernel32"]),
    ("tcpestats", &["basetsd", "ntdef"], &[]),
    ("tcpmib", &["basetsd", "in6addr", "minwindef", "ntdef"], &[]),
    ("transportsettingcommon", &["guiddef"], &[]),
    ("tvout", &["guiddef", "minwindef"], &[]),
    ("udpmib", &["basetsd", "in6addr", "minwindef", "ntdef"], &[]),
    ("usb", &["minwindef", "usbspec", "winnt"], &[]),
    ("usbioctl", &["basetsd", "guiddef", "minwindef", "ntdef", "usb", "usbiodef", "usbspec", "winioctl"], &[]),
    ("usbiodef", &["guiddef", "minwindef", "winioctl", "winnt"], &[]),
    ("usbscan", &["ntdef", "winioctl"], &[]),
    ("usbspec", &["basetsd", "guiddef", "minwindef", "winnt"], &[]),
    ("windef", &["minwindef", "winnt"], &[]),
    ("windot11", &["basetsd", "minwindef", "ntddndis", "winnt", "wlantypes"], &[]),
    ("windowsx", &["minwindef"], &[]),
    ("winerror", &["minwindef", "wtypesbase"], &[]),
    ("winusbio", &["minwindef", "usb"], &[]),
    ("wlantypes", &["basetsd", "minwindef"], &[]),
    ("wmistr", &["basetsd", "guiddef", "minwindef", "winnt"], &[]),
    ("wnnc", &["minwindef"], &[]),
    ("ws2def", &["basetsd", "guiddef", "inaddr", "minwindef", "vcruntime", "winnt"], &[]),
    ("ws2ipdef", &["in6addr", "inaddr", "minwindef", "ws2def"], &[]),
    ("wtypes", &["guiddef", "minwindef", "ntdef", "rpcndr", "wingdi", "wtypesbase"], &[]),
    ("wtypesbase", &["minwindef", "rpcndr", "winnt"], &[]),
    // ucrt
    ("corecrt", &[], &[]),
    // um
    ("accctrl", &["guiddef", "minwindef", "winbase", "winnt"], &[]),
    ("aclapi", &["accctrl", "guiddef", "minwindef", "winnt"], &["advapi32"]),
    ("adhoc", &["guiddef", "minwindef", "unknwnbase", "winnt"], &[]),
    ("appmgmt", &["guiddef", "minwindef", "winnt"], &["advapi32"]),
    ("audioclient", &["audiosessiontypes", "basetsd", "guiddef", "minwindef", "mmreg", "strmif", "unknwnbase", "winerror", "winnt", "wtypesbase"], &[]),
    ("audiosessiontypes", &["minwindef"], &[]),
    ("avrt", &["guiddef", "minwindef", "winnt"], &["avrt"]),
    ("bits", &["basetsd", "guiddef", "minwindef", "unknwnbase", "winnt"], &[]),
    ("bits10_1", &["basetsd", "bits", "bits2_0", "bits3_0", "bits5_0", "minwindef", "winnt"], &[]),
    ("bits1_5", &["basetsd", "bits", "rpcndr", "winnt"], &[]),
    ("bits2_0", &["basetsd", "bits", "bits1_5", "minwindef", "winnt"], &[]),
    ("bits2_5", &["minwindef", "rpcndr", "unknwnbase", "winnt"], &[]),
    ("bits3_0", &["basetsd", "bits", "bits2_0", "guiddef", "minwindef", "unknwnbase", "winnt"], &[]),
    ("bits4_0", &["basetsd", "bits3_0", "minwindef", "unknwnbase", "winnt"], &[]),
    ("bits5_0", &["basetsd", "bits1_5", "bits3_0", "bits4_0", "guiddef", "minwindef", "winnt"], &[]),
    ("bitscfg", &["guiddef", "oaidl", "unknwnbase", "winnt", "wtypes"], &["oleaut32"]),
    ("bitsmsg", &["minwindef"], &[]),
    ("bluetoothapis", &["bthdef", "bthsdpdef", "guiddef", "minwinbase", "minwindef", "windef", "winnt"], &["bthprops"]),
    ("bluetoothleapis", &["bthledef", "minwindef", "winerror", "winnt"], &["bluetoothapis"]),
    ("bthledef", &["basetsd", "guiddef", "minwindef", "winnt"], &[]),
    ("cfgmgr32", &["basetsd", "cfg", "devpropdef", "guiddef", "minwindef", "winnt", "winreg"], &["cfgmgr32"]),
    ("cguid", &[], &[]),
    ("combaseapi", &["basetsd", "guiddef", "minwindef", "objidl", "objidlbase", "propidl", "rpcdce", "unknwnbase", "winnt", "wtypesbase"], &["ole32"]),
    ("coml2api", &["minwindef"], &[]),
    ("commapi", &["minwinbase", "minwindef", "winbase", "winnt"], &["kernel32"]),
    ("commctrl", &["basetsd", "commoncontrols", "guiddef", "minwinbase", "minwindef", "vcruntime", "windef", "winnt", "winuser"], &["comctl32"]),
    ("commdlg", &["basetsd", "minwindef", "prsht", "unknwnbase", "windef", "wingdi", "winnt", "winuser"], &["comdlg32"]),
    ("commoncontrols", &["commctrl", "guiddef", "minwindef", "unknwnbase", "windef", "winnt"], &["comctl32"]),
    ("consoleapi", &["minwindef", "wincon", "wincontypes", "winnt"], &["kernel32"]),
    ("corsym", &["basetsd", "objidlbase", "unknwnbase", "winnt"], &[]),
    ("d2d1", &["basetsd", "d2dbasetypes", "d3dcommon", "dcommon", "dwrite", "dxgi", "guiddef", "minwindef", "unknwnbase", "wincodec", "windef", "winnt"], &["d2d1"]),
    ("d2d1_1", &["basetsd", "d2d1", "d2d1effectauthor", "d2dbasetypes", "dcommon", "documenttarget", "dwrite", "dxgi", "dxgiformat", "guiddef", "minwindef", "objidlbase", "unknwnbase", "wincodec", "winnt"], &["d2d1"]),
    ("d2d1_2", &["d2d1", "d2d1_1", "dxgi", "minwindef", "winnt"], &["d2d1"]),
    ("d2d1_3", &["basetsd", "d2d1", "d2d1_1", "d2d1_2", "d2d1effects", "d2d1svg", "dcommon", "dwrite", "dxgi", "dxgitype", "minwindef", "ntdef", "objidlbase", "wincodec", "winerror"], &["d2d1"]),
    ("d2d1effectauthor", &["basetsd", "d2d1", "d2d1_1", "d2dbasetypes", "d3dcommon", "dxgiformat", "guiddef", "minwindef", "ntdef", "unknwnbase", "wincodec"], &[]),
    ("d2d1effects", &[], &[]),
    ("d2d1effects_1", &[], &[]),
    ("d2d1effects_2", &[], &[]),
    ("d2d1svg", &["basetsd", "d2d1", "d2d1_1", "guiddef", "minwindef", "ntdef", "objidlbase", "winerror"], &[]),
    ("d2dbasetypes", &["d3d9types", "dcommon"], &[]),
    ("d3d", &[], &[]),
    ("d3d10", &["d3dcommon"], &[]),
    ("d3d10_1", &[], &[]),
    ("d3d10_1shader", &[], &[]),
    ("d3d10effect", &[], &[]),
    ("d3d10misc", &[], &[]),
    ("d3d10sdklayers", &[], &[]),
    ("d3d10shader", &["d3d10", "d3dcommon", "minwindef", "unknwnbase", "winnt"], &[]),
    ("d3d11", &["basetsd", "d3dcommon", "dxgi", "dxgiformat", "dxgitype", "guiddef", "minwindef", "unknwnbase", "windef", "winnt"], &["d3d11"]),
    ("d3d11_1", &["basetsd", "d3d11", "d3dcommon", "dxgiformat", "dxgitype", "guiddef", "minwindef", "unknwnbase", "winnt"], &[]),
    ("d3d11_2", &["basetsd", "d3d11", "d3d11_1", "dxgiformat", "minwindef", "winnt"], &[]),
    ("d3d11_3", &[], &[]),
    ("d3d11_4", &[], &[]),
    ("d3d11on12", &["d3d11", "d3d12", "d3dcommon", "guiddef", "minwindef", "unknwnbase", "winnt"], &["d3d11"]),
    ("d3d11sdklayers", &["basetsd", "d3d11", "dxgi", "minwindef", "unknwnbase", "winnt"], &[]),
    ("d3d11shader", &["basetsd", "d3dcommon", "minwindef", "unknwnbase", "winnt"], &[]),
    ("d3d11tokenizedprogramformat", &["minwindef"], &[]),
    ("d3d12", &["basetsd", "d3dcommon", "dxgiformat", "dxgitype", "guiddef", "minwinbase", "minwindef", "unknwnbase", "windef", "winnt"], &["d3d12"]),
    ("d3d12sdklayers", &["basetsd", "d3d12", "minwindef", "unknwnbase", "winnt"], &[]),
    ("d3d12shader", &["basetsd", "d3dcommon", "minwindef", "unknwnbase", "winnt"], &[]),
    ("d3dcommon", &["basetsd", "minwindef", "unknwnbase", "winnt"], &[]),
    ("d3dcompiler", &["basetsd", "d3d11shader", "d3dcommon", "guiddef", "minwindef", "winnt"], &["d3dcompiler"]),
    ("d3dcsx", &[], &[]),
    ("d3dx10core", &[], &[]),
    ("d3dx10math", &[], &[]),
    ("d3dx10mesh", &[], &[]),
    ("datetimeapi", &["minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("davclnt", &["minwindef", "winnt"], &["netapi32"]),
    ("dbghelp", &["basetsd", "guiddef", "minwindef", "vcruntime", "winnt"], &["dbghelp"]),
    ("dbt", &["basetsd", "guiddef", "minwindef", "winnt", "winuser"], &[]),
    ("dcommon", &["basetsd", "dxgiformat", "minwindef", "windef"], &[]),
    ("dcomp", &["d2d1", "d2d1_1", "d2d1effects", "d2dbasetypes", "d3d9types", "d3dcommon", "dcompanimation", "dcomptypes", "dxgi", "dxgi1_2", "dxgiformat", "guiddef", "minwinbase", "minwindef", "ntdef", "unknwnbase", "windef"], &["dcomp"]),
    ("dcompanimation", &["ntdef", "unknwnbase"], &[]),
    ("dde", &["basetsd", "minwindef"], &["user32"]),
    ("ddraw", &[], &[]),
    ("ddrawi", &[], &[]),
    ("ddrawint", &[], &[]),
    ("debugapi", &["minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("devicetopology", &["guiddef", "minwindef", "unknwnbase", "windef", "winnt", "wtypes"], &[]),
    ("dinput", &[], &[]),
    ("dispex", &["basetsd", "guiddef", "minwindef", "oaidl", "servprov", "unknwnbase", "winerror", "winnt", "wtypes"], &[]),
    ("dmksctl", &[], &[]),
    ("dmusicc", &[], &[]),
    ("docobj", &["guiddef", "minwindef", "oaidl", "unknwnbase", "winnt"], &[]),
    ("documenttarget", &["basetsd", "guiddef", "ntdef", "unknwnbase"], &[]),
    ("dot1x", &["eaptypes", "guiddef", "l2cmn", "minwindef", "winnt"], &[]),
    ("dpa_dsa", &["basetsd", "minwindef", "winnt"], &["comctl32"]),
    ("dpapi", &["minwindef", "wincrypt", "windef", "winnt"], &["crypt32"]),
    ("dsgetdc", &["guiddef", "minwindef", "ntsecapi", "winnt", "ws2def"], &["netapi32"]),
    ("dsound", &["guiddef", "minwindef", "mmsystem", "unknwnbase", "windef", "winerror", "winnt"], &["dsound"]),
    ("dsrole", &["guiddef", "minwindef", "winnt"], &["netapi32"]),
    ("dvp", &[], &[]),
    ("dwmapi", &["basetsd", "minwindef", "uxtheme", "windef", "winnt"], &["dwmapi"]),
    ("dwrite", &["basetsd", "d2d1", "dcommon", "guiddef", "minwindef", "unknwnbase", "windef", "winerror", "wingdi", "winnt"], &["dwrite"]),
    ("dwrite_1", &["basetsd", "dcommon", "dwrite", "minwindef", "winnt"], &[]),
    ("dwrite_2", &["basetsd", "d3d9types", "dcommon", "dwrite", "dwrite_1", "minwindef", "unknwnbase", "winnt"], &[]),
    ("dwrite_3", &["basetsd", "dcommon", "dwrite", "dwrite_1", "dwrite_2", "minwindef", "unknwnbase", "wingdi", "winnt"], &[]),
    ("dxdiag", &[], &[]),
    ("dxfile", &[], &[]),
    ("dxgidebug", &["basetsd", "guiddef", "minwindef", "unknwnbase", "winnt"], &["dxgi"]),
    ("dxva2api", &["basetsd", "d3d9", "d3d9types", "guiddef", "minwindef", "unknwnbase", "windef", "winnt"], &["dxva2"]),
    ("dxvahd", &["d3d9", "d3d9types", "guiddef", "minwindef", "unknwnbase", "windef", "winnt"], &["dxva2"]),
    ("eaptypes", &["guiddef", "minwindef", "winnt"], &[]),
    ("endpointvolume", &["basetsd", "guiddef", "minwindef", "unknwnbase", "winnt"], &[]),
    ("errhandlingapi", &["basetsd", "minwindef", "winnt"], &["kernel32"]),
    ("evntcons", &["basetsd", "evntprov", "evntrace", "guiddef", "minwindef", "winnt"], &["advapi32"]),
    ("exdisp", &["basetsd", "docobj", "oaidl", "ocidl", "winnt", "wtypes"], &[]),
    ("fibersapi", &["minwindef", "winnt"], &["kernel32"]),
    ("fileapi", &["minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("functiondiscoverykeys_devpkey", &["wtypes"], &[]),
    ("gl-gl", &[], &["opengl32"]),
    ("handleapi", &["minwindef", "winnt"], &["kernel32"]),
    ("heapapi", &["basetsd", "minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("highlevelmonitorconfigurationapi", &["minwindef", "physicalmonitorenumerationapi", "winnt"], &["dxva2"]),
    ("http", &["guiddef", "minwinbase", "minwindef", "sspi", "winnt", "ws2def"], &["httpapi"]),
    ("imm", &["minwindef", "windef"], &["imm32"]),
    ("interlockedapi", &["minwindef", "winnt"], &["kernel32"]),
    ("ioapiset", &["basetsd", "minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("ipexport", &["basetsd", "in6addr", "ntdef"], &[]),
    ("iphlpapi", &["basetsd", "ifdef", "ifmib", "ipexport", "ipmib", "iprtrmib", "iptypes", "minwinbase", "minwindef", "ntdef", "tcpestats", "tcpmib", "udpmib", "ws2def", "ws2ipdef"], &["iphlpapi"]),
    ("iptypes", &["basetsd", "corecrt", "guiddef", "ifdef", "ipifcons", "minwindef", "nldef", "ntdef", "ws2def"], &[]),
    ("jobapi", &["minwindef", "winnt"], &["kernel32"]),
    ("jobapi2", &["basetsd", "minwinbase", "minwindef", "ntdef", "winnt"], &["kernel32"]),
    ("knownfolders", &[], &[]),
    ("ktmw32", &["guiddef", "minwinbase", "minwindef", "winnt"], &["ktmw32"]),
    ("l2cmn", &["guiddef", "minwindef", "winnt"], &[]),
    ("libloaderapi", &["basetsd", "minwindef", "winnt"], &["kernel32", "user32"]),
    ("lmaccess", &["basetsd", "lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmalert", &["lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmapibuf", &["lmcons", "minwindef"], &["netapi32"]),
    ("lmat", &["basetsd", "lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmdfs", &["guiddef", "lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmerrlog", &["minwindef", "winnt"], &[]),
    ("lmjoin", &["lmcons", "minwindef", "wincrypt", "winnt"], &["netapi32"]),
    ("lmmsg", &["lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmremutl", &["lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmrepl", &["lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmserver", &["guiddef", "lmcons", "minwindef", "winnt", "winsvc"], &["advapi32", "netapi32"]),
    ("lmshare", &["basetsd", "guiddef", "lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmstats", &["lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmsvc", &["lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmuse", &["lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lmwksta", &["lmcons", "minwindef", "winnt"], &["netapi32"]),
    ("lowlevelmonitorconfigurationapi", &["minwindef", "physicalmonitorenumerationapi", "winnt"], &["dxva2"]),
    ("lsalookup", &["guiddef", "minwindef", "ntdef", "winnt"], &["advapi32"]),
    ("memoryapi", &["basetsd", "minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("minschannel", &["guiddef", "minwindef", "wincrypt", "winnt"], &[]),
    ("minwinbase", &["basetsd", "minwindef", "ntstatus", "winnt"], &[]),
    ("mmdeviceapi", &["guiddef", "minwindef", "propidl", "propsys", "unknwnbase", "winnt", "wtypes"], &["mmdevapi"]),
    ("mmeapi", &["basetsd", "imm", "minwindef", "mmsystem", "winnt"], &["winmm"]),
    ("mmsystem", &["basetsd", "minwindef", "mmreg", "winnt"], &[]),
    ("msaatext", &[], &[]),
    ("mscat", &["guiddef", "minwindef", "mssip", "wincrypt", "winnt"], &[]),
    ("mschapp", &["basetsd", "minwindef", "winnt"], &["advapi32"]),
    ("mssip", &["guiddef", "minwindef", "mscat", "wincrypt", "winnt"], &["crypt32"]),
    ("mswsock", &["minwinbase", "minwindef", "mswsockdef", "winnt", "winsock2", "ws2def"], &["mswsock"]),
    ("namedpipeapi", &["minwinbase", "minwindef", "winnt"], &["advapi32", "kernel32"]),
    ("namespaceapi", &["minwinbase", "minwindef", "ntdef", "winnt"], &["kernel32"]),
    ("nb30", &["minwindef", "winnt"], &["netapi32"]),
    ("ncrypt", &["basetsd", "bcrypt", "minwindef", "winnt"], &["ncrypt"]),
    ("ntlsa", &["basetsd", "guiddef", "lsalookup", "minwindef", "ntdef", "ntsecapi", "subauth", "winnt"], &["advapi32"]),
    ("ntsecapi", &["basetsd", "guiddef", "lsalookup", "minwindef", "ntdef", "sspi", "subauth", "winnt"], &["advapi32"]),
    ("oaidl", &["basetsd", "guiddef", "minwindef", "rpcndr", "unknwnbase", "winnt", "wtypes", "wtypesbase"], &[]),
    ("objbase", &["combaseapi", "minwindef", "winnt"], &["ole32"]),
    ("objidl", &["basetsd", "guiddef", "minwindef", "ntdef", "objidlbase", "unknwnbase", "windef", "winnt", "wtypes", "wtypesbase"], &[]),
    ("objidlbase", &["basetsd", "guiddef", "minwindef", "unknwnbase", "winnt", "wtypesbase"], &[]),
    ("ocidl", &["guiddef", "minwindef", "ntdef", "oaidl", "unknwnbase", "wtypes", "wtypesbase"], &[]),
    ("ole2", &["minwindef", "oleidl", "windef", "winnt"], &["ole32"]),
    ("oleauto", &["basetsd", "minwinbase", "minwindef", "oaidl", "winnt", "wtypes", "wtypesbase"], &["oleaut32"]),
    ("olectl", &["winerror", "winnt"], &[]),
    ("oleidl", &["minwindef", "ntdef", "objidl", "unknwnbase", "windef"], &[]),
    ("opmapi", &["basetsd", "d3d9", "d3d9types", "dxva2api", "guiddef", "minwindef", "unknwnbase", "windef", "winnt"], &["dxva2"]),
    ("pdh", &["basetsd", "guiddef", "minwindef", "windef", "winnt"], &["pdh"]),
    ("perflib", &["basetsd", "guiddef", "minwinbase", "minwindef", "winnt"], &["advapi32"]),
    ("physicalmonitorenumerationapi", &["d3d9", "minwindef", "windef", "winnt"], &["dxva2"]),
    ("playsoundapi", &["minwindef", "winnt"], &["winmm"]),
    ("portabledevice", &["basetsd", "wtypes"], &[]),
    ("portabledeviceapi", &["guiddef", "minwindef", "objidlbase", "portabledevicetypes", "propkeydef", "unknwnbase", "winnt"], &[]),
    ("portabledevicetypes", &["guiddef", "minwindef", "propidl", "propkeydef", "propsys", "unknwnbase", "winnt", "wtypes"], &[]),
    ("powerbase", &["minwindef", "winnt", "winuser"], &["powrprof"]),
    ("powersetting", &["guiddef", "minwindef", "winnt", "winuser"], &["powrprof"]),
    ("powrprof", &["guiddef", "minwindef", "winnt", "winreg"], &["powrprof"]),
    ("processenv", &["minwindef", "winnt"], &["kernel32"]),
    ("processsnapshot", &["basetsd", "minwindef", "winnt"], &["kernel32"]),
    ("processthreadsapi", &["basetsd", "guiddef", "minwinbase", "minwindef", "winnt"], &["advapi32", "kernel32"]),
    ("processtopologyapi", &["minwindef", "winnt"], &["kernel32"]),
    ("profileapi", &["minwindef", "winnt"], &["kernel32"]),
    ("propidl", &["guiddef", "minwindef", "ntdef", "oaidl", "objidlbase", "unknwnbase", "wtypes", "wtypesbase"], &["ole32"]),
    ("propkey", &["minwindef", "ntdef", "wtypes"], &[]),
    ("propkeydef", &["guiddef", "wtypes"], &[]),
    ("propsys", &["minwindef", "propidl", "propkeydef", "unknwnbase", "winnt", "wtypes"], &[]),
    ("prsht", &["basetsd", "minwindef", "windef", "winnt", "winuser"], &["comctl32"]),
    ("psapi", &["basetsd", "minwindef", "winnt"], &["kernel32", "psapi"]),
    ("realtimeapiset", &["basetsd", "minwindef", "winnt"], &["kernel32"]),
    ("reason", &["minwindef"], &[]),
    ("restartmanager", &["minwindef", "winnt"], &["rstrtmgr"]),
    ("restrictederrorinfo", &["unknwnbase", "winnt", "wtypes"], &[]),
    ("rmxfguid", &[], &[]),
    ("rtinfo", &["basetsd"], &[]),
    ("sapi", &["guiddef", "minwindef", "sapi53", "unknwnbase", "winnt"], &[]),
    ("sapi51", &["guiddef", "minwindef", "mmreg", "oaidl", "objidlbase", "rpcndr", "servprov", "unknwnbase", "windef", "winnt", "wtypes", "wtypesbase"], &[]),
    ("sapi53", &["guiddef", "minwindef", "oaidl", "sapi51", "unknwnbase", "urlmon", "winnt", "wtypes"], &[]),
    ("sapiddk", &["guiddef", "minwindef", "sapi", "sapiddk51", "unknwnbase", "winnt"], &[]),
    ("sapiddk51", &["guiddef", "minwindef", "mmreg", "oaidl", "objidlbase", "sapi", "unknwnbase", "windef", "winnt"], &[]),
    ("schannel", &["guiddef", "minwindef", "wincrypt", "windef", "winnt"], &[]),
    ("securityappcontainer", &["minwindef", "winnt"], &["kernel32"]),
    ("securitybaseapi", &["guiddef", "minwinbase", "minwindef", "winnt"], &["advapi32", "kernel32"]),
    ("servprov", &["guiddef", "unknwnbase", "winnt"], &[]),
    ("setupapi", &["basetsd", "commctrl", "devpropdef", "guiddef", "minwindef", "prsht", "spapidef", "windef", "winnt", "winreg"], &["setupapi"]),
    ("shellapi", &["basetsd", "guiddef", "minwinbase", "minwindef", "processthreadsapi", "windef", "winnt", "winuser"], &["shell32", "shlwapi"]),
    ("shellscalingapi", &["minwindef", "windef", "winnt"], &["shcore"]),
    ("shlobj", &["guiddef", "minwinbase", "minwindef", "shtypes", "windef", "winnt"], &["shell32"]),
    ("shobjidl", &["guiddef", "minwindef", "propsys", "shobjidl_core", "shtypes", "unknwnbase", "windef", "winnt"], &[]),
    ("shobjidl_core", &["commctrl", "guiddef", "minwinbase", "minwindef", "objidl", "propkeydef", "propsys", "shtypes", "unknwnbase", "windef", "winnt"], &[]),
    ("shtypes", &["guiddef", "minwindef", "winnt"], &[]),
    ("softpub", &[], &[]),
    ("spapidef", &["minwindef", "winnt"], &[]),
    ("spellcheck", &["minwindef", "ntdef", "objidlbase", "unknwnbase", "winerror"], &[]),
    ("sporder", &["guiddef", "minwindef"], &["sporder"]),
    ("sql", &["sqltypes"], &["odbc32"]),
    ("sqlext", &["sql", "sqltypes"], &[]),
    ("sqltypes", &["basetsd", "guiddef", "windef"], &[]),
    ("sqlucode", &["sqltypes"], &["odbc32"]),
    ("stringapiset", &["minwindef", "winnls", "winnt"], &["kernel32"]),
    ("strmif", &["winnt"], &[]),
    ("subauth", &["minwindef", "winnt"], &[]),
    ("synchapi", &["basetsd", "minwinbase", "minwindef", "winnt"], &["kernel32", "synchronization"]),
    ("sysinfoapi", &["basetsd", "minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("systemtopologyapi", &["minwindef", "winnt"], &["kernel32"]),
    ("taskschd", &["minwinbase", "minwindef", "oaidl", "unknwnbase", "winnt", "wtypes"], &[]),
    ("textstor", &[], &[]),
    ("threadpoolapiset", &["basetsd", "minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("threadpoollegacyapiset", &["minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("timeapi", &["minwindef", "mmsystem"], &["winmm"]),
    ("timezoneapi", &["minwinbase", "minwindef", "winnt"], &["advapi32", "kernel32"]),
    ("tlhelp32", &["basetsd", "minwindef", "winnt"], &["kernel32"]),
    ("unknwnbase", &["guiddef", "minwindef", "winnt"], &[]),
    ("urlhist", &["docobj", "guiddef", "minwindef", "unknwnbase", "winnt", "wtypesbase"], &[]),
    ("urlmon", &["minwindef", "unknwnbase", "winnt"], &[]),
    ("userenv", &["minwindef", "winnt", "winreg"], &["userenv"]),
    ("usp10", &["minwindef", "ntdef", "windef", "winerror", "wingdi", "winnt"], &["usp10"]),
    ("utilapiset", &["minwindef", "ntdef"], &["kernel32"]),
    ("uxtheme", &["commctrl", "minwindef", "windef", "wingdi", "winnt"], &["uxtheme"]),
    ("vsbackup", &["guiddef", "minwindef", "unknwnbase", "vss", "vswriter", "winnt", "wtypes"], &["vssapi"]),
    ("vss", &["guiddef", "minwindef", "unknwnbase", "winnt"], &[]),
    ("vsserror", &["winnt"], &[]),
    ("vswriter", &["minwindef", "unknwnbase", "vss", "winnt", "wtypes"], &[]),
    ("wbemads", &["oaidl", "wbemdisp", "winerror", "wtypes"], &[]),
    ("wbemcli", &["minwindef", "oaidl", "rpcndr", "unknwnbase", "winerror", "winnt", "wtypes"], &[]),
    ("wbemdisp", &["oaidl", "unknwnbase", "winerror", "wtypes"], &[]),
    ("wbemprov", &["minwindef", "oaidl", "unknwnbase", "wbemcli", "winerror", "winnt", "wtypes"], &[]),
    ("wbemtran", &["guiddef", "minwindef", "unknwnbase", "wbemcli", "winerror", "winnt", "wtypes"], &[]),
    ("wct", &["basetsd", "guiddef", "minwindef", "winnt"], &["advapi32"]),
    ("werapi", &["minwindef", "winnt"], &["kernel32", "wer"]),
    ("winbase", &["basetsd", "cfgmgr32", "fileapi", "guiddef", "libloaderapi", "minwinbase", "minwindef", "processthreadsapi", "vadefs", "windef", "winnt"], &["kernel32"]),
    ("wincodec", &["basetsd", "d2d1", "d2d1_1", "dcommon", "dxgiformat", "dxgitype", "guiddef", "minwindef", "ntdef", "objidlbase", "ocidl", "propidl", "unknwnbase", "windef", "winerror", "winnt"], &["windowscodecs"]),
    ("wincodecsdk", &["guiddef", "minwindef", "oaidl", "objidl", "objidlbase", "ocidl", "propidl", "unknwnbase", "wincodec", "winnt", "wtypes"], &["ole32", "oleaut32", "windowscodecs"]),
    ("wincon", &["minwinbase", "minwindef", "wincontypes", "windef", "wingdi", "winnt"], &["kernel32"]),
    ("wincontypes", &["minwindef", "winnt"], &[]),
    ("wincred", &["minwindef", "sspi", "windef", "winnt"], &["advapi32", "credui"]),
    ("wincrypt", &["basetsd", "bcrypt", "guiddef", "minwinbase", "minwindef", "ncrypt", "vcruntime", "winnt"], &["advapi32", "crypt32", "cryptnet"]),
    ("windowsceip", &["minwindef"], &["kernel32"]),
    ("winefs", &["basetsd", "minwinbase", "minwindef", "wincrypt", "winnt"], &["advapi32"]),
    ("winevt", &["basetsd", "guiddef", "minwinbase", "minwindef", "vcruntime", "winnt"], &["wevtapi"]),
    ("wingdi", &["basetsd", "minwindef", "windef", "winnt"], &["gdi32", "msimg32", "opengl32", "winspool"]),
    ("winhttp", &["basetsd", "minwinbase", "minwindef", "winnt"], &["winhttp"]),
    ("wininet", &["basetsd", "minwinbase", "minwindef", "ntdef", "windef", "winineti", "winnt"], &["wininet"]),
    ("winineti", &["minwindef"], &[]),
    ("winioctl", &["basetsd", "devpropdef", "guiddef", "minwindef", "winnt"], &[]),
    ("winnetwk", &["basetsd", "minwindef", "windef", "winerror", "winnt"], &["mpr"]),
    ("winnls", &["basetsd", "guiddef", "minwinbase", "minwindef", "winnt"], &["kernel32"]),
    ("winnt", &["basetsd", "excpt", "guiddef", "ktmtypes", "minwindef", "ntdef", "vcruntime"], &["kernel32"]),
    ("winreg", &["basetsd", "minwinbase", "minwindef", "reason", "winnt"], &["advapi32"]),
    ("winsafer", &["basetsd", "guiddef", "minwindef", "wincrypt", "windef", "winnt"], &["advapi32"]),
    ("winscard", &["basetsd", "guiddef", "minwindef", "rpcdce", "windef", "winnt", "winsmcrd"], &["winscard"]),
    ("winsmcrd", &["minwindef", "winioctl"], &[]),
    ("winsock2", &["basetsd", "guiddef", "inaddr", "minwinbase", "minwindef", "qos", "winbase", "windef", "winerror", "winnt", "ws2def", "wtypesbase"], &["ws2_32"]),
    ("winspool", &["guiddef", "minwinbase", "minwindef", "vcruntime", "windef", "winerror", "wingdi", "winnt"], &["winspool"]),
    ("winsvc", &["minwindef", "winnt"], &["advapi32"]),
    ("wintrust", &["guiddef", "minwindef", "ntdef", "wincrypt", "windef"], &["wintrust"]),
    ("winusb", &["minwinbase", "minwindef", "usb", "usbspec", "winnt", "winusbio"], &["winusb"]),
    ("winuser", &["basetsd", "guiddef", "limits", "minwinbase", "minwindef", "vadefs", "windef", "wingdi", "winnt"], &["user32"]),
    ("winver", &["minwindef", "winnt"], &["kernel32", "version"]),
    ("wlanapi", &["devpropdef", "eaptypes", "guiddef", "l2cmn", "minwindef", "windef", "windot11", "winnt", "wlantypes"], &["wlanapi"]),
    ("wlanihv", &["basetsd", "dot1x", "eaptypes", "guiddef", "l2cmn", "minwindef", "windot11", "winnt", "winuser", "wlanihvtypes", "wlantypes", "wlclient"], &[]),
    ("wlanihvtypes", &["eaptypes", "guiddef", "minwindef", "winnt", "wlantypes"], &[]),
    ("wlclient", &["guiddef", "minwindef", "windot11", "winnt"], &[]),
    ("wow64apiset", &["minwindef", "winnt"], &["kernel32"]),
    ("wpdmtpextensions", &["wtypes"], &[]),
    ("ws2bth", &["bthdef", "bthsdpdef", "guiddef", "minwindef", "winnt", "ws2def"], &[]),
    ("ws2spi", &["basetsd", "guiddef", "minwindef", "vcruntime", "windef", "winnt", "winsock2", "ws2def", "wtypesbase"], &["ws2_32"]),
    ("ws2tcpip", &["guiddef", "minwinbase", "minwindef", "mstcpip", "vcruntime", "winerror", "winnt", "winsock2", "ws2def", "wtypesbase"], &["fwpuclnt", "ws2_32"]),
    ("wtsapi32", &["minwindef", "ntdef"], &["wtsapi32"]),
    ("xinput", &["guiddef", "minwindef", "winnt"], &["xinput"]),
    // vc
    ("excpt", &[], &[]),
    ("limits", &[], &[]),
    ("vadefs", &[], &[]),
    ("vcruntime", &[], &[]),
    // winrt
    ("activation", &["inspectable", "winnt"], &[]),
    ("hstring", &["winnt"], &[]),
    ("inspectable", &["guiddef", "hstring", "minwindef", "unknwnbase", "winnt"], &[]),
    ("roapi", &["activation", "basetsd", "guiddef", "hstring", "inspectable", "objidl", "winnt"], &["runtimeobject"]),
    ("robuffer", &["objidl", "winnt"], &["runtimeobject"]),
    ("roerrorapi", &["basetsd", "hstring", "minwindef", "restrictederrorinfo", "unknwnbase", "winnt"], &["runtimeobject"]),
    ("winstring", &["basetsd", "hstring", "minwindef", "winnt"], &["runtimeobject"]),
];
struct Header {
    required: bool,
    included: Cell<bool>,
    dependencies: &'static [&'static str],
    libraries: &'static [&'static str],
}
struct Graph(HashMap<&'static str, Header>);
impl Graph {
    fn generate() -> Graph {
        Graph(DATA.iter().map(|&(name, dependencies, libraries)| {
            let header = Header {
                required: false,
                included: Cell::new(false),
                dependencies: dependencies,
                libraries: libraries,
            };
            (name, header)
        }).collect())
    }
    fn identify_required(&mut self) {
        for (name, header) in &mut self.0 {
            if let Ok(_) = var(&format!("CARGO_FEATURE_{}", name.to_uppercase())) {
                header.required = true;
                header.included.set(true);
            }
        }
    }
    fn check_everything(&self) {
        if let Ok(_) = var("CARGO_FEATURE_EVERYTHING") {
            for (_, header) in &self.0 {
                header.included.set(true);
            }
        }
    }
    fn resolve_dependencies(&self) {
        let mut done = false;
        while !done {
            done = true;
            for (_, header) in &self.0 {
                if header.included.get() {
                    for dep in header.dependencies {
                        let dep = &self.0.get(dep).expect(dep);
                        if !dep.included.get() {
                            done = false;
                            dep.included.set(true);
                        }
                    }
                }
            }
        }
    }
    fn emit_features(&self) {
        for (name, header) in &self.0 {
            if header.included.get() && !header.required {
                println!("cargo:rustc-cfg=feature=\"{}\"", name);
            }
        }
    }
    fn emit_libraries(&self) {
        let mut libs = self.0.iter().filter(|&(_, header)| {
            header.included.get()
        }).flat_map(|(_, header)| {
            header.libraries.iter()
        }).collect::<Vec<_>>();
        libs.sort();
        libs.dedup();
        // FIXME Temporary hacks until build script is redesigned.
        libs.retain(|&&lib| match &*var("TARGET").unwrap() {
            "aarch64-pc-windows-msvc" | "aarch64-uwp-windows-msvc" | "thumbv7a-pc-windows-msvc" => {
                if lib == "opengl32" { false }
                else { true }
            },
            _ => true,
        });
        let prefix = library_prefix();
        let kind = library_kind();
        for lib in libs {
            println!("cargo:rustc-link-lib={}={}{}", kind, prefix, lib);
        }
    }
}
fn library_prefix() -> &'static str {
    if var("TARGET").map(|target|
        target == "i686-pc-windows-gnu" || target == "x86_64-pc-windows-gnu"
    ).unwrap_or(false) && var("WINAPI_NO_BUNDLED_LIBRARIES").is_err() {
        "winapi_"
    } else {
        ""
    }
}
fn library_kind() -> &'static str {
    if var("WINAPI_STATIC_NOBUNDLE").is_ok() {
        "static-nobundle"
    } else {
        "dylib"
    }
}
fn try_everything() {
    let mut graph = Graph::generate();
    graph.identify_required();
    graph.check_everything();
    graph.resolve_dependencies();
    graph.emit_features();
    graph.emit_libraries();
}
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=WINAPI_NO_BUNDLED_LIBRARIES");
    println!("cargo:rerun-if-env-changed=WINAPI_STATIC_NOBUNDLE");
    let target = var("TARGET").unwrap();
    let target: Vec<_> = target.split('-').collect();
    if target.get(2) == Some(&"windows") {
        try_everything();
    }
}
========== build.rs from winapi-i686-pc-windows-gnu-0.4.0 ============================================================
// Copyright © 2016-2018 winapi-rs developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
fn main() {
    use std::env::var;
    use std::path::Path;
    println!("cargo:rerun-if-env-changed=WINAPI_NO_BUNDLED_LIBRARIES");
    if var("WINAPI_NO_BUNDLED_LIBRARIES").is_ok() {
        return;
    }
    if var("TARGET").map(|target| target == "i686-pc-windows-gnu").unwrap_or(false) {
        let dir = var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-search=native={}", Path::new(&dir).join("lib").display());
    }
}
========== build.rs from winapi-x86_64-pc-windows-gnu-0.4.0 ============================================================
// Copyright © 2016-2018 winapi-rs developers
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
fn main() {
    use std::env::var;
    use std::path::Path;
    println!("cargo:rerun-if-env-changed=WINAPI_NO_BUNDLED_LIBRARIES");
    if var("WINAPI_NO_BUNDLED_LIBRARIES").is_ok() {
        return;
    }
    if var("TARGET").map(|target| target == "x86_64-pc-windows-gnu").unwrap_or(false) {
        let dir = var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-search=native={}", Path::new(&dir).join("lib").display());
    }
}
========== build.rs from windows_aarch64_gnullvm-0.48.0 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "aarch64-pc-windows-gnullvm" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_aarch64_msvc-0.36.1 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "aarch64-pc-windows-msvc" && target != "aarch64-uwp-windows-msvc" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_aarch64_msvc-0.48.0 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "aarch64-pc-windows-msvc" && target != "aarch64-uwp-windows-msvc" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_i686_gnu-0.36.1 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "i686-pc-windows-gnu" && target != "i686-uwp-windows-gnu" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_i686_gnu-0.48.0 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "i686-pc-windows-gnu" && target != "i686-uwp-windows-gnu" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_i686_msvc-0.36.1 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "i686-pc-windows-msvc" && target != "i686-uwp-windows-msvc" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_i686_msvc-0.48.0 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "i686-pc-windows-msvc" && target != "i686-uwp-windows-msvc" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_x86_64_gnu-0.36.1 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "x86_64-pc-windows-gnu" && target != "x86_64-uwp-windows-gnu" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_x86_64_gnu-0.48.0 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "x86_64-pc-windows-gnu" && target != "x86_64-uwp-windows-gnu" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_x86_64_gnullvm-0.48.0 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "x86_64-pc-windows-gnullvm" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_x86_64_msvc-0.36.1 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "x86_64-pc-windows-msvc" && target != "x86_64-uwp-windows-msvc" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from windows_x86_64_msvc-0.48.0 ============================================================
fn main() {
    let target = std::env::var("TARGET").unwrap();
    if target != "x86_64-pc-windows-msvc" && target != "x86_64-uwp-windows-msvc" {
        return;
    }

    let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();

    println!("cargo:rustc-link-search=native={}", std::path::Path::new(&dir).join("lib").display());
}
========== build.rs from x11-dl-2.19.1 ============================================================
// x11-rs: Rust bindings for X11 libraries
// The X11 libraries are available under the MIT license.
// These bindings are public domain.

extern crate pkg_config;

use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let libraries = [
        // lib           pkgconfig name
        ("xext", "xext"),
        ("gl", "gl"),
        ("xcursor", "xcursor"),
        ("xxf86vm", "xxf86vm"),
        ("xft", "xft"),
        ("xinerama", "xinerama"),
        ("xi", "xi"),
        ("x11", "x11"),
        ("xlib_xcb", "x11-xcb"),
        ("xmu", "xmu"),
        ("xrandr", "xrandr"),
        ("xtst", "xtst"),
        ("xrender", "xrender"),
        ("xscrnsaver", "xscrnsaver"),
        ("xt", "xt"),
    ];

    let mut config = String::new();
    for &(lib, pcname) in libraries.iter() {
        let libdir = match pkg_config::get_variable(pcname, "libdir") {
            Ok(libdir) => format!("Some(\"{}\")", libdir),
            Err(_) => "None".to_string(),
        };
        config.push_str(&format!(
            "pub const {}: Option<&'static str> = {};\n",
            lib, libdir
        ));
    }
    let config = format!("pub mod config {{ pub mod libdir {{\n{}}}\n}}", config);
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("config.rs");
    let mut f = File::create(&dest_path).unwrap();
    f.write_all(&config.into_bytes()).unwrap();

    let target = env::var("TARGET").unwrap();
    if target.contains("linux") {
        println!("cargo:rustc-link-lib=dl");
    } else if target.contains("freebsd") || target.contains("dragonfly") {
        println!("cargo:rustc-link-lib=c");
    }
}
========== build.rs from xous-0.9.50 ============================================================
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
========== build.rs from xous-riscv-0.5.6 ============================================================
use std::path::PathBuf;
use std::{env, fs};

fn main() {
    let target = env::var("TARGET").unwrap();
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let name = env::var("CARGO_PKG_NAME").unwrap();

    if target.starts_with("riscv") && env::var_os("CARGO_FEATURE_INLINE_ASM").is_none() {
        fs::copy(
            format!("bin/{}.a", target),
            out_dir.join(format!("lib{}.a", name)),
        ).unwrap();

        println!("cargo:rustc-link-lib=static={}", name);
        println!("cargo:rustc-link-search={}", out_dir.display());
    }

    if target.starts_with("riscv32") {
        println!("cargo:rustc-cfg=riscv");
        println!("cargo:rustc-cfg=riscv32");
    } else if target.starts_with("riscv64") {
        println!("cargo:rustc-cfg=riscv");
        println!("cargo:rustc-cfg=riscv64");
    }
}
========== build.rs from zstd-safe-5.0.2+zstd.1.5.2 ============================================================
fn main() {
    // Force the `std` feature in some cases
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    if target_arch == "wasm32" || target_os == "hermit" {
        println!("cargo:rustc-cfg=feature=\"std\"");
    }
}
