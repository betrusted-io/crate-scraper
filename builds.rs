========== build.rs from packed_simd_2-0.3.7 ============================================================
fn main() {
    let target = std::env::var("TARGET").expect("TARGET environment variable not defined");
    if target.contains("neon") {
        println!("cargo:rustc-cfg=libcore_neon");
    }
}
========== build.rs from num-integer-0.1.44 ============================================================
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
========== build.rs from crossbeam-utils-0.8.6 ============================================================
#![warn(rust_2018_idioms)]

use std::env;

include!("no_atomic.rs");

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
// With the exceptions mentioned above, the rustc-cfg strings below are
// *not* public API. Please let us know by opening a GitHub issue if your build
// environment requires some way to enable these cfgs other than by executing
// our build script.
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
        // Otherwise, assuming `"max-atomic-width" == 64`.
    }

    println!("cargo:rerun-if-changed=no_atomic.rs");
}
========== build.rs from ring-0.16.20 ============================================================
// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! Build the non-Rust components.

// It seems like it would be a good idea to use `log!` for logging, but it
// isn't worth having the external dependencies (one for the `log` crate, and
// another for the concrete logging implementation). Instead we use `eprintln!`
// to log everything to stderr.

// In the `pregenerate_asm_main()` case we don't want to access (Cargo)
// environment variables at all, so avoid `use std::env` here.

use std::{
    fs::{self, DirEntry},
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

const X86: &str = "x86";
const X86_64: &str = "x86_64";
const AARCH64: &str = "aarch64";
const ARM: &str = "arm";

#[rustfmt::skip]
const RING_SRCS: &[(&[&str], &str)] = &[
    (&[], "crypto/fipsmodule/aes/aes_nohw.c"),
    (&[], "crypto/fipsmodule/bn/montgomery.c"),
    (&[], "crypto/fipsmodule/bn/montgomery_inv.c"),
    (&[], "crypto/limbs/limbs.c"),
    (&[], "crypto/mem.c"),
    (&[], "crypto/poly1305/poly1305.c"),

    (&[AARCH64, ARM, X86_64, X86], "crypto/crypto.c"),
    (&[AARCH64, ARM, X86_64, X86], "crypto/curve25519/curve25519.c"),
    (&[AARCH64, ARM, X86_64, X86], "crypto/fipsmodule/ec/ecp_nistz.c"),
    (&[AARCH64, ARM, X86_64, X86], "crypto/fipsmodule/ec/ecp_nistz256.c"),
    (&[AARCH64, ARM, X86_64, X86], "crypto/fipsmodule/ec/gfp_p256.c"),
    (&[AARCH64, ARM, X86_64, X86], "crypto/fipsmodule/ec/gfp_p384.c"),

    (&[X86_64, X86], "crypto/cpu-intel.c"),

    (&[X86], "crypto/fipsmodule/aes/asm/aesni-x86.pl"),
    (&[X86], "crypto/fipsmodule/aes/asm/vpaes-x86.pl"),
    (&[X86], "crypto/fipsmodule/bn/asm/x86-mont.pl"),
    (&[X86], "crypto/chacha/asm/chacha-x86.pl"),
    (&[X86], "crypto/fipsmodule/ec/asm/ecp_nistz256-x86.pl"),
    (&[X86], "crypto/fipsmodule/modes/asm/ghash-x86.pl"),

    (&[X86_64], "crypto/fipsmodule/aes/asm/aesni-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/aes/asm/vpaes-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/bn/asm/x86_64-mont.pl"),
    (&[X86_64], "crypto/fipsmodule/bn/asm/x86_64-mont5.pl"),
    (&[X86_64], "crypto/chacha/asm/chacha-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/ec/asm/p256-x86_64-asm.pl"),
    (&[X86_64], "crypto/fipsmodule/modes/asm/aesni-gcm-x86_64.pl"),
    (&[X86_64], "crypto/fipsmodule/modes/asm/ghash-x86_64.pl"),
    (&[X86_64], "crypto/poly1305/poly1305_vec.c"),
    (&[X86_64], SHA512_X86_64),
    (&[X86_64], "crypto/cipher_extra/asm/chacha20_poly1305_x86_64.pl"),

    (&[AARCH64, ARM], "crypto/fipsmodule/aes/asm/aesv8-armx.pl"),
    (&[AARCH64, ARM], "crypto/fipsmodule/modes/asm/ghashv8-armx.pl"),

    (&[ARM], "crypto/fipsmodule/aes/asm/bsaes-armv7.pl"),
    (&[ARM], "crypto/fipsmodule/aes/asm/vpaes-armv7.pl"),
    (&[ARM], "crypto/fipsmodule/bn/asm/armv4-mont.pl"),
    (&[ARM], "crypto/chacha/asm/chacha-armv4.pl"),
    (&[ARM], "crypto/curve25519/asm/x25519-asm-arm.S"),
    (&[ARM], "crypto/fipsmodule/ec/asm/ecp_nistz256-armv4.pl"),
    (&[ARM], "crypto/fipsmodule/modes/asm/ghash-armv4.pl"),
    (&[ARM], "crypto/poly1305/poly1305_arm.c"),
    (&[ARM], "crypto/poly1305/poly1305_arm_asm.S"),
    (&[ARM], "crypto/fipsmodule/sha/asm/sha256-armv4.pl"),
    (&[ARM], "crypto/fipsmodule/sha/asm/sha512-armv4.pl"),

    (&[AARCH64], "crypto/fipsmodule/aes/asm/vpaes-armv8.pl"),
    (&[AARCH64], "crypto/fipsmodule/bn/asm/armv8-mont.pl"),
    (&[AARCH64], "crypto/chacha/asm/chacha-armv8.pl"),
    (&[AARCH64], "crypto/fipsmodule/ec/asm/ecp_nistz256-armv8.pl"),
    (&[AARCH64], "crypto/fipsmodule/modes/asm/ghash-neon-armv8.pl"),
    (&[AARCH64], SHA512_ARMV8),
];

const SHA256_X86_64: &str = "crypto/fipsmodule/sha/asm/sha256-x86_64.pl";
const SHA512_X86_64: &str = "crypto/fipsmodule/sha/asm/sha512-x86_64.pl";

const SHA256_ARMV8: &str = "crypto/fipsmodule/sha/asm/sha256-armv8.pl";
const SHA512_ARMV8: &str = "crypto/fipsmodule/sha/asm/sha512-armv8.pl";

const RING_TEST_SRCS: &[&str] = &[("crypto/constant_time_test.c")];

#[rustfmt::skip]
const RING_INCLUDES: &[&str] =
    &[
      "crypto/curve25519/curve25519_tables.h",
      "crypto/curve25519/internal.h",
      "crypto/fipsmodule/bn/internal.h",
      "crypto/fipsmodule/ec/ecp_nistz256_table.inl",
      "crypto/fipsmodule/ec/ecp_nistz384.inl",
      "crypto/fipsmodule/ec/ecp_nistz.h",
      "crypto/fipsmodule/ec/ecp_nistz384.h",
      "crypto/fipsmodule/ec/ecp_nistz256.h",
      "crypto/internal.h",
      "crypto/limbs/limbs.h",
      "crypto/limbs/limbs.inl",
      "crypto/poly1305/internal.h",
      "include/GFp/aes.h",
      "include/GFp/arm_arch.h",
      "include/GFp/base.h",
      "include/GFp/check.h",
      "include/GFp/cpu.h",
      "include/GFp/mem.h",
      "include/GFp/poly1305.h",
      "include/GFp/type_check.h",
      "third_party/fiat/curve25519_32.h",
      "third_party/fiat/curve25519_64.h",
    ];

#[rustfmt::skip]
const RING_PERL_INCLUDES: &[&str] =
    &["crypto/perlasm/arm-xlate.pl",
      "crypto/perlasm/x86gas.pl",
      "crypto/perlasm/x86nasm.pl",
      "crypto/perlasm/x86asm.pl",
      "crypto/perlasm/x86_64-xlate.pl"];

const RING_BUILD_FILE: &[&str] = &["build.rs"];

const PREGENERATED: &str = "pregenerated";

fn c_flags(target: &Target) -> &'static [&'static str] {
    if target.env != MSVC {
        static NON_MSVC_FLAGS: &[&str] = &[
            "-std=c1x", // GCC 4.6 requires "c1x" instead of "c11"
            "-Wbad-function-cast",
            "-Wnested-externs",
            "-Wstrict-prototypes",
        ];
        NON_MSVC_FLAGS
    } else {
        &[]
    }
}

fn cpp_flags(target: &Target) -> &'static [&'static str] {
    if target.env != MSVC {
        static NON_MSVC_FLAGS: &[&str] = &[
            "-pedantic",
            "-pedantic-errors",
            "-Wall",
            "-Wextra",
            "-Wcast-align",
            "-Wcast-qual",
            "-Wconversion",
            "-Wenum-compare",
            "-Wfloat-equal",
            "-Wformat=2",
            "-Winline",
            "-Winvalid-pch",
            "-Wmissing-field-initializers",
            "-Wmissing-include-dirs",
            "-Wredundant-decls",
            "-Wshadow",
            "-Wsign-compare",
            "-Wsign-conversion",
            "-Wundef",
            "-Wuninitialized",
            "-Wwrite-strings",
            "-fno-strict-aliasing",
            "-fvisibility=hidden",
        ];
        NON_MSVC_FLAGS
    } else {
        static MSVC_FLAGS: &[&str] = &[
            "/GS",   // Buffer security checks.
            "/Gy",   // Enable function-level linking.
            "/EHsc", // C++ exceptions only, only in C++.
            "/GR-",  // Disable RTTI.
            "/Zc:wchar_t",
            "/Zc:forScope",
            "/Zc:inline",
            "/Zc:rvalueCast",
            // Warnings.
            "/sdl",
            "/Wall",
            "/wd4127", // C4127: conditional expression is constant
            "/wd4464", // C4464: relative include path contains '..'
            "/wd4514", // C4514: <name>: unreferenced inline function has be
            "/wd4710", // C4710: function not inlined
            "/wd4711", // C4711: function 'function' selected for inline expansion
            "/wd4820", // C4820: <struct>: <n> bytes padding added after <name>
            "/wd5045", /* C5045: Compiler will insert Spectre mitigation for memory load if
                        * /Qspectre switch specified */
        ];
        MSVC_FLAGS
    }
}

const LD_FLAGS: &[&str] = &[];

// None means "any OS" or "any target". The first match in sequence order is
// taken.
const ASM_TARGETS: &[(&str, Option<&str>, Option<&str>)] = &[
    ("x86_64", Some("ios"), Some("macosx")),
    ("x86_64", Some("macos"), Some("macosx")),
    ("x86_64", Some(WINDOWS), Some("nasm")),
    ("x86_64", None, Some("elf")),
    ("aarch64", Some("ios"), Some("ios64")),
    ("aarch64", Some("macos"), Some("ios64")),
    ("aarch64", None, Some("linux64")),
    ("x86", Some(WINDOWS), Some("win32n")),
    ("x86", Some("ios"), Some("macosx")),
    ("x86", None, Some("elf")),
    ("arm", Some("ios"), Some("ios32")),
    ("arm", None, Some("linux32")),
    ("wasm32", None, None),
];

const WINDOWS: &str = "windows";
const MSVC: &str = "msvc";
const MSVC_OBJ_OPT: &str = "/Fo";
const MSVC_OBJ_EXT: &str = "obj";

fn main() {
    if let Ok(package_name) = std::env::var("CARGO_PKG_NAME") {
        if package_name == "ring" {
            ring_build_rs_main();
            return;
        }
    }

    pregenerate_asm_main();
}

fn ring_build_rs_main() {
    use std::env;

    let out_dir = env::var("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let env = env::var("CARGO_CFG_TARGET_ENV").unwrap();
    let (obj_ext, obj_opt) = if env == MSVC {
        (MSVC_OBJ_EXT, MSVC_OBJ_OPT)
    } else {
        ("o", "-o")
    };

    let is_git = std::fs::metadata(".git").is_ok();

    // Published builds are always release builds.
    let is_debug = is_git && env::var("DEBUG").unwrap() != "false";

    let target = Target {
        arch,
        os,
        env,
        obj_ext,
        obj_opt,
        is_git,
        is_debug,
    };
    let pregenerated = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join(PREGENERATED);

    build_c_code(&target, pregenerated, &out_dir);
    check_all_files_tracked()
}

fn pregenerate_asm_main() {
    let pregenerated = PathBuf::from(PREGENERATED);
    std::fs::create_dir(&pregenerated).unwrap();
    let pregenerated_tmp = pregenerated.join("tmp");
    std::fs::create_dir(&pregenerated_tmp).unwrap();

    for &(target_arch, target_os, perlasm_format) in ASM_TARGETS {
        // For Windows, package pregenerated object files instead of
        // pregenerated assembly language source files, so that the user
        // doesn't need to install the assembler.
        let asm_dir = if target_os == Some(WINDOWS) {
            &pregenerated_tmp
        } else {
            &pregenerated
        };

        if let Some(perlasm_format) = perlasm_format {
            let perlasm_src_dsts =
                perlasm_src_dsts(&asm_dir, target_arch, target_os, perlasm_format);
            perlasm(&perlasm_src_dsts, target_arch, perlasm_format, None);

            if target_os == Some(WINDOWS) {
                let srcs = asm_srcs(perlasm_src_dsts);
                for src in srcs {
                    let obj_path = obj_path(&pregenerated, &src, MSVC_OBJ_EXT);
                    run_command(nasm(&src, target_arch, &obj_path));
                }
            }
        }
    }
}

struct Target {
    arch: String,
    os: String,
    env: String,
    obj_ext: &'static str,
    obj_opt: &'static str,
    is_git: bool,
    is_debug: bool,
}

fn build_c_code(target: &Target, pregenerated: PathBuf, out_dir: &Path) {
    #[cfg(not(feature = "wasm32_c"))]
    {
        if &target.arch == "wasm32" {
            return;
        }
    }

    let includes_modified = RING_INCLUDES
        .iter()
        .chain(RING_BUILD_FILE.iter())
        .chain(RING_PERL_INCLUDES.iter())
        .map(|f| file_modified(Path::new(*f)))
        .max()
        .unwrap();

    fn is_none_or_equals<T>(opt: Option<T>, other: T) -> bool
    where
        T: PartialEq,
    {
        if let Some(value) = opt {
            value == other
        } else {
            true
        }
    }

    let (_, _, perlasm_format) = ASM_TARGETS
        .iter()
        .find(|entry| {
            let &(entry_arch, entry_os, _) = *entry;
            entry_arch == target.arch && is_none_or_equals(entry_os, &target.os)
        })
        .unwrap();

    let use_pregenerated = !target.is_git;
    let warnings_are_errors = target.is_git;

    let asm_dir = if use_pregenerated {
        &pregenerated
    } else {
        out_dir
    };

    let asm_srcs = if let Some(perlasm_format) = perlasm_format {
        let perlasm_src_dsts =
            perlasm_src_dsts(asm_dir, &target.arch, Some(&target.os), perlasm_format);

        if !use_pregenerated {
            perlasm(
                &perlasm_src_dsts[..],
                &target.arch,
                perlasm_format,
                Some(includes_modified),
            );
        }

        let mut asm_srcs = asm_srcs(perlasm_src_dsts);

        // For Windows we also pregenerate the object files for non-Git builds so
        // the user doesn't need to install the assembler. On other platforms we
        // assume the C compiler also assembles.
        if use_pregenerated && target.os == WINDOWS {
            // The pregenerated object files always use ".obj" as the extension,
            // even when the C/C++ compiler outputs files with the ".o" extension.
            asm_srcs = asm_srcs
                .iter()
                .map(|src| obj_path(&pregenerated, src.as_path(), "obj"))
                .collect::<Vec<_>>();
        }

        asm_srcs
    } else {
        Vec::new()
    };

    let core_srcs = sources_for_arch(&target.arch)
        .into_iter()
        .filter(|p| !is_perlasm(&p))
        .collect::<Vec<_>>();

    let test_srcs = RING_TEST_SRCS.iter().map(PathBuf::from).collect::<Vec<_>>();

    let libs = [
        ("ring-core", &core_srcs[..], &asm_srcs[..]),
        ("ring-test", &test_srcs[..], &[]),
    ];

    // XXX: Ideally, ring-test would only be built for `cargo test`, but Cargo
    // can't do that yet.
    libs.iter().for_each(|&(lib_name, srcs, additional_srcs)| {
        build_library(
            &target,
            &out_dir,
            lib_name,
            srcs,
            additional_srcs,
            warnings_are_errors,
            includes_modified,
        )
    });

    println!(
        "cargo:rustc-link-search=native={}",
        out_dir.to_str().expect("Invalid path")
    );
}

fn build_library(
    target: &Target,
    out_dir: &Path,
    lib_name: &str,
    srcs: &[PathBuf],
    additional_srcs: &[PathBuf],
    warnings_are_errors: bool,
    includes_modified: SystemTime,
) {
    // Compile all the (dirty) source files into object files.
    let objs = additional_srcs
        .iter()
        .chain(srcs.iter())
        .filter(|f| &target.env != "msvc" || f.extension().unwrap().to_str().unwrap() != "S")
        .map(|f| compile(f, target, warnings_are_errors, out_dir, includes_modified))
        .collect::<Vec<_>>();

    // Rebuild the library if necessary.
    let lib_path = PathBuf::from(out_dir).join(format!("lib{}.a", lib_name));

    if objs
        .iter()
        .map(Path::new)
        .any(|p| need_run(&p, &lib_path, includes_modified))
    {
        let mut c = cc::Build::new();

        for f in LD_FLAGS {
            let _ = c.flag(&f);
        }
        match target.os.as_str() {
            "macos" => {
                let _ = c.flag("-fPIC");
                let _ = c.flag("-Wl,-dead_strip");
            }
            _ => {
                let _ = c.flag("-Wl,--gc-sections");
            }
        }
        for o in objs {
            let _ = c.object(o);
        }

        // Handled below.
        let _ = c.cargo_metadata(false);

        c.compile(
            lib_path
                .file_name()
                .and_then(|f| f.to_str())
                .expect("No filename"),
        );
    }

    // Link the library. This works even when the library doesn't need to be
    // rebuilt.
    println!("cargo:rustc-link-lib=static={}", lib_name);
}

fn compile(
    p: &Path,
    target: &Target,
    warnings_are_errors: bool,
    out_dir: &Path,
    includes_modified: SystemTime,
) -> String {
    let ext = p.extension().unwrap().to_str().unwrap();
    if ext == "obj" {
        p.to_str().expect("Invalid path").into()
    } else {
        let mut out_path = out_dir.join(p.file_name().unwrap());
        assert!(out_path.set_extension(target.obj_ext));
        if need_run(&p, &out_path, includes_modified) {
            let cmd = if target.os != WINDOWS || ext != "asm" {
                cc(p, ext, target, warnings_are_errors, &out_path)
            } else {
                nasm(p, &target.arch, &out_path)
            };

            run_command(cmd);
        }
        out_path.to_str().expect("Invalid path").into()
    }
}

fn obj_path(out_dir: &Path, src: &Path, obj_ext: &str) -> PathBuf {
    let mut out_path = out_dir.join(src.file_name().unwrap());
    assert!(out_path.set_extension(obj_ext));
    out_path
}

fn cc(
    file: &Path,
    ext: &str,
    target: &Target,
    warnings_are_errors: bool,
    out_dir: &Path,
) -> Command {
    let is_musl = target.env.starts_with("musl");

    let mut c = cc::Build::new();
    let _ = c.include("include");
    match ext {
        "c" => {
            for f in c_flags(target) {
                let _ = c.flag(f);
            }
        }
        "S" => (),
        e => panic!("Unsupported file extension: {:?}", e),
    };
    for f in cpp_flags(target) {
        let _ = c.flag(&f);
    }
    if target.os != "none"
        && target.os != "redox"
        && target.os != "windows"
        && target.arch != "wasm32"
    {
        let _ = c.flag("-fstack-protector");
    }

    match (target.os.as_str(), target.env.as_str()) {
        // ``-gfull`` is required for Darwin's |-dead_strip|.
        ("macos", _) => {
            let _ = c.flag("-gfull");
        }
        (_, "msvc") => (),
        _ => {
            let _ = c.flag("-g3");
        }
    };
    if !target.is_debug {
        let _ = c.define("NDEBUG", None);
    }

    if &target.env == "msvc" {
        if std::env::var("OPT_LEVEL").unwrap() == "0" {
            let _ = c.flag("/Od"); // Disable optimization for debug builds.
                                   // run-time checking: (s)tack frame, (u)ninitialized variables
            let _ = c.flag("/RTCsu");
        } else {
            let _ = c.flag("/Ox"); // Enable full optimization.
        }
    }

    // Allow cross-compiling without a target sysroot for these targets.
    //
    // poly1305_vec.c requires <emmintrin.h> which requires <stdlib.h>.
    if (target.arch == "wasm32" && target.os == "unknown")
        || (target.os == "linux" && is_musl && target.arch != "x86_64")
    {
        if let Ok(compiler) = c.try_get_compiler() {
            // TODO: Expand this to non-clang compilers in 0.17.0 if practical.
            if compiler.is_like_clang() {
                let _ = c.flag("-nostdlibinc");
                let _ = c.define("GFp_NOSTDLIBINC", "1");
            }
        }
    }

    if warnings_are_errors {
        let flag = if &target.env != "msvc" {
            "-Werror"
        } else {
            "/WX"
        };
        let _ = c.flag(flag);
    }
    if is_musl {
        // Some platforms enable _FORTIFY_SOURCE by default, but musl
        // libc doesn't support it yet. See
        // http://wiki.musl-libc.org/wiki/Future_Ideas#Fortify
        // http://www.openwall.com/lists/musl/2015/02/04/3
        // http://www.openwall.com/lists/musl/2015/06/17/1
        let _ = c.flag("-U_FORTIFY_SOURCE");
    }

    let mut c = c.get_compiler().to_command();
    let _ = c
        .arg("-c")
        .arg(format!(
            "{}{}",
            target.obj_opt,
            out_dir.to_str().expect("Invalid path")
        ))
        .arg(file);
    c
}

fn nasm(file: &Path, arch: &str, out_file: &Path) -> Command {
    let oformat = match arch {
        "x86_64" => ("win64"),
        "x86" => ("win32"),
        _ => panic!("unsupported arch: {}", arch),
    };
    let mut c = Command::new("./target/tools/nasm");
    let _ = c
        .arg("-o")
        .arg(out_file.to_str().expect("Invalid path"))
        .arg("-f")
        .arg(oformat)
        .arg("-Xgnu")
        .arg("-gcv8")
        .arg(file);
    c
}

fn run_command_with_args<S>(command_name: S, args: &[String])
where
    S: AsRef<std::ffi::OsStr> + Copy,
{
    let mut cmd = Command::new(command_name);
    let _ = cmd.args(args);
    run_command(cmd)
}

fn run_command(mut cmd: Command) {
    eprintln!("running {:?}", cmd);
    let status = cmd.status().unwrap_or_else(|e| {
        panic!("failed to execute [{:?}]: {}", cmd, e);
    });
    if !status.success() {
        panic!("execution failed");
    }
}

fn sources_for_arch(arch: &str) -> Vec<PathBuf> {
    RING_SRCS
        .iter()
        .filter(|&&(archs, _)| archs.is_empty() || archs.contains(&arch))
        .map(|&(_, p)| PathBuf::from(p))
        .collect::<Vec<_>>()
}

fn perlasm_src_dsts(
    out_dir: &Path,
    arch: &str,
    os: Option<&str>,
    perlasm_format: &str,
) -> Vec<(PathBuf, PathBuf)> {
    let srcs = sources_for_arch(arch);
    let mut src_dsts = srcs
        .iter()
        .filter(|p| is_perlasm(p))
        .map(|src| (src.clone(), asm_path(out_dir, src, os, perlasm_format)))
        .collect::<Vec<_>>();

    // Some PerlAsm source files need to be run multiple times with different
    // output paths.
    {
        // Appease the borrow checker.
        let mut maybe_synthesize = |concrete, synthesized| {
            let concrete_path = PathBuf::from(concrete);
            if srcs.contains(&concrete_path) {
                let synthesized_path = PathBuf::from(synthesized);
                src_dsts.push((
                    concrete_path,
                    asm_path(out_dir, &synthesized_path, os, perlasm_format),
                ))
            }
        };
        maybe_synthesize(SHA512_X86_64, SHA256_X86_64);
        maybe_synthesize(SHA512_ARMV8, SHA256_ARMV8);
    }

    src_dsts
}

fn asm_srcs(perlasm_src_dsts: Vec<(PathBuf, PathBuf)>) -> Vec<PathBuf> {
    perlasm_src_dsts
        .into_iter()
        .map(|(_src, dst)| dst)
        .collect::<Vec<_>>()
}

fn is_perlasm(path: &PathBuf) -> bool {
    path.extension().unwrap().to_str().unwrap() == "pl"
}

fn asm_path(out_dir: &Path, src: &Path, os: Option<&str>, perlasm_format: &str) -> PathBuf {
    let src_stem = src.file_stem().expect("source file without basename");

    let dst_stem = src_stem.to_str().unwrap();
    let dst_extension = if os == Some("windows") { "asm" } else { "S" };
    let dst_filename = format!("{}-{}.{}", dst_stem, perlasm_format, dst_extension);
    out_dir.join(dst_filename)
}

fn perlasm(
    src_dst: &[(PathBuf, PathBuf)],
    arch: &str,
    perlasm_format: &str,
    includes_modified: Option<SystemTime>,
) {
    for (src, dst) in src_dst {
        if let Some(includes_modified) = includes_modified {
            if !need_run(src, dst, includes_modified) {
                continue;
            }
        }

        let mut args = Vec::<String>::new();
        args.push(src.to_string_lossy().into_owned());
        args.push(perlasm_format.to_owned());
        if arch == "x86" {
            args.push("-fPIC".into());
            args.push("-DOPENSSL_IA32_SSE2".into());
        }
        // Work around PerlAsm issue for ARM and AAarch64 targets by replacing
        // back slashes with forward slashes.
        let dst = dst
            .to_str()
            .expect("Could not convert path")
            .replace("\\", "/");
        args.push(dst);
        run_command_with_args(&get_command("PERL_EXECUTABLE", "perl"), &args);
    }
}

fn need_run(source: &Path, target: &Path, includes_modified: SystemTime) -> bool {
    let s_modified = file_modified(source);
    if let Ok(target_metadata) = std::fs::metadata(target) {
        let target_modified = target_metadata.modified().unwrap();
        s_modified >= target_modified || includes_modified >= target_modified
    } else {
        // On error fetching metadata for the target file, assume the target
        // doesn't exist.
        true
    }
}

fn file_modified(path: &Path) -> SystemTime {
    let path = Path::new(path);
    let path_as_str = format!("{:?}", path);
    std::fs::metadata(path)
        .expect(&path_as_str)
        .modified()
        .expect("nah")
}

fn get_command(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.into())
}

fn check_all_files_tracked() {
    for path in &["crypto", "include", "third_party/fiat"] {
        walk_dir(&PathBuf::from(path), &is_tracked);
    }
}

fn is_tracked(file: &DirEntry) {
    let p = file.path();
    let cmp = |f| p == PathBuf::from(f);
    let tracked = match p.extension().and_then(|p| p.to_str()) {
        Some("h") | Some("inl") => RING_INCLUDES.iter().any(cmp),
        Some("c") | Some("S") | Some("asm") => {
            RING_SRCS.iter().any(|(_, f)| cmp(f)) || RING_TEST_SRCS.iter().any(cmp)
        }
        Some("pl") => RING_SRCS.iter().any(|(_, f)| cmp(f)) || RING_PERL_INCLUDES.iter().any(cmp),
        _ => true,
    };
    if !tracked {
        panic!("{:?} is not tracked in build.rs", p);
    }
}

fn walk_dir<F>(dir: &Path, cb: &F)
where
    F: Fn(&DirEntry),
{
    if dir.is_dir() {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_dir() {
                walk_dir(&path, cb);
            } else {
                cb(&entry);
            }
        }
    }
}
========== build.rs from nom-6.1.0 ============================================================
extern crate version_check;

fn main() {
  if version_check::is_min_version("1.44.0").unwrap_or(true) {
    println!("cargo:rustc-cfg=stable_i128");
  }
}
========== build.rs from sdl2-sys-0.34.3 ============================================================
#![allow(unused_imports, dead_code, unused_variables)]

#[cfg(feature = "pkg-config")]
extern crate pkg_config;
#[cfg(feature = "bindgen")]
extern crate bindgen;
#[cfg(feature="bundled")]
extern crate cmake;
#[cfg(feature="bundled")]
extern crate tar;
#[cfg(feature="bundled")]
extern crate flate2;
#[cfg(feature="bundled")]
extern crate unidiff;

#[macro_use]
extern crate cfg_if;

use std::path::{Path, PathBuf};
use std::{io, fs, env};

// corresponds to the headers that we have in sdl2-sys/SDL2-{version}
const SDL2_HEADERS_BUNDLED_VERSION: &str = "2.0.12";

// means the lastest stable version that can be downloaded from SDL2's source
const LASTEST_SDL2_VERSION: &str = "2.0.12";

#[cfg(feature = "bindgen")]
macro_rules! add_msvc_includes_to_bindings {
    ($bindings:expr) => {
        $bindings = $bindings.clang_arg(format!("-IC:/Program Files (x86)/Windows Kits/8.1/Include/shared"));
        $bindings = $bindings.clang_arg(format!("-IC:/Program Files/LLVM/lib/clang/5.0.0/include"));
        $bindings = $bindings.clang_arg(format!("-IC:/Program Files (x86)/Windows Kits/10/Include/10.0.10240.0/ucrt"));
        $bindings = $bindings.clang_arg(format!("-IC:/Program Files (x86)/Microsoft Visual Studio 14.0/VC/include"));
        $bindings = $bindings.clang_arg(format!("-IC:/Program Files (x86)/Windows Kits/8.1/Include/um"));
    };
}

fn get_bundled_header_path() -> PathBuf {
    let mut include_path: PathBuf = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    include_path.push(format!("SDL2-{}", SDL2_HEADERS_BUNDLED_VERSION));
    include_path.push("include");
    include_path
}

#[cfg(feature = "bundled")]
fn run_command(cmd: &str, args: &[&str]) {
    use std::process::Command;
    match Command::new(cmd).args(args).output() {
        Ok(output) => {
            if !output.status.success() {
                let error = std::str::from_utf8(&output.stderr).unwrap();
                panic!("Command '{}' failed: {}", cmd, error);
            }
        }
        Err(error) => {
            panic!("Error running command '{}': {:#}", cmd, error);
        }
    }
}

#[cfg(feature = "bundled")]
fn download_to(url: &str, dest: &str) {
    if cfg!(windows) {
        run_command("powershell", &[
            "-NoProfile", "-NonInteractive",
            "-Command", &format!("& {{
                $client = New-Object System.Net.WebClient
                $client.DownloadFile(\"{0}\", \"{1}\")
                if (!$?) {{ Exit 1 }}
            }}", url, dest).as_str()
        ]);
    } else {
        run_command("curl", &[url, "-o", dest]);
    }
}

#[cfg(feature = "use-pkgconfig")]
fn pkg_config_print(statik: bool, lib_name: &str) {
    pkg_config::Config::new()
        .statik(statik)
        .probe(lib_name).unwrap();
}

#[cfg(feature = "use-pkgconfig")]
fn get_pkg_config() {
    let statik: bool = if cfg!(feature = "static-link") { true } else { false };

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

// returns the location of the downloaded source
#[cfg(feature = "bundled")]
fn download_sdl2() -> PathBuf {
    let out_dir = env::var("OUT_DIR").unwrap();
    
    let sdl2_archive_name = format!("SDL2-{}.tar.gz", LASTEST_SDL2_VERSION);
    let sdl2_archive_url = format!("https://libsdl.org/release/{}", sdl2_archive_name);

    let sdl2_archive_path = Path::new(&out_dir).join(sdl2_archive_name);
    let sdl2_build_path = Path::new(&out_dir).join(format!("SDL2-{}", LASTEST_SDL2_VERSION));

    // avoid re-downloading the archive if it already exists    
    if !sdl2_archive_path.exists() {
        download_to(&sdl2_archive_url, sdl2_archive_path.to_str().unwrap());
    }

    let reader = flate2::read::GzDecoder::new(
        fs::File::open(&sdl2_archive_path).unwrap()
    );
    let mut ar = tar::Archive::new(reader);
    ar.unpack(&out_dir).unwrap();

    sdl2_build_path
}

// apply patches to sdl2 source
#[cfg(feature = "bundled")]
fn patch_sdl2(sdl2_source_path: &Path) {
    // vector of <(patch_file_name, patch_file_contents)>
    let patches: Vec<(&str, &'static str)> = vec![
        // Required patches can be added here like this:
        // ("SDL-2.x.y-filename.patch", include_str!("patches/SDL-2.x.y-filename.patch")),

        // https://bugzilla.libsdl.org/show_bug.cgi?id=5105
        // Expected to be fixed in 2.0.14
        ("SDL2-2.0.12-sndio-shared-linux.patch", include_str!("patches/SDL2-2.0.12-sndio-shared-linux.patch")),
    ];
    let sdl_version = format!("SDL2-{}", LASTEST_SDL2_VERSION);

    for patch in &patches {
        // Only apply patches whose file name is prefixed with the currently
        // targeted version of SDL2.
        if !patch.0.starts_with(&sdl_version) {
            continue;
        }
        let mut patch_set = unidiff::PatchSet::new();
        patch_set.parse(patch.1).expect("Error parsing diff");

        // For every modified file, copy the existing file to <file_name>_old,
        // open a new copy of <file_name>. and fill the new file with a
        // combination of the unmodified contents, and the patched sections.
        // TOOD: This code is untested (save for the immediate application), and
        // probably belongs in the unidiff (or similar) package.
        for modified_file in patch_set.modified_files() {
            use std::io::{Write, BufRead};

            let file_path = sdl2_source_path.join(modified_file.path());
            let old_path = sdl2_source_path.join(format!("{}_old", modified_file.path()));
            fs::rename(&file_path, &old_path)
                .expect(&format!(
                    "Rename of {} to {} failed",
                    file_path.to_string_lossy(),
                    old_path.to_string_lossy()));

            let     dst_file = fs::File::create(file_path).unwrap();
            let mut dst_buf  = io::BufWriter::new(dst_file);
            let     old_file = fs::File::open(old_path).unwrap();
            let mut old_buf  = io::BufReader::new(old_file);
            let mut cursor = 0;

            for (i, hunk) in modified_file.into_iter().enumerate() {
                // Write old lines from cursor to the start of this hunk.
                let num_lines = hunk.source_start - cursor - 1;
                for _ in 0..num_lines {
                    let mut line = String::new();
                    old_buf.read_line(&mut line).unwrap();
                    dst_buf.write_all(line.as_bytes()).unwrap();
                }
                cursor += num_lines;

                // Skip lines in old_file, and verify that what we expect to
                // replace is present in the old_file.
                for expected_line in hunk.source_lines() {
                    let mut actual_line = String::new();
                    old_buf.read_line(&mut actual_line).unwrap();
                    actual_line.pop(); // Remove the trailing newline.
                    if expected_line.value.trim_end() != actual_line {
                        panic!("Can't apply patch; mismatch between expected and actual in hunk {}", i);
                    }
                }
                cursor += hunk.source_length;

                // Write the new lines into the destination.
                for line in hunk.target_lines() {
                    dst_buf.write_all(line.value.as_bytes()).unwrap();
                    dst_buf.write_all(b"\n").unwrap();
                }
            }

            // Write all remaining lines from the old file into the new.
            for line in old_buf.lines() {
                dst_buf.write_all(&line.unwrap().into_bytes()).unwrap();
                dst_buf.write_all(b"\n").unwrap();
            }
        }
        // For every removed file, simply delete the original.
        // TODO: This is entirely untested code. There are likely bugs here, and
        // this really should be part of the unidiff library, not a function
        // defined here. Hopefully this gets moved somewhere else before it
        // bites someone.
        for removed_file in patch_set.removed_files() {
            fs::remove_file(sdl2_source_path.join(removed_file.path()))
                .expect(
                    &format!("Failed to remove file {} from {}",
                        removed_file.path(),
                        sdl2_source_path.to_string_lossy()));
        }
        // For every new file, copy the entire contents of the patched file into
        // a newly created <file_name>.
        // TODO: This is entirely untested code. There are likely bugs here, and
        // this really should be part of the unidiff library, not a function
        // defined here. Hopefully this gets moved somewhere else before it
        // bites someone.
        for added_file in patch_set.added_files() {
            use std::io::Write;

            // This should be superfluous. I don't know how a new file would
            // ever have more than one hunk.
            assert!(added_file.len() == 1);
            let file_path = sdl2_source_path.join(added_file.path());
            let dst_file = fs::File::create(&file_path)
                .expect(&format!(
                    "Failed to create file {}",
                    file_path.to_string_lossy()));
            let mut dst_buf = io::BufWriter::new(&dst_file);

            for line in added_file.into_iter().nth(0).unwrap().target_lines() {
                dst_buf.write_all(line.value.as_bytes()).unwrap();
                dst_buf.write_all(b"\n").unwrap();
            }
        }
    }
}

// compile a shared or static lib depending on the feature 
#[cfg(feature = "bundled")]
fn compile_sdl2(sdl2_build_path: &Path, target_os: &str) -> PathBuf {
    let mut cfg = cmake::Config::new(sdl2_build_path);
    cfg.profile("release");

    #[cfg(target_os = "linux")]
    {
        use version_compare::Version;
        if let Ok(version) = std::process::Command::new("cc").arg("-dumpversion").output() {
            let local_ver = Version::from(std::str::from_utf8(&version.stdout).unwrap()).unwrap();
            let affected_ver = Version::from("10").unwrap();

            if local_ver >= affected_ver {
                cfg.cflag("-fcommon");
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
fn compute_include_paths() -> Vec<String> {
    let mut include_paths: Vec<String> = vec!();
    
    if let Ok(include_path) = env::var("SDL2_INCLUDE_PATH") {
        include_paths.push(format!("{}", include_path));
    };

    #[cfg(feature = "pkg-config")] {
        // don't print the "cargo:xxx" directives, we're just trying to get the include paths here
        let pkg_config_library = pkg_config::Config::new().print_system_libs(false).probe("sdl2").unwrap();
        for path in pkg_config_library.include_paths {
            include_paths.push(format!("{}", path.display()));
        };
    }

    #[cfg(feature = "vcpkg")] {
        // don't print the "cargo:xxx" directives, we're just trying to get the include paths here
        let vcpkg_library = vcpkg::Config::new().cargo_metadata(false).probe("sdl2").unwrap();
        for path in vcpkg_library.include_paths {
            include_paths.push(format!("{}", path.display()));
        };
    }


    include_paths
}

fn link_sdl2(target_os: &str) {
    #[cfg(all(feature = "use-pkgconfig", not(feature = "bundled")))] {
        // prints the appropriate linking parameters when using pkg-config
        // useless when using "bundled"
        get_pkg_config();
    }    
    
    #[cfg(all(feature = "use-vcpkg", not(feature = "bundled")))] {
        // prints the appropriate linking parameters when using pkg-config
        // useless when using "bundled"
        get_vcpkg_config();
    }

    #[cfg(not(feature = "static-link"))] {
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

    #[cfg(feature = "static-link")] {
        if cfg!(feature = "bundled") || (cfg!(feature = "use-pkgconfig") == false && cfg!(feature = "use-vcpkg") == false) { 
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
            println!("cargo:rustc-link-lib=framework=CoreVideo");
            println!("cargo:rustc-link-lib=framework=CoreAudio");
            println!("cargo:rustc-link-lib=framework=AudioToolbox");
            println!("cargo:rustc-link-lib=iconv");
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
    #[cfg(all(not(feature = "use-pkgconfig"), not(feature = "static-link")))] {
        if cfg!(feature = "mixer") {
            if target_os.contains("linux") || target_os.contains("freebsd") || target_os.contains("openbsd") {
                println!("cargo:rustc-flags=-l SDL2_mixer");
            } else if target_os.contains("windows") {
                println!("cargo:rustc-flags=-l SDL2_mixer");
            } else if target_os.contains("darwin") {
                if cfg!(any(mac_framework, feature="use_mac_framework")) {
                    println!("cargo:rustc-flags=-l framework=SDL2_mixer");
                } else {
                    println!("cargo:rustc-flags=-l SDL2_mixer");
                }
            }
        }
        if cfg!(feature = "image") {
            if target_os.contains("linux") || target_os.contains("freebsd") || target_os.contains("openbsd") {
                println!("cargo:rustc-flags=-l SDL2_image");
            } else if target_os.contains("windows") {
                println!("cargo:rustc-flags=-l SDL2_image");
            } else if target_os.contains("darwin") {
                if cfg!(any(mac_framework, feature="use_mac_framework")) {
                    println!("cargo:rustc-flags=-l framework=SDL2_image");
                } else {
                    println!("cargo:rustc-flags=-l SDL2_image");
                }
            }
        }
        if cfg!(feature = "ttf") {
            if target_os.contains("linux") || target_os.contains("freebsd") || target_os.contains("openbsd") {
                println!("cargo:rustc-flags=-l SDL2_ttf");
            } else if target_os.contains("windows") {
                println!("cargo:rustc-flags=-l SDL2_ttf");
            } else if target_os.contains("darwin") {
                if cfg!(any(mac_framework, feature="use_mac_framework")) {
                    println!("cargo:rustc-flags=-l framework=SDL2_ttf");
                } else {
                    println!("cargo:rustc-flags=-l SDL2_ttf");
                }
            }
        }
        if cfg!(feature = "gfx") {
            if target_os.contains("linux") || target_os.contains("freebsd") || target_os.contains("openbsd") {
                println!("cargo:rustc-flags=-l SDL2_gfx");
            } else if target_os.contains("windows") {
                println!("cargo:rustc-flags=-l SDL2_gfx");
            } else if target_os.contains("darwin") {
                if cfg!(any(mac_framework, feature="use_mac_framework")) {
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

fn copy_dynamic_libraries(sdl2_compiled_path: &PathBuf, target_os: &str) {
    // Windows binaries do not embed library search paths, so successfully
    // linking the DLL isn't sufficient to find it at runtime -- it must be
    // either on PATH or in the current working directory when we run binaries
    // linked against it. In other words, to run the test suite we need to
    // copy sdl2.dll out of its build tree and down to the top level cargo
    // binary output directory.
    if target_os.contains("windows") {
        let sdl2_dll_name = "SDL2.dll";
        let sdl2_bin_path = sdl2_compiled_path.join("bin");
        let target_path = find_cargo_target_dir();

        let src_dll_path = sdl2_bin_path.join(sdl2_dll_name);
        let dst_dll_path = target_path.join(sdl2_dll_name);

        fs::copy(&src_dll_path, &dst_dll_path)
            .expect(&format!("Failed to copy SDL2 dynamic library from {} to {}",
                             src_dll_path.to_string_lossy(),
                             dst_dll_path.to_string_lossy()));
    }
}

fn main() {
    let target = env::var("TARGET").expect("Cargo build scripts always have TARGET");
    let host = env::var("HOST").expect("Cargo build scripts always have HOST");
    let target_os = get_os_from_triple(target.as_str()).unwrap();

    let sdl2_compiled_path: PathBuf;
    #[cfg(feature = "bundled")] {
        let sdl2_source_path = download_sdl2();
        patch_sdl2(sdl2_source_path.as_path());
        sdl2_compiled_path = compile_sdl2(sdl2_source_path.as_path(), target_os);

        let sdl2_downloaded_include_path = sdl2_source_path.join("include");
        let sdl2_compiled_lib_path = sdl2_compiled_path.join("lib");

        println!("cargo:rustc-link-search={}", sdl2_compiled_lib_path.display());
        
        #[cfg(feature = "bindgen")] {
            let include_paths = vec!(String::from(sdl2_downloaded_include_path.to_str().unwrap()));
            println!("cargo:include={}", include_paths.join(":"));
            generate_bindings(target.as_str(), host.as_str(), include_paths.as_slice())
        }
        #[cfg(not(feature = "bindgen"))] {
            println!("cargo:include={}", sdl2_downloaded_include_path.display());
        }
    };

    #[cfg(all(not(feature = "bundled"), feature = "bindgen"))] {
        let include_paths: Vec<String> = compute_include_paths();
        generate_bindings(target.as_str(), host.as_str(), include_paths.as_slice())
    }

    #[cfg(not(feature = "bindgen"))] {
        copy_pregenerated_bindings();
        println!("cargo:include={}", get_bundled_header_path().display());
    }

    link_sdl2(target_os);

    #[cfg(all(feature = "bundled", not(feature = "static-link")))] {
        copy_dynamic_libraries(&sdl2_compiled_path, target_os);
    }
}

#[cfg(not(feature = "bindgen"))]
fn copy_pregenerated_bindings() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let crate_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    fs::copy(crate_path.join("sdl_bindings.rs"), out_path.join("sdl_bindings.rs"))
        .expect("Couldn't find pregenerated bindings!");

    if cfg!(feature = "image") {
        fs::copy(crate_path.join("sdl_image_bindings.rs"), out_path.join("sdl_image_bindings.rs"))
            .expect("Couldn't find pregenerated SDL_image bindings!");
    }
    if cfg!(feature = "ttf") {
        fs::copy(crate_path.join("sdl_ttf_bindings.rs"), out_path.join("sdl_ttf_bindings.rs"))
            .expect("Couldn't find pregenerated SDL_ttf bindings!");
    }
    if cfg!(feature = "mixer") {
        fs::copy(crate_path.join("sdl_mixer_bindings.rs"), out_path.join("sdl_mixer_bindings.rs"))
            .expect("Couldn't find pregenerated SDL_mixer bindings!");
    }

    if cfg!(feature = "gfx") {
        fs::copy(crate_path.join("sdl_gfx_framerate_bindings.rs"), out_path.join("sdl_gfx_framerate_bindings.rs"))
            .expect("Couldn't find pregenerated SDL_gfx framerate bindings!");

        fs::copy(crate_path.join("sdl_gfx_primitives_bindings.rs"), out_path.join("sdl_gfx_primitives_bindings.rs"))
            .expect("Couldn't find pregenerated SDL_gfx primitives bindings!");

        fs::copy(crate_path.join("sdl_gfx_imagefilter_bindings.rs"), out_path.join("sdl_gfx_imagefilter_bindings.rs"))
            .expect("Couldn't find pregenerated SDL_gfx imagefilter bindings!");

        fs::copy(crate_path.join("sdl_gfx_rotozoom_bindings.rs"), out_path.join("sdl_gfx_rotozoom_bindings.rs"))
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
        .default_enum_style(bindgen::EnumVariation::Rust { non_exhaustive: false })
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

    let mut gfx_framerate_bindings = bindgen::Builder::default()
        .use_core()
        .ctypes_prefix("libc");
    let mut gfx_primitives_bindings = bindgen::Builder::default()
        .use_core()
        .raw_line("use crate::*;")
        .ctypes_prefix("libc");
    let mut gfx_imagefilter_bindings = bindgen::Builder::default()
        .use_core()
        .ctypes_prefix("libc");
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

    if headers_paths.len() == 0 {
        // if no paths are being provided, fall back to the headers included in this repo
        let include_path = get_bundled_header_path();
        println!("cargo:include={}", include_path.display());

        bindings = bindings.clang_arg(format!("-I{}", include_path.display()));
        if cfg!(feature = "image") {
            image_bindings = image_bindings.clang_arg(format!("-I{}", include_path.display()));
        }
        if cfg!(feature = "ttf") {
            ttf_bindings = ttf_bindings.clang_arg(format!("-I{}", include_path.display()));
        }
        if cfg!(feature = "mixer") {
            mixer_bindings = mixer_bindings.clang_arg(format!("-I{}", include_path.display()));
        }
        if cfg!(feature = "gfx") {
            gfx_framerate_bindings = gfx_framerate_bindings.clang_arg(format!("-I{}", include_path.display()));
            gfx_primitives_bindings = gfx_primitives_bindings.clang_arg(format!("-I{}", include_path.display()));
            gfx_imagefilter_bindings = gfx_imagefilter_bindings.clang_arg(format!("-I{}", include_path.display()));
            gfx_rotozoom_bindings = gfx_rotozoom_bindings.clang_arg(format!("-I{}", include_path.display()));
        }
    } else {
        // if paths are included, use them for bindgen. Bindgen should use the first one.
        println!("cargo:include={}", headers_paths.join(":"));
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
                gfx_framerate_bindings = gfx_framerate_bindings.clang_arg(format!("-I{}", headers_path));
                gfx_primitives_bindings = gfx_primitives_bindings.clang_arg(format!("-I{}", headers_path));
                gfx_imagefilter_bindings = gfx_imagefilter_bindings.clang_arg(format!("-I{}", headers_path));
                gfx_rotozoom_bindings = gfx_rotozoom_bindings.clang_arg(format!("-I{}", headers_path));
            }
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
            gfx_primitives_bindings = gfx_primitives_bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
            gfx_imagefilter_bindings = gfx_imagefilter_bindings.clang_arg("-DSDL_VIDEO_DRIVER_X11");
            gfx_imagefilter_bindings = gfx_imagefilter_bindings.clang_arg("-DSDL_VIDEO_DRIVER_WAYLAND");
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

fn get_os_from_triple(triple: &str) -> Option<&str>
{
    triple.splitn(3, "-").nth(2)
}
========== build.rs from cast-0.2.7 ============================================================
extern crate rustc_version;

fn main() {
    let vers = rustc_version::version().unwrap();
    if vers.major == 1 && vers.minor >= 26 {
        println!("cargo:rustc-cfg=stable_i128")
    }
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
========== build.rs from libm-0.2.1 ============================================================
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
========== build.rs from rayon-core-1.9.1 ============================================================
// We need a build script to use `link = "rayon-core"`.  But we're not
// *actually* linking to anything, just making sure that we're the only
// rayon-core in use.
fn main() {
    // we don't need to rebuild for anything else
    println!("cargo:rerun-if-changed=build.rs");
}
========== build.rs from rustls-0.20.4 ============================================================
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
========== build.rs from log-0.4.14 ============================================================
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
        "msp430-none-elf" | "riscv32i-unknown-none-elf" | "riscv32imc-unknown-none-elf" => false,
        _ => true,
    }
}

fn rustc_target() -> Option<String> {
    env::var("TARGET").ok()
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
========== build.rs from serde_json-1.0.66 ============================================================
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
========== build.rs from bare-metal-0.2.4 ============================================================
extern crate rustc_version;

fn main() {
    let vers = rustc_version::version().unwrap();

    if vers.major == 1 && vers.minor < 31 {
        println!("cargo:rustc-cfg=unstable_const_fn")
    }
}
========== build.rs from libc-0.2.113 ============================================================
use std::env;
use std::process::Command;
use std::str;

fn main() {
    // Avoid unnecessary re-building.
    println!("cargo:rerun-if-changed=build.rs");

    let (rustc_minor_ver, is_nightly) = rustc_minor_nightly().expect("Failed to get rustc version");
    let rustc_dep_of_std = env::var("CARGO_FEATURE_RUSTC_DEP_OF_STD").is_ok();
    let align_cargo_feature = env::var("CARGO_FEATURE_ALIGN").is_ok();
    let const_extern_fn_cargo_feature = env::var("CARGO_FEATURE_CONST_EXTERN_FN").is_ok();
    let libc_ci = env::var("LIBC_CI").is_ok();

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
        Some(10) if libc_ci || rustc_dep_of_std => {
            println!("cargo:rustc-cfg=freebsd10")
        }
        Some(11) if libc_ci => println!("cargo:rustc-cfg=freebsd11"),
        Some(12) if libc_ci => println!("cargo:rustc-cfg=freebsd12"),
        Some(13) if libc_ci => println!("cargo:rustc-cfg=freebsd13"),
        Some(14) if libc_ci => println!("cargo:rustc-cfg=freebsd14"),
        Some(_) | None => println!("cargo:rustc-cfg=freebsd11"),
    }

    // On CI: deny all warnings
    if libc_ci {
        println!("cargo:rustc-cfg=libc_deny_warnings");
    }

    // Rust >= 1.15 supports private module use:
    if rustc_minor_ver >= 15 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_priv_mod_use");
    }

    // Rust >= 1.19 supports unions:
    if rustc_minor_ver >= 19 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_union");
    }

    // Rust >= 1.24 supports const mem::size_of:
    if rustc_minor_ver >= 24 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_const_size_of");
    }

    // Rust >= 1.25 supports repr(align):
    if rustc_minor_ver >= 25 || rustc_dep_of_std || align_cargo_feature {
        println!("cargo:rustc-cfg=libc_align");
    }

    // Rust >= 1.30 supports `core::ffi::c_void`, so libc can just re-export it.
    // Otherwise, it defines an incompatible type to retaining
    // backwards-compatibility.
    if rustc_minor_ver >= 30 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_core_cvoid");
    }

    // Rust >= 1.33 supports repr(packed(N)) and cfg(target_vendor).
    if rustc_minor_ver >= 33 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_packedN");
        println!("cargo:rustc-cfg=libc_cfg_target_vendor");
    }

    // Rust >= 1.40 supports #[non_exhaustive].
    if rustc_minor_ver >= 40 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_non_exhaustive");
    }

    if rustc_minor_ver >= 51 || rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_ptr_addr_of");
    }

    // #[thread_local] is currently unstable
    if rustc_dep_of_std {
        println!("cargo:rustc-cfg=libc_thread_local");
    }

    if const_extern_fn_cargo_feature {
        if !is_nightly || rustc_minor_ver < 40 {
            panic!("const-extern-fn requires a nightly compiler >= 1.40")
        }
        println!("cargo:rustc-cfg=libc_const_extern_fn");
    }
}

fn rustc_minor_nightly() -> Option<(u32, bool)> {
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

    Some((minor, nightly))
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
========== build.rs from minifb-0.22.0 ============================================================
use std::env;
extern crate cc;

fn main() {
    if cfg!(not(any(
        target_os = "macos",
        target_os = "windows",
        target_os = "redox"
    ))) && cfg!(not(any(feature = "wayland", feature = "x11")))
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
    } else if !env.contains("windows") {
        // build scalar on non-windows and non-mac
        cc::Build::new()
            .file("src/native/posix/scalar.cpp")
            .opt_level(3) // always build with opts for scaler so it's fast in debug also
            .compile("libscalar.a")
    }
}
========== build.rs from serde-1.0.130 ============================================================
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
    if minor >= 26 {
        println!("cargo:rustc-cfg=ops_bound");
    } else if minor >= 17 && cfg!(feature = "std") {
        println!("cargo:rustc-cfg=collections_bound");
    }

    // core::cmp::Reverse stabilized in Rust 1.19:
    // https://doc.rust-lang.org/stable/core/cmp/struct.Reverse.html
    if minor >= 19 {
        println!("cargo:rustc-cfg=core_reverse");
    }

    // CString::into_boxed_c_str and PathBuf::into_boxed_path stabilized in Rust 1.20:
    // https://doc.rust-lang.org/std/ffi/struct.CString.html#method.into_boxed_c_str
    // https://doc.rust-lang.org/std/path/struct.PathBuf.html#method.into_boxed_path
    if minor >= 20 {
        println!("cargo:rustc-cfg=de_boxed_c_str");
        println!("cargo:rustc-cfg=de_boxed_path");
    }

    // From<Box<T>> for Rc<T> / Arc<T> stabilized in Rust 1.21:
    // https://doc.rust-lang.org/std/rc/struct.Rc.html#impl-From<Box<T>>
    // https://doc.rust-lang.org/std/sync/struct.Arc.html#impl-From<Box<T>>
    if minor >= 21 {
        println!("cargo:rustc-cfg=de_rc_dst");
    }

    // Duration available in core since Rust 1.25:
    // https://blog.rust-lang.org/2018/03/29/Rust-1.25.html#library-stabilizations
    if minor >= 25 {
        println!("cargo:rustc-cfg=core_duration");
    }

    // 128-bit integers stabilized in Rust 1.26:
    // https://blog.rust-lang.org/2018/05/10/Rust-1.26.html
    //
    // Disabled on Emscripten targets before Rust 1.40 since
    // Emscripten did not support 128-bit integers until Rust 1.40
    // (https://github.com/rust-lang/rust/pull/65251)
    if minor >= 26 && (!emscripten || minor >= 40) {
        println!("cargo:rustc-cfg=integer128");
    }

    // Inclusive ranges methods stabilized in Rust 1.27:
    // https://github.com/rust-lang/rust/pull/50758
    // Also Iterator::try_for_each:
    // https://blog.rust-lang.org/2018/06/21/Rust-1.27.html#library-stabilizations
    if minor >= 27 {
        println!("cargo:rustc-cfg=range_inclusive");
        println!("cargo:rustc-cfg=iterator_try_fold");
    }

    // Non-zero integers stabilized in Rust 1.28:
    // https://blog.rust-lang.org/2018/08/02/Rust-1.28.html#library-stabilizations
    if minor >= 28 {
        println!("cargo:rustc-cfg=num_nonzero");
    }

    // Current minimum supported version of serde_derive crate is Rust 1.31.
    if minor >= 31 {
        println!("cargo:rustc-cfg=serde_derive");
    }

    // TryFrom, Atomic types, non-zero signed integers, and SystemTime::checked_add
    // stabilized in Rust 1.34:
    // https://blog.rust-lang.org/2019/04/11/Rust-1.34.0.html#tryfrom-and-tryinto
    // https://blog.rust-lang.org/2019/04/11/Rust-1.34.0.html#library-stabilizations
    if minor >= 34 {
        println!("cargo:rustc-cfg=core_try_from");
        println!("cargo:rustc-cfg=num_nonzero_signed");
        println!("cargo:rustc-cfg=systemtime_checked_add");

        // Whitelist of archs that support std::sync::atomic module. Ideally we
        // would use #[cfg(target_has_atomic = "...")] but it is not stable yet.
        // Instead this is based on rustc's src/librustc_target/spec/*.rs.
        let has_atomic64 = target.starts_with("x86_64")
            || target.starts_with("i686")
            || target.starts_with("aarch64")
            || target.starts_with("powerpc64")
            || target.starts_with("sparc64")
            || target.starts_with("mips64el");
        let has_atomic32 = has_atomic64 || emscripten;
        if has_atomic64 {
            println!("cargo:rustc-cfg=std_atomic64");
        }
        if has_atomic32 {
            println!("cargo:rustc-cfg=std_atomic");
        }
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
========== build.rs from xkbcommon-sys-0.7.5 ============================================================
use std::env;

extern crate pkg_config;
use pkg_config::{Config, Error};

fn is_static() -> bool {
	env::var("CARGO_FEATURE_STATIC").is_ok()
}

fn common() -> Result<(), Error> {
	if let Ok(path) = env::var("XKBCOMMON_LIB_DIR") {
		for lib in &["xkbcommon"] {
			println!("cargo:rustc-link-lib={}={}", if is_static() { "static" } else { "dylib" }, lib);
		}

		println!("cargo:rustc-link-search=native={}", path);
	}
	else {
		Config::new().statik(is_static()).probe("xkbcommon")?;
	}

	Ok(())
}

fn x11() -> Result<(), Error> {
	if env::var("CARGO_FEATURE_X11").is_ok() {
		if let Ok(path) = env::var("XKBCOMMON_LIB_DIR") {
			for lib in &["xkbcommon-x11"] {
				println!("cargo:rustc-link-lib={}={}", if is_static() { "static" } else { "dylib" }, lib);
			}

			println!("cargo:rustc-link-search=native={}", path);
		}
		else {
			Config::new().statik(is_static()).probe("xkbcommon-x11")?;
		}
	}

	Ok(())
}

fn main() {
	common().unwrap();
	x11().unwrap();
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
========== build.rs from miniz_oxide-0.4.3 ============================================================
#![forbid(unsafe_code)]
use autocfg;

fn main() {
    autocfg::new().emit_sysroot_crate("alloc");
}
========== build.rs from encoding_rs-0.8.28 ============================================================
fn main() {
    // This does not enable `RUSTC_BOOTSTRAP=1` for `packed_simd`.
    // You still need to knowingly have a setup that makes
    // `packed_simd` compile. Therefore, having this file on
    // crates.io is harmless in terms of users of `encoding_rs`
    // accidentally depending on nightly features. Having this
    // here means that if you knowingly want this, you only
    // need to maintain a fork of `packed_simd` without _also_
    // having to maintain a fork of `encoding_rs`.
    #[cfg(feature = "simd-accel")]
    println!("cargo:rustc-env=RUSTC_BOOTSTRAP=1");
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
========== build.rs from generic-array-0.14.4 ============================================================
fn main() {
    if version_check::is_min_version("1.41.0").unwrap_or(false) {
        println!("cargo:rustc-cfg=relaxed_coherence");
    }
}
========== build.rs from crc32fast-1.2.1 ============================================================
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
========== build.rs from compiler_builtins-0.1.39 ============================================================
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

    // Forcibly enable memory intrinsics on wasm32 & SGX as we don't have a libc to
    // provide them.
    if (target.contains("wasm32") && !target.contains("wasi"))
        || (target.contains("sgx") && target.contains("fortanix"))
        || target.contains("-none")
        || target.contains("nvptx")
    {
        println!("cargo:rustc-cfg=feature=\"mem\"");
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
        // * wasm32 - clang 8 for wasm is somewhat hard to come by and it's
        //   unlikely that the C is really that much better than our own Rust.
        // * nvptx - everything is bitcode, not compatible with mixed C/Rust
        // * riscv - the rust-lang/rust distribution container doesn't have a C
        //   compiler nor is cc-rs ready for compilation to riscv (at this
        //   time). This can probably be removed in the future
        if !target.contains("wasm32") && !target.contains("nvptx") && !target.starts_with("riscv") {
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

    // Only emit the ARM Linux atomic emulation on pre-ARMv6 architectures.
    if llvm_target[0] == "armv4t" || llvm_target[0] == "armv5te" {
        println!("cargo:rustc-cfg=kernel_user_helpers")
    }
}

#[cfg(feature = "c")]
mod c {
    extern crate cc;

    use std::collections::BTreeMap;
    use std::env;
    use std::path::PathBuf;

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
            ("apple_versioning", "apple_versioning.c"),
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
                ("__truncdfsf2", "truncdfsf2.c"),
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
        if target_os != "ios" && (target_vendor != "apple" || target_arch != "x86") {
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
                sources.extend(&[
                    ("__floatdisf", "x86_64/floatdisf.c"),
                    ("__floatdixf", "x86_64/floatdixf.c"),
                ]);
            }
        } else {
            // None of these seem to be used on x86_64 windows, and they've all
            // got the wrong ABI anyway, so we want to avoid them.
            if target_os != "windows" {
                if target_arch == "x86_64" {
                    sources.extend(&[
                        ("__floatdisf", "x86_64/floatdisf.c"),
                        ("__floatdixf", "x86_64/floatdixf.c"),
                        ("__floatundidf", "x86_64/floatundidf.S"),
                        ("__floatundisf", "x86_64/floatundisf.S"),
                        ("__floatundixf", "x86_64/floatundixf.S"),
                    ]);
                }
            }

            if target_arch == "x86" {
                sources.extend(&[
                    ("__ashldi3", "i386/ashldi3.S"),
                    ("__ashrdi3", "i386/ashrdi3.S"),
                    ("__divdi3", "i386/divdi3.S"),
                    ("__floatdidf", "i386/floatdidf.S"),
                    ("__floatdisf", "i386/floatdisf.S"),
                    ("__floatdixf", "i386/floatdixf.S"),
                    ("__floatundidf", "i386/floatundidf.S"),
                    ("__floatundisf", "i386/floatundisf.S"),
                    ("__floatundixf", "i386/floatundixf.S"),
                    ("__lshrdi3", "i386/lshrdi3.S"),
                    ("__moddi3", "i386/moddi3.S"),
                    ("__muldi3", "i386/muldi3.S"),
                    ("__udivdi3", "i386/udivdi3.S"),
                    ("__umoddi3", "i386/umoddi3.S"),
                ]);
            }
        }

        if target_arch == "arm" && target_os != "ios" && target_env != "msvc" {
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
            ]);

            if target_os != "windows" {
                sources.extend(&[("__multc3", "multc3.c")]);
            }

            if target_env == "musl" {
                sources.extend(&[
                    ("__addtf3", "addtf3.c"),
                    ("__multf3", "multf3.c"),
                    ("__subtf3", "subtf3.c"),
                    ("__divtf3", "divtf3.c"),
                    ("__powitf2", "powitf2.c"),
                    ("__fe_getround", "fp_mode.c"),
                    ("__fe_raise_inexact", "fp_mode.c"),
                ]);
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

        let src_dir = root.join("lib/builtins");
        for (sym, src) in sources.map.iter() {
            let src = src_dir.join(src);
            cfg.file(&src);
            println!("cargo:rerun-if-changed={}", src.display());
            println!("cargo:rustc-cfg={}=\"optimized-c\"", sym);
        }

        cfg.compile("libcompiler-rt.a");
    }
}
========== build.rs from sdl2-0.34.3 ============================================================
fn main() {
    #[cfg(any(target_os="openbsd", target_os="freebsd"))]
    println!(r"cargo:rustc-link-search=/usr/local/lib");
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
========== build.rs from eyre-0.6.5 ============================================================
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitStatus};

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
========== build.rs from bindgen-0.56.0 ============================================================
mod target {
    use std::env;
    use std::fs::File;
    use std::io::Write;
    use std::path::{Path, PathBuf};

    pub fn main() {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

        let mut dst =
            File::create(Path::new(&out_dir).join("host-target.txt")).unwrap();
        dst.write_all(env::var("TARGET").unwrap().as_bytes())
            .unwrap();
    }
}

mod testgen {
    use std::char;
    use std::env;
    use std::ffi::OsStr;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    pub fn main() {
        let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
        let mut dst =
            File::create(Path::new(&out_dir).join("tests.rs")).unwrap();

        let manifest_dir =
            PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
        let headers_dir = manifest_dir.join("tests").join("headers");

        let headers = match fs::read_dir(headers_dir) {
            Ok(dir) => dir,
            // We may not have headers directory after packaging.
            Err(..) => return,
        };

        let entries =
            headers.map(|result| result.expect("Couldn't read header file"));

        println!("cargo:rerun-if-changed=tests/headers");

        for entry in entries {
            match entry.path().extension().and_then(OsStr::to_str) {
                Some("h") | Some("hpp") => {
                    let func = entry
                        .file_name()
                        .to_str()
                        .unwrap()
                        .replace(|c| !char::is_alphanumeric(c), "_")
                        .replace("__", "_")
                        .to_lowercase();
                    writeln!(
                        dst,
                        "test_header!(header_{}, {:?});",
                        func,
                        entry.path(),
                    )
                    .unwrap();
                }
                _ => {}
            }
        }

        dst.flush().unwrap();
    }
}

fn main() {
    target::main();
    testgen::main();

    // On behalf of clang_sys, rebuild ourselves if important configuration
    // variables change, to ensure that bindings get rebuilt if the
    // underlying libclang changes.
    println!("cargo:rerun-if-env-changed=LLVM_CONFIG_PATH");
    println!("cargo:rerun-if-env-changed=LIBCLANG_PATH");
    println!("cargo:rerun-if-env-changed=LIBCLANG_STATIC_PATH");
    println!("cargo:rerun-if-env-changed=BINDGEN_EXTRA_CLANG_ARGS");
}
========== build.rs from num-traits-0.2.14 ============================================================
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

    autocfg::rerun_path("build.rs");
}
========== build.rs from memchr-2.3.4 ============================================================
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
    if is_env_set("CARGO_CFG_MEMCHR_DISABLE_AUTO_SIMD")
        || !target_has_feature("sse2")
    {
        return;
    }
    println!("cargo:rustc-cfg=memchr_runtime_simd");
    println!("cargo:rustc-cfg=memchr_runtime_sse2");
    println!("cargo:rustc-cfg=memchr_runtime_sse42");
    println!("cargo:rustc-cfg=memchr_runtime_avx");
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
========== build.rs from proc-macro2-1.0.28 ============================================================
// rustc-cfg emitted by the build script:
//
// "use_proc_macro"
//     Link to extern crate proc_macro. Available on any compiler and any target
//     except wasm32. Requires "proc-macro" Cargo cfg to be enabled (default is
//     enabled). On wasm32 we never link to proc_macro even if "proc-macro" cfg
//     is enabled.
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

use std::env;
use std::iter;
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

    let semver_exempt = cfg!(procmacro2_semver_exempt);
    if semver_exempt {
        // https://github.com/alexcrichton/proc-macro2/issues/147
        println!("cargo:rustc-cfg=procmacro2_semver_exempt");
    }

    if semver_exempt || cfg!(feature = "span-locations") {
        println!("cargo:rustc-cfg=span_locations");
    }

    if version.minor < 32 {
        println!("cargo:rustc-cfg=no_libprocmacro_unwind_safe");
    }

    if version.minor < 39 {
        println!("cargo:rustc-cfg=no_bind_by_move_pattern_guard");
    }

    if version.minor >= 44 {
        println!("cargo:rustc-cfg=lexerror_display");
    }

    if version.minor >= 45 {
        println!("cargo:rustc-cfg=hygiene");
    }

    let target = env::var("TARGET").unwrap();
    if !enable_use_proc_macro(&target) {
        return;
    }

    println!("cargo:rustc-cfg=use_proc_macro");

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

fn enable_use_proc_macro(target: &str) -> bool {
    // wasm targets don't have the `proc_macro` crate, disable this feature.
    if target.contains("wasm32") {
        return false;
    }

    // Otherwise, only enable it if our feature is actually enabled.
    cfg!(feature = "proc-macro")
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
    let mut flags_var_split;
    let mut flags_none;
    let flags: &mut dyn Iterator<Item = &str> =
        if let Some(encoded_rustflags) = env::var_os("CARGO_ENCODED_RUSTFLAGS") {
            flags_var = encoded_rustflags;
            flags_var_string = flags_var.to_string_lossy();
            flags_var_split = flags_var_string.split('\x1f');
            &mut flags_var_split
        } else if let Some(rustflags) = env::var_os("RUSTFLAGS") {
            flags_var = rustflags;
            flags_var_string = flags_var.to_string_lossy();
            flags_var_split = flags_var_string.split(' ');
            &mut flags_var_split
        } else {
            flags_none = iter::empty();
            &mut flags_none
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
========== build.rs from wasm-bindgen-0.2.74 ============================================================
// Empty `build.rs` so that `[package] links = ...` works in `Cargo.toml`.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
========== build.rs from rayon-1.5.1 ============================================================
fn main() {
    let ac = autocfg::new();
    if ac.probe_expression("(0..10).step_by(2).rev()") {
        autocfg::emit("step_by");
    }
    if ac.probe_expression("{ fn foo<const N: usize>() {} }") {
        autocfg::emit("min_const_generics");
    }
}
========== build.rs from serde_derive-1.0.130 ============================================================
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
========== build.rs from syn-1.0.75 ============================================================
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
    let nightly = version.contains("nightly");
    Some(Compiler { minor, nightly })
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
========== build.rs from ryu-1.0.5 ============================================================
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

    // 128-bit integers disabled on Emscripten targets as Emscripten doesn't
    // currently support integers larger than 64 bits.
    if !emscripten {
        println!("cargo:rustc-cfg=integer128");
    }

    // MaybeUninit<T> stabilized in Rust 1.36:
    // https://blog.rust-lang.org/2019/07/04/Rust-1.36.0.html
    if minor >= 36 {
        println!("cargo:rustc-cfg=maybe_uninit");
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
========== build.rs from nom-5.1.2 ============================================================
extern crate version_check;

fn main() {
  if version_check::is_min_version("1.28.0").unwrap_or(true) {
    println!("cargo:rustc-cfg=stable_i128");
  }
}
========== build.rs from clang-sys-1.1.0 ============================================================
// Copyright 2016 Kyle Mayes
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Finds `libclang` static or dynamic libraries and links to them.
//!
//! # Environment Variables
//!
//! This build script can make use of several environment variables to help it
//! find the required static or dynamic libraries.
//!
//! * `LLVM_CONFIG_PATH` - provides a path to an `llvm-config` executable
//! * `LIBCLANG_PATH` - provides a path to a directory containing a `libclang`
//!    shared library or a path to a specific `libclang` shared library
//! * `LIBCLANG_STATIC_PATH` - provides a path to a directory containing LLVM
//!    and Clang static libraries

#![allow(unused_attributes)]

extern crate glob;

use std::path::Path;

#[path = "build/common.rs"]
pub mod common;
#[path = "build/dynamic.rs"]
pub mod dynamic;
#[path = "build/static.rs"]
pub mod static_;

/// Copy the file from the supplied source to the supplied destination.
#[cfg(feature = "runtime")]
fn copy(source: &str, destination: &Path) {
    use std::fs::File;
    use std::io::{Read, Write};

    let mut string = String::new();
    File::open(source)
        .unwrap()
        .read_to_string(&mut string)
        .unwrap();
    File::create(destination)
        .unwrap()
        .write_all(string.as_bytes())
        .unwrap();
}

/// Generates the finding and linking code so that it may be used at runtime.
#[cfg(feature = "runtime")]
fn main() {
    use std::env;

    if cfg!(feature = "static") {
        panic!("`runtime` and `static` features can't be combined");
    }

    let out = env::var("OUT_DIR").unwrap();
    copy("build/common.rs", &Path::new(&out).join("common.rs"));
    copy("build/dynamic.rs", &Path::new(&out).join("dynamic.rs"));
}

/// Finds and links to the required libraries.
#[cfg(not(feature = "runtime"))]
fn main() {
    if cfg!(feature = "static") {
        static_::link();
    } else {
        dynamic::link();
    }

    if let Some(output) = common::run_llvm_config(&["--includedir"]) {
        let directory = Path::new(output.trim_end());
        println!("cargo:include={}", directory.display());
    }
}
========== build.rs from wasm-bindgen-shared-0.2.74 ============================================================
use std::collections::hash_map::DefaultHasher;
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
    let schema_file = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"));
    let schema_file = std::fs::read(schema_file).unwrap();

    let mut hasher = DefaultHasher::new();
    hasher.write(&schema_file);

    println!("cargo:rustc-env=SCHEMA_FILE_HASH={}", hasher.finish());
}
========== build.rs from anyhow-1.0.43 ============================================================
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

    if rustc < 38 {
        println!("cargo:rustc-cfg=anyhow_no_macro_reexport");
    }

    if rustc < 51 {
        println!("cargo:rustc-cfg=anyhow_no_ptr_addr_of");
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
========== build.rs from semver-1.0.4 ============================================================
use std::env;
use std::process::Command;
use std::str;

fn main() {
    let compiler = match rustc_minor_version() {
        Some(compiler) => compiler,
        None => return,
    };

    if compiler < 32 {
        // u64::from_ne_bytes.
        // https://doc.rust-lang.org/std/primitive.u64.html#method.from_ne_bytes
        println!("cargo:rustc-cfg=no_from_ne_bytes");
    }

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
