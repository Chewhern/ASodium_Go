# ASodium_Go

ASodium_Go is a Go CGO binding for **libsodium**, modeled after my
production-grade **ASodium (C#)** implementation.

This Go version is primarily derived from the C# implementation and is
still undergoing cleanup and maintenance.

My proficiency in Go is currently weaker than in C#, so this binding
should be approached with care.

If you encounter bugs or design issues, please feel free to report them.

> **Important**
>
> As long as this project is **not listed on pkg.go.dev**, it should be
> considered **experimental / pre-release / non-stable**.
>
> This library is intended for users who already understand:
> - libsodium
> - CGO
> - native dependency management
>
> It is **not intended as a drop-in replacement** for existing Go crypto
> libraries.

---

## Project Status

- ✅ API modeled after a tested C# implementation
- ⚠️ Go binding has **not yet undergone comprehensive Go-level testing**
- ⚠️ CGO boundary, memory handling, and concurrency behavior are still
  being validated
- ❌ No production stability guarantees at this stage

This project deliberately favors **explicit usage and informed users**
over ease of discovery.

---

## Non-Goals

- This is **not** a pure-Go implementation
- This is **not** designed for beginners
- This is **not** optimized for automatic dependency installation
- This does **not** attempt to hide libsodium or CGO complexity

If you are looking for a batteries-included crypto library, this is
probably not what you want.

---

## Requirements (Windows, MinGW)

1. Download the **precompiled libsodium (MinGW)** release from the
   official libsodium GitHub releases page.
2. Install a C compiler by following this guide:  
   https://www.freecodecamp.org/news/how-to-install-c-and-cpp-compiler-on-windows/
3. Install **pkg-config** via **MSYS2** or **MinGW**
   (refer to your preferred tooling or an LLM for details).
4. Configure **PKG_CONFIG_PATH** to point to the directory containing
   `libsodium.pc`:

```
//powershell or command prompt
setx PKG_CONFIG_PATH "C:\Users\john\Desktop\Project_Dependencies\libsodium\lib\pkgconfig"
```

## Requirements (Linux)
This binding has not been fully tested on Linux yet.

You may refer to the following project for general libsodium + Go setup guidance:

https://github.com/GoKillers/libsodium-go

Adjust paths and tooling as necessary for your distribution.

## Runtime requirements (Windows)
When using the precompiled libsodium build, ensure that:

- **libsodium-26.dll** is available at runtime

- The DLL is either:

  - placed in the executable directory, or

  - discoverable via the system PATH

## Runtime Requirements (Linux)
Similar requirements apply on Linux.

Ensure that:

- the appropriate libsodium shared library is installed

- the dynamic linker can locate it at runtime

Exact filenames and locations may vary by distribution.

## Notes on Safety and Usage
This binding does not attempt to silently fall back when libsodium is unavailable.

All native dependencies are expected to be installed explicitly.

Users are expected to understand key sizes, nonce usage, and memory handling requirements imposed by libsodium.

Until further testing and validation is completed, use at your own risk.
