# ASodium_Go

ASodium_Go is a Go CGO binding for **libsodium**, modeled after my production-grade **ASodium (C#)** implementation.

It does refer to some references from [jamesruan](https://github.com/jamesruan/sodium) and [GoKillers](https://github.com/GoKillers/libsodium-go)

This Go version is primarily derived from the C# implementation and is still undergoing cleanup and maintenance.

My proficiency in Go is currently weaker than in C#, so this binding should be approached with care.

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

- ✅ ABI modeled after a tested C# implementation
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

## Method Choice

This binding exposes **two usage models**, each with different security and operational trade-offs.

### Pointer-Based API (High-Security Use Cases)

If your Go application is **security-focused** and requires stronger memory guarantees (for example, preventing sensitive material from being swapped to disk), you should use the **pointer-based API**, after libsodium has been properly initialized.

This approach allows memory to be allocated via `sodium_malloc` (already comes with `sodium_mlock`), which is required for:

- `sodium_munlock`
- `sodium_mprotect_noaccess`
- `sodium_mprotect_readonly`
- `sodium_mprotect_readwrite`

These mechanisms **cannot be reliably applied** to Go-managed memory (e.g. `[]byte`) and have been verified to **not work correctly with managed memory addresses**.

This model is intended for:
- key material
- longer-lived secrets
- high-risk threat models

It comes with increased complexity and requires careful lifecycle management.

---

### Byte-Based API (General Use Cases)

If your application does **not** require strict memory protection guarantees, you may use the **byte-based API**.

This version operates on Go-managed memory (`[]byte`) and is easier to integrate with standard Go code.

When using this model, you are responsible for deciding whether sensitive data should be explicitly cleared from memory after use.

This model is suitable for:
- short-lived secrets
- lower-risk applications
- simpler integration scenarios

---

### Important Notes

- Pointer-based usage does **not automatically make an application secure**.
- Byte-based usage is **not inherently unsafe**, but offers fewer memory protection guarantees.
- Users are expected to choose the model that best fits their threat model and operational requirements.

## Notes on Safety and Usage
This binding does not attempt to silently fall back when libsodium is unavailable.

All native dependencies are expected to be installed explicitly.

Users are expected to understand key sizes, nonce usage, and memory handling requirements imposed by libsodium.

Until further testing and validation is completed, use at your own risk.
