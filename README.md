***
***
***

### // Ascon reference library for me and for you. //

This is an Ascon/NIST SP 800-232 implementation in the form of a small C library. NIST SP 800-232 is the latest official standard. Every cipher from the official implementation is here. All functions/ciphers are validated against the official KAT vectors. C99 only for compatibility across compilers and systems. There are no dependencies, it is freestanding C. Not even libc is needed!

Use example commands from the project root.

## Importing

### Structure information.

In your project, you only need to include the public header in `include/`. 

- `<root>`

    - `src/` - Internal headers and source files. No need to import these.

    - `demo/` - Example C app using the everything in this library.

    - `tests/` - A test app that checks the library functions against the official KAT test vectors, "Known Answer Test". An input-output set provided by the official spec. Passing the input data to a valid implementation will return data matching the expected output data. 

## How to build and run

### Build demo

#### // Via CLI

'zig cc', 'clang', 'gcc' is interchangeable for this. 

```
zig cc -std=c99 -I. demo.c ascon_hash.c ascon_xof.c ascon_aead.c ascon_perm.c -o demo
```

#### // Via build.zig

```
zig build
```

### Build tests

#### // Via CLI

zig cc -std=c99 -O2 -Iinclude -Isrc tests/kat.c src/*.c -o kat

#### // Via build.zig

```
zig build test
```

// in progress //
