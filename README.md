***
***
***

### < In progress, ready soon! (any day now) >

Current status: Testing implementation, files will trickle in.

// Counting those in ./include, ./src, and build.zig.
Completed core files available: **3/9**

### // Ascon reference library for me and for you. //

This is an Ascon/NIST SP 800-232 implementation in the form of a small C library. NIST SP 800-232 is the latest official standard. Every cipher from the official implementation is here. All functions/ciphers are validated against the official KAT vectors. C99 only for compatibility across compilers and systems. There are no dependencies, it is freestanding C. Not even libc is needed!

Use example commands from the project root.

<br>

## Import

> In your project, you only need to include the public header in <u>*include/*</u>.

- `include/`
    - ascon.h <i><-- include this only.</i>

- `src/` - Internal headers and source files. No need to import these.

    - ascon_aead.c
    - ascon_hash.c
    - ascon_perm.c
    - ascon_perm.h
    - ascon_sponge.h
    - ascon_word.h
    - ascon_xof.c

- `demo/` - Example C app using the everything in this library.

    - demo.c

- `tests/` - A test app that checks the library functions against the official KAT test vectors, "Known Answer Test". An input-output set provided by the official spec. Passing the input data to a valid implementation will return data matching the expected output data. 
    - `vectors/` ...
    - kat.c

## How to build, run, and import

### Build and use a static library

`zig build`

// Output

```
./zig-out/
    include/ascon.h (library header)
    lib/libascon.a (static libary bin)
```

#### Use in your project

Include the header file `ascon.h` and link the static library `libascon.a`, both from the chart above.

### Build demo

#### // Via CLI

'zig cc', 'clang', 'gcc' are interchangeable for this. 

```
zig cc -std=c99 -I. demo.c ascon_hash.c ascon_xof.c ascon_aead.c ascon_perm.c -o demo
```

Output at project root.

#### // Via build.zig

```
zig build demo
```

Output at `./zig-out/bin/`.

### Build tests - KAT

#### // Via CLI

```
zig cc -std=c99 -O2 -Iinclude -Isrc tests/kat.c src/*.c -o kat
```

Output at project root.

#### // Via build.zig

```
zig build kat
```

Output at ./zig-out/bin/

***
***

#### Notes on building 

##### // How to save 632 bytes!

As mentioned earlier, there is no dependency on libc. It's recommended to use the flag -ffreestanding with zig cc, clang, and gcc. Even though the code does not use libc functions like memset, the compiler will recognize equivalent for loops (for-loops?), and turn it into a memset call anyway. No issue in most cases, but passing -ffreestanding to zig cc or clang saved 632 bytes in the output by using the for loop in the source rather than the call sequence. 

#### Notes on Ascon

There are multiple iterations published for competitions and a NIST draft. This implementation is based on the latest NIST "final" SP (special publication) as of at least 2026-09-26 ([ISO 8601](https://en.wikipedia.org/wiki/ISO_8601) btw, A... Debian Testing btw). 

***
***

#### References

- [Ascon - official site](https://ascon.isec.tugraz.at/)
- [NIST SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/final) // [NIST SP 800-232 PDF](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-232.pdf)
- [Ascon (cipher) - Wikipedia](https://en.wikipedia.org/wiki/Ascon_(cipher))
- [ascon-c - GitHub](https://github.com/ascon/ascon-c)
