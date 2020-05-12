
# Introduction

**backdoorfactory** is an extension to [bettercap](https://www.bettercap.org/) that allows the insertion of shellcode into intercepted file downloads.

It lets you man-in-the-middle web file downloads and inject them with platform-appropriate shellcode.  It works on downloaded archives as well.

This is a complete refactor and rewrite of the original [the-backdoor-factory](https://github.com/secretsquirrel/the-backdoor-factory).

## Features

* Works on PE, Mach-O, and ELF format binaries using the [Binject Debug library](https://github.com/Binject/debug)
* Integrates with [bettercap](https://www.bettercap.org/)'s DNS and ARP based man-in-the-middling capabilites
* Unpacks and repacks Zip, Tar, and Tar.gz archives, injecting any binaries inside
* Supports configurable methods of shellcode injection via the [Binjection library](https://github.com/Binject/binjection)
* Shellcode repository allows different shellcodes per architecture and per binary format
