# Windows DLL Injector

Implementation by Brandon Arvanaghi ([@arvanaghi](https://twitter.com/arvanaghi))

## Usage:

This injector assumes you provide a valid DLL path (e.g. `C:\Windows\System32\cryptext.dll`)

    DLL_Injector.exe <Executable_Name> <Path_To_DLL>

A specific example:

    DLL_Injector.exe Receiver.exe C:\Windows\System32\cryptext.dll

See my [blog post](https://arvanaghi.com/blog/dll-injection-using-loadlibrary-in-C/) explaining how `CreateRemoteThread`, `VirtualAlloxEx`, and `LoadLibrary` can be used to inject a DLL. Note that this is a noisy way to inject a DLL into a remote process.


