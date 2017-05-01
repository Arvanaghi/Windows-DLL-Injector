# Windows DLL Injector

Implementation by Brandon Arvanaghi (https://twitter.com/arvanaghi)[(@arvanaghi)]

## Usage:

This injector assumes you provide a valid DLL path (e.g. `C:\Windows\System32\cryptext.dll`)

    DLL_Injector.exe <Executable_Name> <Path_To_DLL>

A specific example:

    DLL_Injector.exe Receiver.exe C:\Windows\System32\cryptext.dll

I did a writeup on how a basic DLL injection can be achieved by using `CreateRemoteThread` and `LoadLibrary`. Note that this is a noisy way to inject a DLL into a remote process, and was implemented for educational purposes. See my [blog post](https://arvanaghi.com/blog/dll-injection-using-loadlibrary-in-C/).


