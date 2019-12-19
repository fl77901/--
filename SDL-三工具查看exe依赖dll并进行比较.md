# SDL-三工具查看exe依赖dll并进行比较

---

## 实验目的：
- 综合使用源代码中的模块遍历，结合三个工具 `dumpbin`、`process explore`、`depends`查看可执行文件依赖的dll，进行比较。
## 实验环境：
- Virtual Studio 2017
## 实验过程：
#### dumpbin工具
- 打开vs自带的命令行窗口，按照以下步骤操作：
    - `cd`进入app文件目录下；
    - `dumpbin /imports app.exe`命令查看app.exe调用的dll文件；
    - 输出结果如下，app.exe调用了`baseLib.dll`与`KERNEL32.dll`：
```
Dump of file app.exe

File Type: EXECUTABLE IMAGE

  Section contains the following imports:

    baseLib.dll
             14000C220 Import Address Table
             140014258 Import Name Table
                     0 time date stamp
                     0 Index of first forwarder reference

                           0 lib_function

    KERNEL32.dll
             14000C000 Import Address Table
             140014038 Import Name Table
                     0 time date stamp
                     0 Index of first forwarder reference

                         1D8 GetCommandLineA
                         613 WriteConsoleW
                         443 QueryPerformanceCounter
                         21A GetCurrentProcessId
                         21E GetCurrentThreadId
                         2E9 GetSystemTimeAsFileTime
                         363 InitializeSListHead
                         4C4 RtlCaptureContext
                         4CB RtlLookupFunctionEntry
                         4D2 RtlVirtualUnwind
                         379 IsDebuggerPresent
                         5AC UnhandledExceptionFilter
                         56C SetUnhandledExceptionFilter
                         2D0 GetStartupInfoW
                         380 IsProcessorFeaturePresent
                         277 GetModuleHandleW
                          C9 CreateFileW
                         4D1 RtlUnwindEx
                         260 GetLastError
                         530 SetLastError
                         132 EnterCriticalSection
                         3B5 LeaveCriticalSection
                         10E DeleteCriticalSection
                         35F InitializeCriticalSectionAndSpinCount
                         59C TlsAlloc
                         59E TlsGetValue
                         59F TlsSetValue
                         59D TlsFree
                         1AD FreeLibrary
                         2AE GetProcAddress
                         3BB LoadLibraryExW
                         2D2 GetStdHandle
                         614 WriteFile
                         272 GetModuleFileNameA
                         3E5 MultiByteToWideChar
                         600 WideCharToMultiByte
                         219 GetCurrentProcess
                         160 ExitProcess
                         58A TerminateProcess
                         276 GetModuleHandleExW
                         459 RaiseException
                         1D9 GetCommandLineW
                         1B4 GetACP
                         34A HeapFree
                         346 HeapAlloc
                         177 FindClose
                         17C FindFirstFileExA
                         18C FindNextFileA
                         385 IsValidCodePage
                         297 GetOEMCP
                         1C3 GetCPInfo
                         238 GetEnvironmentStringsW
                         1AC FreeEnvironmentStringsW
                         512 SetEnvironmentVariableA
                         548 SetStdHandle
                         24F GetFileType
                         2D7 GetStringTypeW
                          99 CompareStringW
                         3A9 LCMapStringW
                         2B4 GetProcessHeap
                         34F HeapSize
                         34D HeapReAlloc
                         1A1 FlushFileBuffers
                         1EC GetConsoleCP
                         1FE GetConsoleMode
                         522 SetFilePointerEx
                          85 CloseHandle

  Summary

        2000 .data
        1000 .pdata
        9000 .rdata
        1000 .reloc
        B000 .text
```
#### Process Explorer工具
- 在`View->Lower Pane View`->勾选`DLLs`;
- 显示结果如下图所示，这里显示了app.exe所依赖的所有的dll：
    ![pe查看dll][1]
#### Dependency Walker工具
- 显示结果如下，这里遇到了一些问题，无论下载的是x86还是x64版本的工具，打开app.exe时右下角部分内容无法显示，但其他内容还是可以正常查看：
    ![d查看dll][2]
    ![d查看dll2][3]
## 实验总结
- `dumpbin`的输出比较简洁，只提供了极少的dll，以及该dll下的所有函数。
- `Process Explorer`的输出变多，应该是把dll的链上一直到根`ntdll.dll`上的调用的dll都输出，显示dll的信息包括名字、描述、公司名字和路径。
- `Dependency Walker`输出详尽，所有调用的dll都输出了，还包括dll模块所使用的函数、所有导出函数和所有的属性包括文件的时间戳等信息。


  [1]: https://s2.ax1x.com/2019/12/19/QqhpHH.jpg
  [2]: https://s2.ax1x.com/2019/12/19/QqhCEd.jpg
  [3]: https://s2.ax1x.com/2019/12/19/QqhPUA.jpg