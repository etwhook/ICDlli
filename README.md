
# ICDlli

Yet Another Method Of Detecting DLL Injection, Using Instrumention Callbacks.


## Usage In Byfron and AC / AT Software

One of the biggest threat to any AC or AT software is **DLL Injection**, Which will allow a cheater to gain **internal** access to the process, Now alot of ACs have implemented lots of techniques to detect these dll injection methods, One is hooking **LdrInitializeThunk** for which i released a little PoC on this github, But the most popular method is using **instrumention callbacks** (ICs), Which allow you to capture all **system calls**, Now how can we utilize this? Since **LdrInitializeThunk** is still a system call, An IC can very well capture it, And that's how byfron detects dll injection and other injection methods (most notably **APC Injection**, a later PoC will be released for that too), ICDlli will fetch the threads start address and then get its function name and then compare it to the **LoadLibrary** variations and **LdrLoadDll**, If the match was successful, It would terminate the thread.

