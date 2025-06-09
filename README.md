# Sample-Remote-Process-Injection-3

This project is for testing and better understanding process injection and Powershell/C++ functions that are called when the sample script is executed. This project tracks the functions from high-level down to syscall leveraging and pivoting off of [Malware Morphology](https://github.com/jaredcatkinson/MalwareMorphology) and [function-call-stacks](https://github.com/jaredcatkinson/function-call-stacks) projects by [@jaredcatkinson](https://github.com/jaredcatkinson).

This project is designed for educational purposes only.

This source code simply starts the process mspaint.exe and injects shellcode, that opens a messagebox to display a hello message.

Be sure to open mspaint.exe first, then run "sample3.ps1" as administrator.

To see the "Function Calls Diagram.json", copy the json to the website [arrows.app](https://arrows.app).

Note: The "Function Calls Diagram.json" diagram is currently incomplete due to difficulties tracking functions through .NET API's/DLL's.

This source code is only intended for educational use.

Usage of this source code for nefarious, malicious, or illegal purposes is strictly prohibited.
