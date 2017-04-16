using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    internal static partial class Kernel32
    {
        [DllImport(Libraries.Kernel32, EntryPoint = "VirtualAlloc", CharSet = CharSet.Unicode, SetLastError = true)]
        internal extern static IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, int flAllocationType, int flProtect);
        [DllImport(Libraries.Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal extern static bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, int dwFreeType);
        [DllImport(Libraries.Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal extern static bool VirtualLock(IntPtr lpAddress, UIntPtr dwSize);
    }
}
