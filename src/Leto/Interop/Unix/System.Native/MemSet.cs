using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    internal static partial class Sys
    {
        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_MemSet")]
        internal static extern unsafe void* MemSet(void* s, int c, UIntPtr n);
    }
}