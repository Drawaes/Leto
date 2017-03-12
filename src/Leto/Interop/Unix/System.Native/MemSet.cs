using System;
using System.Runtime.InteropServices;

namespace Leto.Interop
{
    internal static partial class Sys
    {
        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_MemSet")]
        internal static extern IntPtr MemSet(IntPtr s, int c, UIntPtr n);
    }
}