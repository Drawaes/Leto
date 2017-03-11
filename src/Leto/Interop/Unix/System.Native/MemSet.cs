using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    internal static partial class Sys
    {
        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_MemSet")]
        internal static extern unsafe void* MemSet(void* s, int c, UIntPtr n);
    }
}