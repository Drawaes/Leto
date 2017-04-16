using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.EphemeralBuffers.Interop
{
    internal static partial class Kernel32
    {
        [DllImport(Libraries.Kernel32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();
    }
}
