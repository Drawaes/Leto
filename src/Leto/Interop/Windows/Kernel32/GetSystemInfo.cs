using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.Interop
{
    internal partial class Kernel32
    {
        [DllImport(Libraries.Kernel32)]
        internal extern static void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);
    }
}
