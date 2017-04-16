using System.Runtime.InteropServices;

namespace Leto.EphemeralBuffers.Interop
{
    internal static partial class Kernel32
    {
        [DllImport(Libraries.Kernel32)]
        internal extern static void GetSystemInfo(out SYSTEM_INFO lpSystemInfo);
    }
}
