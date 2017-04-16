using System;
using System.Runtime.InteropServices;

namespace Leto.EphemeralBuffers.Interop
{
    internal static partial class Sys
    {
        [Flags]
        internal enum MemoryMappedProtections
        {
            PROT_NONE = 0x0,
            PROT_READ = 0x1,
            PROT_WRITE = 0x2,
            PROT_EXEC = 0x4
        }

        [Flags]
        internal enum MemoryMappedFlags
        {
            MAP_SHARED = 0x01,
            MAP_PRIVATE = 0x02,
            MAP_ANONYMOUS = 0x10,
        }

        // NOTE: Shim returns null pointer on failure, not non-null MAP_FAILED sentinel.
        [DllImport(Libraries.SystemNative, EntryPoint = "SystemNative_MMap", SetLastError = true)]
        internal static extern IntPtr MMap(
            IntPtr addr, ulong len,
            MemoryMappedProtections prot, MemoryMappedFlags flags,
            IntPtr fd, long offset);
    }
}
