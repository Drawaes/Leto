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
            MAP_ANONYMOUS = 0x20,
        }

        [DllImport("libc.so.6", SetLastError =true, EntryPoint ="mmap")]
        internal static extern IntPtr MMap(IntPtr addr, UIntPtr length, MemoryMappedProtections prot, MemoryMappedFlags flags, int fd, UIntPtr offset);
    }
}
