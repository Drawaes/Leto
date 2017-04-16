using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using static Leto.Interop.Kernel32;

namespace Leto.EphemeralBuffers
{
    public sealed class EphemeralBufferPoolWindows : EphemeralBufferPool
    {
        public EphemeralBufferPoolWindows(int bufferSize, int bufferCount) : base(bufferSize, bufferCount)
        {
        }

        protected override IntPtr AllocateMemory(uint amountToAllocate)
        {
            var result = VirtualAlloc(IntPtr.Zero,(UIntPtr) amountToAllocate, MemOptions.MEM_COMMIT | MemOptions.MEM_RESERVE, PageOptions.PAGE_READWRITE);
            if(!VirtualLock(result,(UIntPtr)amountToAllocate))
            {
                ExceptionHelper.UnableToAllocateMemory();
            }
            return result;
        }

        protected override int GetPageSize()
        {
            GetSystemInfo(out SYSTEM_INFO sysInfo);
            return sysInfo.dwPageSize;
        }

        protected override void FreeMemory(IntPtr pointer, uint amountToAllocate)
        {
            if (!VirtualFree(pointer, (UIntPtr)amountToAllocate, 0x8000))
            {
                ExceptionHelper.UnableToFreeMemory();
            }
        }
    }
}
