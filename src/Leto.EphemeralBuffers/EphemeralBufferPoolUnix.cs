using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Leto.EphemeralBuffers;
using static Leto.EphemeralBuffers.Interop.Sys;

namespace Leto.EphemeralBuffers
{
    public sealed class EphemeralBufferPoolUnix : EphemeralBufferPool
    {
        public EphemeralBufferPoolUnix(int bufferSize, int bufferCount) : base(bufferSize, bufferCount)
        {
        }

        protected override IntPtr AllocateMemory(uint amountToAllocate)
        {
            var result = MMap(IntPtr.Zero,(UIntPtr) amountToAllocate, MemoryMappedProtections.PROT_READ | MemoryMappedProtections.PROT_WRITE, MemoryMappedFlags.MAP_PRIVATE | MemoryMappedFlags.MAP_ANONYMOUS, -1,(UIntPtr) 0);
            if(result.ToInt64() == -1)
            {
                var errorCode = Marshal.GetLastWin32Error();
                ExceptionHelper.UnableToAllocateMemory();
            }
            if (MLock(result,(UIntPtr) amountToAllocate) < 0)
            {
                ExceptionHelper.UnableToAllocateMemory();
            }
            return result;
        }
     
        protected override void FreeMemory(IntPtr pointer, uint amountToAllocate)
        {
            if (munmap(pointer, (UIntPtr) amountToAllocate) < 0)
            {
                ExceptionHelper.UnableToFreeMemory();
            }
        }

        protected override int GetPageSize()
        {
            var pageSize = SysConf(SysConfName._SC_PAGESIZE).ToInt32();
            if (pageSize < 0)
            {
                ExceptionHelper.MemoryBadPageSize();
            }
            return (int)pageSize;
        }
    }
}
