using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using Leto.EphemeralBuffers;
using static Leto.Interop.Sys;

namespace Leto.EphemeralBuffers
{
    internal sealed class EphemeralBufferPoolUnix : EphemeralBufferPool
    {
        public EphemeralBufferPoolUnix(int bufferSize, int bufferCount) : base(bufferSize, bufferCount)
        {
        }

        protected override IntPtr AllocateMemory(uint amountToAllocate)
        {
            var result = MMap(IntPtr.Zero, amountToAllocate, MemoryMappedProtections.PROT_READ | MemoryMappedProtections.PROT_WRITE, MemoryMappedFlags.MAP_PRIVATE | MemoryMappedFlags.MAP_ANONYMOUS, new IntPtr(-1), 0);
            if(result == IntPtr.Zero)
            {
                ExceptionHelper.UnableToAllocateMemory();
            }
            if (MLock(result, amountToAllocate) < 0)
            {
                ExceptionHelper.UnableToAllocateMemory();
            }
            return result;
        }
     
        protected override void FreeMemory(IntPtr pointer, uint amountToAllocate)
        {
            if (MUnmap(pointer, amountToAllocate) < 0)
            {
                ExceptionHelper.UnableToFreeMemory();
            }
        }

        protected override int GetPageSize()
        {
            var pageSize = SysConf(SysConfName._SC_PAGESIZE);
            if (pageSize < 0)
            {
                ExceptionHelper.MemoryBadPageSize();
            }
            return (int)pageSize;
        }
    }
}
