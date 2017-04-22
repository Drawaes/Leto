using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace Leto.EphemeralBuffers
{
    internal static class ExceptionHelper
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        [DebuggerStepThrough]
        internal static void ThrowException(Exception ex) => throw ex;

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void RequestedBufferTooLarge() => ThrowException(new InvalidOperationException("The requested buffer size is too large"));

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void OutOfAvailableBuffers() => ThrowException(new InvalidOperationException("We are out of available buffers"));

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void MemoryBadPageSize() => ThrowException(new InvalidOperationException("Bad memory page size"));

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void UnableToFreeMemory() => ThrowException(new InvalidOperationException("Unable to free the allocated memory"));

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void UnableToFreeMemory(WinErrors errorCode) => ThrowException(new InvalidOperationException($"Unable to free the allocated memory with errorcode {errorCode}"));

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void UnableToAllocateMemory(WinErrors errorCode)
        {
            if(errorCode == WinErrors.ERROR_WORKING_SET_QUOTA)
            {
                ThrowException(new InvalidOperationException("Insufficient quota of working set to lock the memory from paging."));
            }
            ThrowException(new InvalidOperationException($"Unable to allocate memory with error code {errorCode}"));
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void UnableToAllocateMemory() => ThrowException(new InvalidOperationException($"Unable to lock memory"));

        internal enum WinErrors
        {
            ERROR_WORKING_SET_QUOTA = 0x5AD
        }
    }
}
