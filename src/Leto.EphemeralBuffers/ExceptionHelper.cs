using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace Leto.EphemeralBuffers
{
    internal static class ExceptionHelper
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        [DebuggerStepThrough]
        internal static void ThrowException(Exception ex) => throw ex;

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void MemoryBufferNotEphemeral() => ThrowException(new InvalidOperationException("The buffer was not ephemeral"));

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void RequestedBufferTooLarge() => ThrowException(new InvalidOperationException("The requested buffer size is too large"));

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void OutOfAvailableBuffers() => ThrowException(new InvalidOperationException("We are out of available buffers"));

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void MemoryBadPageSize() => ThrowException(new InvalidOperationException("Bad memory page size"));

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void UnableToFreeMemory() => ThrowException(new InvalidOperationException("Unable to free the allocated memory"));
        
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void UnableToAllocateMemory() => ThrowException(new InvalidOperationException("Unable to allocate memory"));
    }
}
