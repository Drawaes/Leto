using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

namespace Leto.Internal
{
    internal static class ExceptionHelper
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        [DebuggerStepThrough]
        internal static void ThrowException(Exception ex)
        {
            throw ex;
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void MemoryBufferNotEphemeral()
        {
            ThrowException(new InvalidOperationException("The buffer was not ephemeral"));
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void MemeoryBadPageSize()
        {
            ThrowException(new InvalidOperationException("Unable to get system page size"));
        }
    }
}
