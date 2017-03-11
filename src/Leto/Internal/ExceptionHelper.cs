using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

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
    }
}
