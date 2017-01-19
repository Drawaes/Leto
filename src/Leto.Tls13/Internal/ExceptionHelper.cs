using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;

namespace Leto.Tls13.Internal
{
    internal static class ExceptionHelper
    {
        [MethodImpl(MethodImplOptions.NoInlining)]
        internal static void ThrowException(Exception ex)
        {
            throw ex;
        }

    }
}
