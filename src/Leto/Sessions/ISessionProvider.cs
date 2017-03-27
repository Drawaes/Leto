using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Sessions
{
    public interface ISessionProvider
    {
        Span<byte> ProcessSessionTicket(Span<byte> sessionTicket);
        Span<byte> ProduceSessionTicket(ReadOnlySpan<byte> sessionData);
    }
}
