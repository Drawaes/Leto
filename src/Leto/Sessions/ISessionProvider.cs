using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Text;

namespace Leto.Sessions
{
    public interface ISessionProvider
    {
        Span<byte> ProcessSessionTicket(Span<byte> sessionTicket);
        void EncryptSessionKey(ref WritableBuffer writer, Span<byte> ticketContent);
        DateTime GetCurrentExpiry();
    }
}
