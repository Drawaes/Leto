using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Handshake.Extensions
{
    public class SecureRenegotiationProvider
    {
        public void ProcessExtension(Span<byte> span)
        {
            if (span.Length != 1)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.handshake_failure, "We don't support renegotiation so cannot support a secure renegotiation");
            }
        }
    }
}
