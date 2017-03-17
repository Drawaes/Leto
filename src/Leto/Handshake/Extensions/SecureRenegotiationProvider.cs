using Leto.ConnectionStates;
using System;
using System.Collections.Generic;
using System.IO.Pipelines;
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

        public void WriteExtension(ref WritableBuffer writer)
        {
            //While we don't currently support renegotiation if the client does we should
            //respond to say we don't want any negotiation to give clarity to our position
            //and reduce an attack vector for a MITM attack
            writer.WriteBigEndian(ExtensionType.renegotiation_info);
            writer.WriteBigEndian<ushort>(1);
            writer.WriteBigEndian<byte>(0);
        }
    }
}
