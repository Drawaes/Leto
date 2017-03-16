using Leto.Handshake.Extensions;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto
{
    public interface ISecurePipeListener
    {
        ICryptoProvider CryptoProvider { get; }
        ApplicationLayerProtocolProvider AlpnProvider { get; }
        SecureRenegotiationProvider SecureRenegotiationProvider { get; }
    }
}
