using Leto.CipherSuites;
using Leto.Handshake;
using System;
using System.Collections.Generic;
using System.Text;

namespace Leto
{
    public interface ICryptoProvider
    {
        CipherSuiteProvider CipherSuites { get; }
    }
}
