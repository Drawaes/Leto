using Leto.Keyshares;
using System;
using System.Linq;

namespace Leto.CipherSuites
{
    public class CipherSuite
    {
        private ushort _code;
        private string _name;
        private TlsVersion[] _supportedVersions;
        private KeyExchangeType? _keyExchange;

        public CipherSuite(ushort code, string name, KeyExchangeType? keyExchange, params TlsVersion[] supportedVersions)
        {
            _code = code;
            _name = name;
            _keyExchange = keyExchange;
            _supportedVersions = supportedVersions ?? new TlsVersion[0];
        }

        public ushort Code => _code;
        public KeyExchangeType KeyExchange => 
            _keyExchange ?? throw new InvalidOperationException($"Key exchange is not supported by this cipher suite {_name}");

        public bool SupportsVersion(TlsVersion version) => _supportedVersions.Contains(version);
        public override string ToString() => _name;
    }
}
