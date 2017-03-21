using Leto.Certificates;
using Leto.Hashes;
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
        private HashType _hashType;
        private BulkCipherType _bulkCipherType;
        private CertificateType? _certificateType;

        public CipherSuite(ushort code, string name,BulkCipherType cipherType, HashType hashType, KeyExchangeType? keyExchange, CertificateType? certificateType, params TlsVersion[] supportedVersions)
        {
            _bulkCipherType = cipherType;
            _certificateType = certificateType;
            _code = code;
            _name = name;
            _hashType = hashType;
            _keyExchange = keyExchange;
            _supportedVersions = supportedVersions ?? new TlsVersion[0];
        }

        public ushort Code => _code;
        public CertificateType? CertificateType => _certificateType;
        public KeyExchangeType KeyExchange =>
            _keyExchange ?? throw new InvalidOperationException($"Key exchange is not supported by this cipher suite {_name}");
        public HashType HashType => _hashType;
        public BulkCipherType BulkCipherType => _bulkCipherType;

        public bool SupportsVersion(TlsVersion version) => _supportedVersions.Contains(version);
        public override string ToString() => _name;
    }
}
