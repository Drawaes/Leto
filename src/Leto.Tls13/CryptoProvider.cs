using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.Hash;
using Leto.Tls13.KeyExchange;

namespace Leto.Tls13
{
    public class CryptoProvider
    {
        private IHashProvider _hashProvider;
        private IKeyShareProvider _keyShareProvider;
        private CipherSuite[] _priorityOrderedCipherSuites;

        public CryptoProvider()
        {
            _keyShareProvider = new KeyExchange.OpenSsl11.KeyShareProvider();
            _hashProvider = new Hash.OpenSsl11.HashProvider();

            _priorityOrderedCipherSuites = new CipherSuite[]
                {
                    new CipherSuite() { BulkCipherType = BulkCipher.BulkCipherType.AES_128_GCM, CipherCode = 0x1301, HashType = HashType.SHA256},
                    new CipherSuite() { BulkCipherType = BulkCipher.BulkCipherType.AES_256_GCM, CipherCode = 0x1302, HashType = HashType.SHA384},
                    new CipherSuite() { BulkCipherType = BulkCipher.BulkCipherType.CHACHA20_POLY1305, CipherCode = 0x1303, HashType = HashType.SHA256},
                    new CipherSuite() { BulkCipherType = BulkCipher.BulkCipherType.AES_128_CCM, CipherCode = 0x1304, HashType = HashType.SHA256},
                    new CipherSuite() { BulkCipherType = BulkCipher.BulkCipherType.AES_128_CCM_8, CipherCode = 0x1305, HashType = HashType.SHA256}
                };
        }

        public IHashProvider HashProvider => _hashProvider;

        public unsafe CipherSuite GetCipherSuiteFromExtension(ReadableBuffer buffer)
        {
            if(buffer.Length % 2 != 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
            var numberOfCiphers = buffer.Length /2;
            var peerCipherList = stackalloc ushort[numberOfCiphers];
            for(var i = 0; i < numberOfCiphers;i++)
            {
                peerCipherList[i] = buffer.ReadBigEndian<ushort>();
                buffer = buffer.Slice(sizeof(ushort));
            }

            for(var i = 0; i < _priorityOrderedCipherSuites.Length; i++)
            {
                for(var x = 0; x < numberOfCiphers;x++)
                {
                    if(peerCipherList[x] == _priorityOrderedCipherSuites[i].CipherCode)
                    {
                        return _priorityOrderedCipherSuites[i];
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.insufficient_security);
            return null;
        }
    }
}
