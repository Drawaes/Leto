using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Certificates;
using Leto.Tls13.Hash;
using Leto.Tls13.KeyExchange;
using static Interop.LibCrypto;

namespace Leto.Tls13
{
    public sealed class CryptoProvider : IDisposable
    {
        private IHashProvider _hashProvider;
        private IKeyshareProvider _keyShareProvider;
        private IBulkCipherProvider _bulkCipherProvider;
        private CipherSuite[] _priorityOrderedCipherSuitesTls13;
        private CipherSuite[] _priorityOrderedCipherSuitesTls12;
        private NamedGroup[] _priorityOrderedKeyExchanges;
        private SignatureScheme[] _prioritySignatureSchemes;

        public CryptoProvider()
        {
            if(RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                _keyShareProvider = new KeyExchange.OpenSsl11.KeyshareProvider(); 
                _hashProvider = new Hash.OpenSsl11.HashProvider();
                _bulkCipherProvider = new BulkCipher.OpenSsl11.BulkCipherProvider();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                _keyShareProvider = new KeyExchange.Windows.KeyshareProvider();
                _hashProvider = new Hash.Windows.HashProvider();

            }
            else
            {
                throw new NotImplementedException();
            }

            

            _prioritySignatureSchemes = new SignatureScheme[]
            {
                SignatureScheme.ecdsa_secp256r1_sha256,
                SignatureScheme.ecdsa_secp384r1_sha384,
                SignatureScheme.ecdsa_secp521r1_sha512,
                SignatureScheme.rsa_pss_sha256,
                SignatureScheme.rsa_pss_sha384,
                SignatureScheme.rsa_pss_sha512
            };

            _priorityOrderedKeyExchanges = new NamedGroup[]
            {

                 NamedGroup.x25519,
                 NamedGroup.x448,
                 NamedGroup.secp256r1,
                 NamedGroup.secp521r1,
                 NamedGroup.secp384r1,
                 NamedGroup.ffdhe8192,
                 NamedGroup.ffdhe6144,
                 NamedGroup.ffdhe4096,
                 NamedGroup.ffdhe3072,
                 NamedGroup.ffdhe2048
            };

            _priorityOrderedCipherSuitesTls13 = new CipherSuite[]
                {
                    new CipherSuite() { BulkCipherType = BulkCipherType.CHACHA20_POLY1305, CipherCode = 0x1303, HashType = HashType.SHA256},
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_128_GCM, CipherCode = 0x1301, HashType = HashType.SHA256},
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_256_GCM, CipherCode = 0x1302, HashType = HashType.SHA384},
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_128_CCM, CipherCode = 0x1304, HashType = HashType.SHA256},
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_128_CCM_8, CipherCode = 0x1305, HashType = HashType.SHA256}
                };

            _priorityOrderedCipherSuitesTls12 = new CipherSuite[]
                {
                    //new CipherSuite() {BulkCipherType = BulkCipherType.AES_128_GCM, HashType = HashType.SHA256, CipherName = "TLS_RSA_WITH_AES_128_GCM_SHA256", CipherCode = 0x009C },
                    //new CipherSuite() {BulkCipherType = BulkCipherType.AES_256_GCM, HashType = HashType.SHA384, CipherCode = 0x009D, CipherName = "TLS_RSA_WITH_AES_256_GCM_SHA384" },
                    //new CipherSuite() {BulkCipherType = BulkCipherType.AES_128_GCM, HashType = HashType.SHA256, CipherCode = 0x009E, CipherName = "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256" },
                    //new CipherSuite() { BulkCipherType = BulkCipherType.AES_256_GCM, HashType = HashType.SHA384, CipherCode = 0x009F, CipherName = "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" },
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_128_GCM, HashType = HashType.SHA256, CipherCode = 0xC02B, CipherName = "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", ExchangeType = KeyExchangeType.Ecdhe },
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_256_GCM, HashType = HashType.SHA384, CipherCode = 0xC02C, CipherName = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", ExchangeType = KeyExchangeType.Ecdhe },
                    //new CipherSuite() {BulkCipherType = BulkCipherType.AES_128_GCM, HashType = HashType.SHA256, CipherCode = 0xC02F, CipherName = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" },
                    //new CipherSuite() {BulkCipherType = BulkCipherType.AES_256_GCM, HashType = HashType.SHA384, CipherCode = 0xC030, CipherName = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" },
                    //new CipherSuite() {BulkCipherType = BulkCipherType.CHACHA20_POLY1305, HashType = HashType.SHA256, CipherCode = 0xCCA8, CipherName ="TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
                    new CipherSuite() {BulkCipherType = BulkCipherType.CHACHA20_POLY1305, HashType = HashType.SHA256, CipherCode = 0xCCA9, CipherName ="TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", ExchangeType = KeyExchangeType.Ecdhe },
                    //new CipherSuite() {BulkCipherType = BulkCipherType.CHACHA20_POLY1305, HashType = HashType.SHA256, CipherCode = 0xCCAA, CipherName = "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256" },
                };
        }

        public IHashProvider HashProvider => _hashProvider;
        public IKeyshareProvider KeyShareProvider => _keyShareProvider;
        public IBulkCipherProvider CipherProvider => _bulkCipherProvider;
        public NamedGroup[] SupportedNamedGroups => _priorityOrderedKeyExchanges;

        public void WriteSupportedGroups(ref WritableBuffer buffer)
        {
            var length = _priorityOrderedKeyExchanges.Length * sizeof(NamedGroup);
            buffer.WriteBigEndian((ushort)length);
            for (int i = 0; i < _priorityOrderedKeyExchanges.Length; i++)
            {
                buffer.WriteBigEndian(_priorityOrderedKeyExchanges[i]);
            }
        }

        public void WriteSignatureSchemes(ref WritableBuffer buffer)
        {
            var length = _prioritySignatureSchemes.Length * sizeof(SignatureScheme);
            buffer.WriteBigEndian((ushort)length);
            for (int i = 0; i < _prioritySignatureSchemes.Length; i++)
            {
                buffer.WriteBigEndian(_prioritySignatureSchemes[i]);
            }
        }

        public IKeyshareInstance GetDefaultKeyShare()
        {
            return _keyShareProvider.GetKeyShareInstance(_priorityOrderedKeyExchanges[0]);
        }

        public void WriteCipherSuites(ref WritableBuffer buffer)
        {
            var length = _priorityOrderedCipherSuitesTls13.Length * sizeof(ushort);
            buffer.WriteBigEndian((ushort)length);
            for (int i = 0; i < _priorityOrderedCipherSuitesTls13.Length; i++)
            {
                buffer.WriteBigEndian(_priorityOrderedCipherSuitesTls13[i].CipherCode);
            }
        }

        public CipherSuite GetCipherSuiteFromCode(ushort cipherCode, TlsVersion version)
        {
            var list = GetCipherSuites(version);
            for (int i = 0; i < list.Length; i++)
            {
                if (list[i] != null)
                {
                    return list[i];
                }
            }
            return null;
        }
        
        public unsafe CipherSuite GetCipherSuiteFromExtension(ReadableBuffer buffer, TlsVersion version)
        {
            var list = GetCipherSuites(version);
            if (buffer.Length % 2 != 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, "Cipher suite extension is not divisable by zero");
            }
            var numberOfCiphers = buffer.Length / 2;
            var peerCipherList = stackalloc ushort[numberOfCiphers];
            for (var i = 0; i < numberOfCiphers; i++)
            {
                peerCipherList[i] = buffer.ReadBigEndian<ushort>();
                buffer = buffer.Slice(sizeof(ushort));
            }

            for (var i = 0; i < list.Length; i++)
            {
                for (var x = 0; x < numberOfCiphers; x++)
                {
                    if (peerCipherList[x] == list[i].CipherCode)
                    {
                        return list[i];
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.insufficient_security, "Failed to get a bulk cipher from the cipher extensions");
            return null;
        }

        private CipherSuite[] GetCipherSuites(TlsVersion version)
        {
            if(version == TlsVersion.Tls12)
            {
                return _priorityOrderedCipherSuitesTls12;
            }
            if(version == TlsVersion.Tls13Draft18)
            {
                return _priorityOrderedCipherSuitesTls13;
            }
            return null;
        }

        public unsafe IKeyshareInstance GetKeyshareFromNamedGroups(ReadableBuffer buffer)
        {
            if (buffer.Length % 2 != 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter, "The buffer for supported groups is not divisable by 2");
            }
            var numberOfGroups = buffer.Length / 2;
            var peerGroupList = stackalloc NamedGroup[numberOfGroups];
            for (var i = 0; i < numberOfGroups; i++)
            {
                peerGroupList[i] = buffer.ReadBigEndian<NamedGroup>();
                buffer = buffer.Slice(sizeof(NamedGroup));
            }

            for (var i = 0; i < _priorityOrderedKeyExchanges.Length; i++)
            {
                for (var x = 0; x < numberOfGroups; x++)
                {
                    if (peerGroupList[x] == _priorityOrderedKeyExchanges[i])
                    {
                        var ks = _keyShareProvider.GetKeyShareInstance(peerGroupList[x]);
                        if (ks != null)
                        {
                            return ks;
                        }
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.insufficient_security, "Could not agree on a keyshare from named groups");
            return null;
        }

        public unsafe IKeyshareInstance GetKeyshareFromKeyshare(ReadableBuffer buffer)
        {
            var originalBuffer = buffer;

            int keyshareCount = 0;
            //loop through to find the count of keyshares
            while (buffer.Length > 1)
            {
                buffer = buffer.Slice(sizeof(NamedGroup));
                BufferExtensions.SliceVector<ushort>(ref buffer);
                keyshareCount += 2;
            }

            buffer = originalBuffer;
            var peerKeyshareList = stackalloc ushort[keyshareCount];
            int currentIndex = 0;
            while (buffer.Length > 1)
            {
                NamedGroup namedGroup;
                buffer = buffer.SliceBigEndian(out namedGroup);
                var index = (ushort)(originalBuffer.Length - buffer.Length);
                BufferExtensions.SliceVector<ushort>(ref buffer);
                peerKeyshareList[currentIndex] = (ushort)namedGroup;
                peerKeyshareList[currentIndex + 1] = index;
                currentIndex += 2;
            }

            for (var i = 0; i < _priorityOrderedKeyExchanges.Length; i++)
            {
                for (var x = 0; x < keyshareCount; x += 2)
                {
                    if (peerKeyshareList[x] == (ushort)_priorityOrderedKeyExchanges[i])
                    {
                        var instance = _keyShareProvider.GetKeyShareInstance((NamedGroup)peerKeyshareList[x]);
                        if (instance == null)
                        {
                            continue;
                        }
                        originalBuffer = originalBuffer.Slice(peerKeyshareList[x + 1]);
                        originalBuffer = BufferExtensions.SliceVector<ushort>(ref originalBuffer);
                        instance.SetPeerKey(originalBuffer);
                        return instance;
                    }
                }
            }
            return null;
        }

        public unsafe void FillWithRandom(Memory<byte> memoryToFill)
        {
            GCHandle handle;
            var pointer = memoryToFill.GetPointer(out handle);
            try
            {
                ThrowOnError(RAND_bytes(pointer, memoryToFill.Length));
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }

        public unsafe void FillWithRandom(void* ptr, int size)
        {
            ThrowOnError(RAND_bytes((void*)ptr, size));
        }

        public void Dispose()
        {
            _hashProvider.Dispose();
            _keyShareProvider.Dispose();
            _bulkCipherProvider.Dispose();
            GC.SuppressFinalize(this);
        }

        ~CryptoProvider()
        {
            Dispose();
        }
    }
}
