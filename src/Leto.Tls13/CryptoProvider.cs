using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
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
        private CipherSuite[] _priorityOrderedCipherSuites;
        private NamedGroup[] _priorityOrderedKeyExchange;

        public CryptoProvider()
        {
            _keyShareProvider = new KeyExchange.OpenSsl11.KeyshareProvider(); //new KeyExchange.Windows.KeyshareProvider();//
            _hashProvider = new Hash.OpenSsl11.HashProvider(); //new Hash.Windows.HashProvider(); // 
            _bulkCipherProvider = new BulkCipher.OpenSsl11.BulkCipherProvider();

            _priorityOrderedKeyExchange = new NamedGroup[]
            {
                 NamedGroup.x25519,
                 NamedGroup.x448,
                 NamedGroup.secp521r1,
                 NamedGroup.secp384r1,
                 NamedGroup.secp256r1,
                 NamedGroup.ffdhe8192,
                 NamedGroup.ffdhe6144,
                 NamedGroup.ffdhe4096,
                 NamedGroup.ffdhe3072,
                 NamedGroup.ffdhe2048
            };

            _priorityOrderedCipherSuites = new CipherSuite[]
                {
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_128_GCM, CipherCode = 0x1301, HashType = HashType.SHA256},
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_256_GCM, CipherCode = 0x1302, HashType = HashType.SHA384},
                    new CipherSuite() { BulkCipherType = BulkCipherType.CHACHA20_POLY1305, CipherCode = 0x1303, HashType = HashType.SHA256},
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_128_CCM, CipherCode = 0x1304, HashType = HashType.SHA256},
                    new CipherSuite() { BulkCipherType = BulkCipherType.AES_128_CCM_8, CipherCode = 0x1305, HashType = HashType.SHA256}
                };
        }

        internal CipherSuite GetCipherSuiteFromCode(ushort cipherCode)
        {
            for(int i = 0; i < _priorityOrderedCipherSuites.Length;i++)
            {
                if(_priorityOrderedCipherSuites[i] != null)
                {
                    return _priorityOrderedCipherSuites[i];
                }
            }
            return null;
        }

        public IHashProvider HashProvider => _hashProvider;
        public IKeyshareProvider KeyShareProvider => _keyShareProvider;
        public IBulkCipherProvider CipherProvider => _bulkCipherProvider;
        public NamedGroup[] SupportedNamedGroups => _priorityOrderedKeyExchange;

        public unsafe CipherSuite GetCipherSuiteFromExtension(ReadableBuffer buffer)
        {
            if (buffer.Length % 2 != 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
            var numberOfCiphers = buffer.Length / 2;
            var peerCipherList = stackalloc ushort[numberOfCiphers];
            for (var i = 0; i < numberOfCiphers; i++)
            {
                peerCipherList[i] = buffer.ReadBigEndian<ushort>();
                buffer = buffer.Slice(sizeof(ushort));
            }

            for (var i = 0; i < _priorityOrderedCipherSuites.Length; i++)
            {
                for (var x = 0; x < numberOfCiphers; x++)
                {
                    if (peerCipherList[x] == _priorityOrderedCipherSuites[i].CipherCode)
                    {
                        return _priorityOrderedCipherSuites[i];
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.insufficient_security);
            return null;
        }

        public unsafe IKeyshareInstance GetKeyshareFromNamedGroups(ReadableBuffer buffer)
        {
            if (buffer.Length % 2 != 0)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
            var numberOfGroups = buffer.Length / 2;
            var peerGroupList = stackalloc NamedGroup[numberOfGroups];
            for (var i = 0; i < numberOfGroups; i++)
            {
                peerGroupList[i] = buffer.ReadBigEndian<NamedGroup>();
                buffer = buffer.Slice(sizeof(NamedGroup));
            }

            for (var i = 0; i < _priorityOrderedKeyExchange.Length; i++)
            {
                for (var x = 0; x < numberOfGroups; x++)
                {
                    if (peerGroupList[x] == _priorityOrderedKeyExchange[i])
                    {
                        var ks = _keyShareProvider.GetKeyShareInstance(peerGroupList[x]);
                        if (ks != null)
                        {
                            return ks;
                        }
                    }
                }
            }
            Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.insufficient_security);
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

            for (var i = 0; i < _priorityOrderedKeyExchange.Length; i++)
            {
                for (var x = 0; x < keyshareCount; x += 2)
                {
                    if (peerKeyshareList[x] == (ushort)_priorityOrderedKeyExchange[i])
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
