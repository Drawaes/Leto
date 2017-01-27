using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.RecordLayer;

namespace Leto.Tls13.State
{
    public unsafe class KeySchedule : IDisposable
    {
        private void* _secret;
        private byte* _masterSecret;
        private int _hashSize;
        private byte* _clientHandshakeTrafficSecret;
        private byte* _serverHandshakeTrafficSecret;
        private byte* _clientApplicationTrafficSecret;
        private byte* _serverApplicationTrafficSecret;
        private IConnectionStateTls13 _state;
        private byte[] _resumptionSecret;
        private EphemeralBufferPoolWindows _pool;
        private OwnedMemory<byte> _stateData;

        public unsafe KeySchedule(IConnectionStateTls13 state, EphemeralBufferPoolWindows pool, ReadableBuffer resumptionSecret)
        {
            _pool = pool;
            _stateData = pool.Rent();
            _state = state;
            _hashSize = CryptoProvider.HashProvider.HashSize(CipherSuite.HashType);

            _stateData.Memory.TryGetPointer(out _secret);
            _clientHandshakeTrafficSecret = ((byte*)_secret) + _hashSize;
            _serverHandshakeTrafficSecret = _clientHandshakeTrafficSecret + _hashSize;
            _masterSecret = _serverHandshakeTrafficSecret + _hashSize;
            _clientApplicationTrafficSecret = _masterSecret + _hashSize;
            _serverApplicationTrafficSecret = _clientApplicationTrafficSecret + _hashSize;

            void* resumptionPointer = null;
            int secretLength = 0;
            if (resumptionSecret.Length > 0)
            {
                var stackSecret = stackalloc byte[resumptionSecret.Length];
                resumptionSecret.CopyTo(new Span<byte>(stackSecret, resumptionSecret.Length));
                secretLength = resumptionSecret.Length;
                resumptionPointer = stackSecret;
            }
            HkdfFunctions.HkdfExtract(CryptoProvider.HashProvider, CipherSuite.HashType, null, 0, resumptionPointer, secretLength, _secret, _hashSize);
        }

        private CipherSuite CipherSuite => _state.CipherSuite;
        private CryptoProvider CryptoProvider => _state.CryptoProvider;
        public byte[] ResumptionSecret => _resumptionSecret;

        public void GenerateEarlyTrafficKey(ref IBulkCipherInstance earlyDataKey)
        {
            var hash = stackalloc byte[_hashSize];
            _state.HandshakeHash.InterimHash(hash, _hashSize);
            var hashSpan = new Span<byte>(hash, _hashSize);
            HkdfFunctions.ClientEarlyTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, hashSpan, new Span<byte>(_clientHandshakeTrafficSecret, _hashSize));
            earlyDataKey = GetKey(_clientHandshakeTrafficSecret, _hashSize);
        }

        public unsafe void SetDheDerivedValue(IKeyshareInstance keyShare)
        {
            if (keyShare != null)
            {
                keyShare.DeriveSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, _hashSize, _secret, _hashSize);
            }
            else
            {
                HkdfFunctions.HkdfExtract(CryptoProvider.HashProvider, CipherSuite.HashType, null, 0, _secret, _hashSize, _secret, _hashSize);
            }
        }

        public byte[] GenerateServerFinishKey()
        {
            return HkdfFunctions.FinishedKey(CryptoProvider.HashProvider, CipherSuite.HashType, _serverHandshakeTrafficSecret);
        }

        public byte[] GenerateClientFinishedKey()
        {
            return HkdfFunctions.FinishedKey(CryptoProvider.HashProvider, CipherSuite.HashType, _clientHandshakeTrafficSecret);
        }

        private unsafe IBulkCipherInstance GetKey(byte* secret, int secretLength)
        {
            var newKey = CryptoProvider.CipherProvider.GetCipherKey(CipherSuite.BulkCipherType);
            var key = stackalloc byte[newKey.KeyLength];
            var keySpan = new Span<byte>(key, newKey.KeyLength);
            var iv = stackalloc byte[newKey.IVLength];
            var ivSpan = new Span<byte>(iv, newKey.IVLength);
            HkdfFunctions.HkdfExpandLabel(CryptoProvider.HashProvider, CipherSuite.HashType
                    , secret, secretLength, Tls1_3Consts.TrafficKey, new Span<byte>(), keySpan);
            newKey.SetKey(keySpan);
            HkdfFunctions.HkdfExpandLabel(CryptoProvider.HashProvider, CipherSuite.HashType
                    , secret, secretLength, Tls1_3Consts.TrafficIv, new Span<byte>(), ivSpan);
            newKey.SetIV(ivSpan);
            return newKey;
        }

        public unsafe void GenerateResumptionSecret()
        {
            var hash = stackalloc byte[_hashSize];
            _state.HandshakeHash.InterimHash(hash, _hashSize);
            _resumptionSecret = HkdfFunctions.ResumptionSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _masterSecret, new Span<byte>(hash, _hashSize));
        }

        public unsafe void GenerateHandshakeTrafficSecrets(Span<byte> hash)
        {
            HkdfFunctions.ServerHandshakeTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, hash, new Span<byte>(_serverHandshakeTrafficSecret, _hashSize));
            HkdfFunctions.ClientHandshakeTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, hash, new Span<byte>(_clientHandshakeTrafficSecret, _hashSize));
        } 

        public unsafe IBulkCipherInstance GenerateClientHandshakeKey()
        {
            return GetKey(_clientHandshakeTrafficSecret, _hashSize);
        }

        public unsafe IBulkCipherInstance GenerateServerHandshakeKey()
        {
            return GetKey(_serverHandshakeTrafficSecret, _hashSize);
        }

        public unsafe IBulkCipherInstance GenerateClientApplicationKey()
        {
            return GetKey(_clientApplicationTrafficSecret, _hashSize);
        }

        public unsafe IBulkCipherInstance GenerateServerApplicationKey()
        {
            return GetKey(_serverApplicationTrafficSecret, _hashSize);
        }

        public unsafe void GenerateMasterSecret(Span<byte> hash)
        {
            HkdfFunctions.HkdfExtract(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, _hashSize, null, 0, _masterSecret, _hashSize);
            HkdfFunctions.ClientServerApplicationTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _masterSecret, hash,
                new Span<byte>(_clientApplicationTrafficSecret, _hashSize), new Span<byte>(_serverApplicationTrafficSecret, _hashSize));
        }

        public void Dispose()
        {
            _pool.Return(_stateData);
            _stateData = null;
            GC.SuppressFinalize(this);
        }

        ~KeySchedule()
        {
            Dispose();
        }
    }
}

