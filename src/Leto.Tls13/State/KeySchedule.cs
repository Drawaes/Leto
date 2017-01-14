using System;
using System.Buffers;
using System.Collections.Generic;
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
        private int _hashSize;
        private byte* _clientTrafficSecret;
        private byte* _serverTrafficSecret;
        private IConnectionState _state;
        private byte[] _resumptionSecret;
        private SecureBufferPool _pool;
        private OwnedMemory<byte> _stateData;
        private byte[] resumptionSecret;

        public unsafe KeySchedule(IConnectionState state, SecureBufferPool pool, byte[] resumptionSecret)
        {
            _pool = pool;
            _stateData = pool.Rent();
            _state = state;
            _hashSize = CryptoProvider.HashProvider.HashSize(CipherSuite.HashType);

            _stateData.Memory.TryGetPointer(out _secret);
            _clientTrafficSecret = ((byte*)_secret) + _hashSize;
            _serverTrafficSecret = _clientTrafficSecret + _hashSize;

            void* resumptionPointer = null;
            int secretLength = 0;
            if (resumptionSecret != null)
            {
                var stackSecret = stackalloc byte[resumptionSecret.Length];
                resumptionSecret.CopyTo(new Span<byte>(stackSecret, resumptionSecret.Length));
                secretLength = resumptionSecret.Length;
                resumptionPointer = stackSecret;
            }
            HkdfFunctions.HkdfExtract(CryptoProvider.HashProvider, CipherSuite.HashType, null, 0, resumptionPointer, secretLength, _secret, _hashSize);

            if (resumptionSecret != null)
            {
                var hash = stackalloc byte[_hashSize];
                _state.HandshakeHash.InterimHash(hash, _hashSize);
                var hashSpan = new Span<byte>(hash, _hashSize);
                HkdfFunctions.ClientEarlyTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, hashSpan, new Span<byte>(_clientTrafficSecret, _hashSize));
                state.EarlyDataKey = GetKey(_clientTrafficSecret, _hashSize);
            }
        }

        private CipherSuite CipherSuite => _state.CipherSuite;
        private CryptoProvider CryptoProvider => _state.CryptoProvider;
        public byte[] ResumptionSecret => _resumptionSecret;

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
            return HkdfFunctions.FinishedKey(CryptoProvider.HashProvider, CipherSuite.HashType, _serverTrafficSecret);
        }

        public byte[] GenerateClientFinishedKey()
        {
            return HkdfFunctions.FinishedKey(CryptoProvider.HashProvider, CipherSuite.HashType, _clientTrafficSecret);
        }

        private unsafe IBulkCipherInstance GetKey(byte* secret, int secretLength)
        {
            var newKey = CryptoProvider.CipherProvider.GetCipherKey(CipherSuite.BulkCipherType);
            var key = stackalloc byte[newKey.KeyLength];
            var keySpan = new Span<byte>(key, newKey.KeyLength);
            var iv = stackalloc byte[newKey.IVLength];
            var ivSpan = new Span<byte>(iv, newKey.IVLength);
            HkdfFunctions.HkdfExpandLabel(CryptoProvider.HashProvider, CipherSuite.HashType
                    , secret, secretLength, Tls1_3Labels.TrafficKey, new Span<byte>(), keySpan);
            newKey.SetKey(keySpan);
            HkdfFunctions.HkdfExpandLabel(CryptoProvider.HashProvider, CipherSuite.HashType
                    , secret, secretLength, Tls1_3Labels.TrafficIv, new Span<byte>(), ivSpan);
            newKey.SetIV(ivSpan);
            return newKey;
        }

        public unsafe void GenerateResumptionSecret()
        {
            var hash = stackalloc byte[_hashSize];
            _state.HandshakeHash.InterimHash(hash, _hashSize);
            _resumptionSecret = HkdfFunctions.ResumptionSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, new Span<byte>(hash, _hashSize));
        }

        public unsafe void GenerateHandshakeTrafficKeys(Span<byte> hash, ref IBulkCipherInstance clientKey, ref IBulkCipherInstance serverKey)
        {
            HkdfFunctions.ClientHandshakeTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, hash, new Span<byte>(_clientTrafficSecret, _hashSize));
            HkdfFunctions.ServerHandshakeTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, hash, new Span<byte>(_serverTrafficSecret, _hashSize));
            clientKey?.Dispose();
            clientKey = GetKey(_clientTrafficSecret, _hashSize);
            serverKey?.Dispose();
            serverKey = GetKey(_serverTrafficSecret, _hashSize);
        }

        public unsafe void GenerateMasterSecret(Span<byte> hash, ref IBulkCipherInstance clientKey, ref IBulkCipherInstance serverKey)
        {
            HkdfFunctions.HkdfExtract(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, _hashSize, null, 0, (byte*)_secret, _hashSize);
            HkdfFunctions.ClientServerApplicationTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, (byte*)_secret, hash,
                new Span<byte>(_clientTrafficSecret, _hashSize), new Span<byte>(_serverTrafficSecret, _hashSize));
            clientKey?.Dispose();
            clientKey = GetKey(_clientTrafficSecret, _hashSize);
            serverKey?.Dispose();
            serverKey = GetKey(_serverTrafficSecret, _hashSize);
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

