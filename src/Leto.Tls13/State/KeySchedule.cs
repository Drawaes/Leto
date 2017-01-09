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
        private byte[] _clientTrafficSecret;
        private byte[] _serverTrafficSecret;
        private ConnectionState _state;
        private byte[] _resumptionSecret;
        private SecureBufferPool _pool;
        private OwnedMemory<byte> _stateData;

        public unsafe KeySchedule(ConnectionState state, SecureBufferPool pool)
        {
            _pool = pool;
            _stateData = pool.Rent();
            _state = state;
            _hashSize = CryptoProvider.HashProvider.HashSize(CipherSuite.HashType);
            _stateData.Memory.TryGetPointer(out _secret);
            HkdfFunctions.HkdfExtract(CryptoProvider.HashProvider, CipherSuite.HashType, null, 0, null, 0, (byte*)_secret, _hashSize);
        }

        private CipherSuite CipherSuite => _state.CipherSuite;
        private CryptoProvider CryptoProvider => _state.CryptoProvider;

        public unsafe void SetDheDerivedValue(byte[] derivedValue)
        {
            fixed (byte* ikm = derivedValue)
            {
                HkdfFunctions.HkdfExtract(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, _hashSize, ikm, derivedValue.Length, _secret, _hashSize);
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

        private unsafe IBulkCipherInstance GetKey(byte* secret, int secretLength, KeyMode mode)
        {
            var newKey = CryptoProvider.CipherProvider.GetCipherKey(CipherSuite.BulkCipherType);
            var key = stackalloc byte[newKey.KeyLength];
            var keySpan = new Span<byte>(key, newKey.KeyLength);
            var iv = stackalloc byte[newKey.IVLength];
            var ivSpan = new Span<byte>(iv, newKey.IVLength);
            HkdfFunctions.HkdfExpandLabel(CryptoProvider.HashProvider, CipherSuite.HashType
                    , secret, secretLength, HkdfFunctions.s_trafficKey, new Span<byte>(), keySpan);
            newKey.SetKey(keySpan, mode);
            HkdfFunctions.HkdfExpandLabel(CryptoProvider.HashProvider, CipherSuite.HashType
                    , secret, secretLength, HkdfFunctions.s_trafficIv, new Span<byte>(), ivSpan);
            newKey.SetIV(ivSpan);
            return newKey;
        }

        public unsafe void GenerateResumptionSecret()
        {
            var hash = stackalloc byte[_hashSize];
            _state.HandshakeHash.InterimHash(hash, _hashSize);
            _resumptionSecret = HkdfFunctions.ResumptionSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, new Span<byte>(hash, _hashSize));
        }

        public unsafe void GenerateHandshakeTrafficKeys(Span<byte> hash)
        {
            _clientTrafficSecret = HkdfFunctions.ClientHandshakeTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, hash);
            _serverTrafficSecret = HkdfFunctions.ServerHandshakeTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, hash);
            fixed (byte* cSecret = _clientTrafficSecret)
            {
                _state.ReadKey?.Dispose();
                _state.ReadKey = GetKey(cSecret, _clientTrafficSecret.Length, KeyMode.Decryption);
            }
            fixed (byte* sSecret = _serverTrafficSecret)
            {
                _state.WriteKey?.Dispose();
                _state.WriteKey = GetKey(sSecret, _serverTrafficSecret.Length, KeyMode.Encryption);
            }
        }

        public unsafe void GenerateMasterSecret(Span<byte> hash)
        {
            HkdfFunctions.HkdfExtract(CryptoProvider.HashProvider, CipherSuite.HashType, _secret, _hashSize, null, 0, (byte*)_secret, _hashSize);
            var traffic = HkdfFunctions.ClientServerApplicationTrafficSecret(CryptoProvider.HashProvider, CipherSuite.HashType, (byte*)_secret, hash);
            _clientTrafficSecret = traffic.Item1;
            _serverTrafficSecret = traffic.Item2;
            fixed (byte* cSecret = _clientTrafficSecret)
            {
                _state.ReadKey?.Dispose();
                _state.ReadKey = GetKey(cSecret, _clientTrafficSecret.Length, KeyMode.Decryption);
            }
            fixed (byte* sSecret = _serverTrafficSecret)
            {
                _state.WriteKey?.Dispose();
                _state.WriteKey = GetKey(sSecret, _serverTrafficSecret.Length, KeyMode.Encryption);
            }
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

