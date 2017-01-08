using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.KeyExchange;
using Leto.Tls13.RecordLayer;

namespace Leto.Tls13.State
{
    public class KeySchedule
    {
        private CipherSuite _cipherSuite;
        private CryptoProvider _provider;
        private byte[] _earlySecret;
        private byte[] _handshakeSecret;
        private byte[] _masterSecret;
        private int _hashSize;
        private byte[] _clientTrafficSecret;
        private byte[] _serverTrafficSecret;

        public unsafe KeySchedule(CipherSuite cipherSuite, CryptoProvider provider)
        {
            _cipherSuite = cipherSuite;
            _provider = provider;
            _hashSize = provider.HashProvider.HashSize(cipherSuite.HashType);
            _earlySecret = new byte[_hashSize];
            fixed (byte* earlyPtr = _earlySecret)
            {
                HkdfFunctions.HkdfExtract(provider.HashProvider, cipherSuite.HashType, null, 0, null, 0, earlyPtr, _earlySecret.Length);
            }
        }

        public unsafe void SetDheDerivedValue(byte[] derivedValue)
        {
            _handshakeSecret = new byte[_hashSize];
            fixed (byte* salt = _earlySecret)
            fixed (byte* ikm = derivedValue)
            fixed (byte* output = _handshakeSecret)
            {
                HkdfFunctions.HkdfExtract(_provider.HashProvider, _cipherSuite.HashType, salt, _earlySecret.Length, ikm, derivedValue.Length, output, _hashSize);
            }
        }

        public byte[] GenerateServerFinishKey()
        {
            return HkdfFunctions.FinishedKey(_provider.HashProvider, _cipherSuite.HashType, _serverTrafficSecret);
        }

        public byte[] GenerateClientFinishedKey()
        {
            return HkdfFunctions.FinishedKey(_provider.HashProvider, _cipherSuite.HashType, _clientTrafficSecret);
        }

        private unsafe IBulkCipherInstance GetKey(byte* secret, int secretLength, KeyMode mode)
        {
            var newKey = _provider.CipherProvider.GetCipherKey(_cipherSuite.BulkCipherType);
            var key = stackalloc byte[newKey.KeyLength];
            var keySpan = new Span<byte>(key, newKey.KeyLength);
            var iv = stackalloc byte[newKey.IVLength];
            var ivSpan = new Span<byte>(iv, newKey.IVLength);
            HkdfFunctions.HkdfExpandLabel(_provider.HashProvider, _cipherSuite.HashType
                    , secret, secretLength, HkdfFunctions.s_trafficKey, new Span<byte>(), keySpan);
            newKey.SetKey(keySpan, mode);
            HkdfFunctions.HkdfExpandLabel(_provider.HashProvider, _cipherSuite.HashType
                    , secret, secretLength, HkdfFunctions.s_trafficIv, new Span<byte>(), ivSpan);
            newKey.SetIV(ivSpan);
            return newKey;
        }

        public unsafe void GenerateHandshakeTrafficKeys(Span<byte> hash, ConnectionState state)
        {
            _clientTrafficSecret = HkdfFunctions.ClientHandshakeTrafficSecret(_provider.HashProvider, _cipherSuite.HashType, _handshakeSecret, hash);
            _serverTrafficSecret = HkdfFunctions.ServerHandshakeTrafficSecret(_provider.HashProvider, _cipherSuite.HashType, _handshakeSecret, hash);
            fixed (byte* cSecret = _clientTrafficSecret)
            {
                state.ReadKey = GetKey(cSecret, _clientTrafficSecret.Length, KeyMode.Decryption);
            }
            fixed (byte* sSecret = _serverTrafficSecret)
            {
                state.WriteKey = GetKey(sSecret, _serverTrafficSecret.Length, KeyMode.Encryption);
            }
        }

        public unsafe void GenerateMasterSecret(Span<byte> hash, ConnectionState state)
        {
            _masterSecret = new byte[_hashSize];
            fixed (byte* hPtr = _handshakeSecret)
            fixed (byte* mPtr = _masterSecret)
            {
                HkdfFunctions.HkdfExtract(_provider.HashProvider, _cipherSuite.HashType, hPtr, _hashSize, null, 0, mPtr, _hashSize);
            }
            var traffic = HkdfFunctions.ClientServerApplicationTrafficSecret(_provider.HashProvider, _cipherSuite.HashType, _masterSecret, hash);
            _clientTrafficSecret = traffic.Item1;
            _serverTrafficSecret = traffic.Item2;
            fixed (byte* cSecret = _clientTrafficSecret)
            {
                state.ReadKey = GetKey(cSecret, _clientTrafficSecret.Length, KeyMode.Decryption);
            }
            fixed (byte* sSecret = _serverTrafficSecret)
            {
                state.WriteKey = GetKey(sSecret, _serverTrafficSecret.Length, KeyMode.Encryption);
            }
        }
    }
}

