using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
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
        private int _hashSize;
        private byte[] _clientHandshakeTrafficSecret;
        private byte[] _serverHandshakeTrafficSecret;

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
            return HkdfFunctions.FinishedKey(_provider.HashProvider, _cipherSuite.HashType, _serverHandshakeTrafficSecret);
        }

        public byte[] GenerateClientFinishedKey()
        {
            return HkdfFunctions.FinishedKey(_provider.HashProvider, _cipherSuite.HashType, _clientHandshakeTrafficSecret);
        }

        public unsafe void GenerateHandshakeTrafficKeys(Span<byte> hash, ConnectionState state)
        {
            _clientHandshakeTrafficSecret = HkdfFunctions.ClientHandshakeTrafficSecret(_provider.HashProvider, _cipherSuite.HashType, _handshakeSecret, hash);
            _serverHandshakeTrafficSecret = HkdfFunctions.ServerHandshakeTrafficSecret(_provider.HashProvider, _cipherSuite.HashType, _handshakeSecret, hash);

            var clientKey = _provider.CipherProvider.GetCipherKey(_cipherSuite.BulkCipherType);
            var serverKey = _provider.CipherProvider.GetCipherKey(_cipherSuite.BulkCipherType);

            var key = stackalloc byte[clientKey.KeyLength];
            var keySpan = new Span<byte>(key, clientKey.KeyLength);
            fixed (byte* cSecret = _clientHandshakeTrafficSecret)
            {
                HkdfFunctions.HkdfExpandLabel(_provider.HashProvider, _cipherSuite.HashType
                    , cSecret, _clientHandshakeTrafficSecret.Length, HkdfFunctions.s_trafficKey, new Span<byte>(), keySpan);
                clientKey.SetKey(keySpan, BulkCipher.KeyMode.Decryption);
                keySpan = keySpan.Slice(0,clientKey.IVLength);
                HkdfFunctions.HkdfExpandLabel(_provider.HashProvider, _cipherSuite.HashType
                    , cSecret, _clientHandshakeTrafficSecret.Length, HkdfFunctions.s_trafficIv, new Span<byte>(), keySpan);
                clientKey.SetIV(keySpan);
            }
            keySpan = new Span<byte>(key, clientKey.KeyLength);
            fixed (byte* sSecret = _serverHandshakeTrafficSecret)
            {
                HkdfFunctions.HkdfExpandLabel(_provider.HashProvider, _cipherSuite.HashType
                    , sSecret, _serverHandshakeTrafficSecret.Length, HkdfFunctions.s_trafficKey, new Span<byte>(), keySpan);
                serverKey.SetKey(keySpan, BulkCipher.KeyMode.Encryption);
                keySpan = keySpan.Slice(0, serverKey.IVLength);
                HkdfFunctions.HkdfExpandLabel(_provider.HashProvider, _cipherSuite.HashType
                    , sSecret, _serverHandshakeTrafficSecret.Length, HkdfFunctions.s_trafficIv, new Span<byte>(), keySpan);
                serverKey.SetIV(keySpan);
            }
            state.ReadKey = clientKey;
            state.WriteKey = serverKey;
        }

    }
}

