using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Handshake;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange;

namespace Leto.Tls13.State
{
    public unsafe class KeySchedule12 : IDisposable
    {
        private OwnedMemory<byte> _buffer;
        private BufferPool _pool;
        private IConnectionState _state;
        private void* _clientRandom;
        private void* _serverRandom;
        private void* _masterSecret;
        private void* _keyData;

        public KeySchedule12(IConnectionState state, BufferPool pool)
        {
            _pool = pool;
            _buffer = pool.Rent(0);
            _state = state;
            _buffer.Memory.TryGetPointer(out _clientRandom);
            _serverRandom = (byte*)_clientRandom + Hello.RandomLength;
            _masterSecret = (byte*)_serverRandom + Hello.RandomLength;
            _keyData = (byte*)_masterSecret + Tls1_2Consts.MasterSecretLength;
        }

        public Span<byte> ClientRandom => new Span<byte>(_clientRandom, Hello.RandomLength);
        public Span<byte> ServerRandom => new Span<byte>(_serverRandom, Hello.RandomLength);

        public unsafe void GenerateMasterSecret()
        {
            var seedPtr = stackalloc byte[Hello.RandomLength * 2];
            var seedSpan = new Span<byte>(seedPtr, Hello.RandomLength * 2);
            ClientRandom.CopyTo(seedSpan);
            ServerRandom.CopyTo(seedSpan.Slice(Hello.RandomLength));
            _state.KeyShare.DeriveMasterSecretTls12(_state.CryptoProvider.HashProvider, _state.CipherSuite.HashType,
                seedPtr, seedSpan.Length, _masterSecret, Tls1_2Consts.MasterSecretLength);
        }

        public void GenerateKeyMaterial(ref IBulkCipherInstance clientKey, ref IBulkCipherInstance serverKey)
        {
            clientKey = _state.CryptoProvider.CipherProvider.GetCipherKey(_state.CipherSuite.BulkCipherType);
            serverKey = _state.CryptoProvider.CipherProvider.GetCipherKey(_state.CipherSuite.BulkCipherType);

            var materialRequired = (clientKey.KeyLength * 2) + 4 * 2;
            var seedLength = Tls1_2Consts.KeyExpansionSize + Hello.RandomLength * 2;
            var seed = stackalloc byte[seedLength];
            var seedSpan = new Span<byte>(seed, seedLength);
            Tls1_2Consts.GetKeyExpansionSpan().CopyTo(seedSpan);
            ServerRandom.CopyTo(seedSpan.Slice(Tls1_2Consts.KeyExpansionSize));
            ClientRandom.CopyTo(seedSpan.Slice(Tls1_2Consts.KeyExpansionSize + Hello.RandomLength));

            PrfFunctions.P_Hash12(_state.CryptoProvider.HashProvider, _state.CipherSuite.HashType,
                (byte*)_keyData, materialRequired, _masterSecret, Tls1_2Consts.MasterSecretLength,seedSpan );
            var materialSpan = new Span<byte>(_keyData,materialRequired);
            clientKey.SetKey(materialSpan.Slice(0,clientKey.KeyLength));
            materialSpan = materialSpan.Slice(clientKey.KeyLength);
            serverKey.SetKey(materialSpan.Slice(0,serverKey.KeyLength));
            materialSpan = materialSpan.Slice(serverKey.KeyLength);
            var tempIv = stackalloc byte[12];
            var tempSpan = new Span<byte>(tempIv,12);
            for(int i = 0; i < materialSpan.Length;i++)
            {
                materialSpan[i] = (byte)(materialSpan[i] ^ 0x00);
            }
            materialSpan.Slice(0,4).CopyTo(tempSpan);
            clientKey.SetIV(tempSpan);
            materialSpan = materialSpan.Slice(4);
            materialSpan.CopyTo(tempSpan);
            serverKey.SetIV(tempSpan);
        }

        public void Dispose()
        {
            if (_buffer != null)
            {
                _pool.Return(_buffer);
                _buffer = null;
            }
        }

        ~KeySchedule12()
        {
            Dispose();
        }
    }
}
