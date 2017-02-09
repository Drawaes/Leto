using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Threading.Tasks;
using Leto.Tls13.BulkCipher;
using Leto.Tls13.Handshake;
using Leto.Tls13.Hash;
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
        private void* _clientFinishedVerify;
        private void* _serverFinishedVerify;
        private Span<byte> _clientSpan;
        private Span<byte> _serverSpan;
        private void* _keyData;
        private int _materialLength;

        public KeySchedule12(IConnectionState state, BufferPool pool)
        {
            _pool = pool;
            _buffer = pool.Rent(0);
            _state = state;
            _buffer.Memory.TryGetPointer(out _clientRandom);
            _serverRandom = (byte*)_clientRandom + Hello.RandomLength;
            _masterSecret = (byte*)_serverRandom + Hello.RandomLength;
            _clientFinishedVerify = (byte*)_masterSecret + Tls1_2Consts.MASTER_SECRET_LENGTH;
            _clientSpan = new Span<byte>(_clientFinishedVerify, Tls1_2Consts.VERIFY_DATA_LENGTH);
            _serverFinishedVerify = (byte*)_clientFinishedVerify + Tls1_2Consts.VERIFY_DATA_LENGTH;
            _serverSpan = new Span<byte>(_serverFinishedVerify, Tls1_2Consts.VERIFY_DATA_LENGTH);
            _keyData = (byte*)_serverFinishedVerify + Tls1_2Consts.VERIFY_DATA_LENGTH;
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
                seedPtr, seedSpan.Length, _masterSecret, Tls1_2Consts.MASTER_SECRET_LENGTH);
        }

        public unsafe void CalculateClientFinished()
        {
            var hashResult = stackalloc byte[_state.HandshakeHash.HashSize + Tls1_2Consts.ClientFinishedLabelSize];
            var seed = new Span<byte>(hashResult, _state.HandshakeHash.HashSize + Tls1_2Consts.ClientFinishedLabelSize);
            _state.HandshakeHash.InterimHash(hashResult + Tls1_2Consts.ClientFinishedLabelSize, _state.HandshakeHash.HashSize);
            var finishedLabel = Tls1_2Consts.GetClientFinishedSpan();
            finishedLabel.CopyTo(seed);
            PrfFunctions.P_Hash12(_state.CryptoProvider.HashProvider, _state.CipherSuite.HashType, _clientSpan, _masterSecret, Tls1_2Consts.MASTER_SECRET_LENGTH, seed);
        }

        public unsafe void CalculateServerFinished()
        {
            uint header = 0;
            var hPtr = (byte*)&header;
            hPtr[0] = (byte)HandshakeType.finished;
            hPtr[3] = Tls1_2Consts.VERIFY_DATA_LENGTH;
            _state.HandshakeHash.HashData(hPtr, 4);
            _state.HandshakeHash.HashData((byte*)_clientFinishedVerify, Tls1_2Consts.VERIFY_DATA_LENGTH);

        }

        public void GenerateKeyMaterial()
        {
            _materialLength = (_state.CryptoProvider.CipherProvider.GetKeySize(_state.CipherSuite.BulkCipherType) * 2) + 4 * 2;
            var seedLength = Tls1_2Consts.KeyExpansionLabelSize + Hello.RandomLength * 2;
            var seed = stackalloc byte[seedLength];
            var seedSpan = new Span<byte>(seed, seedLength);
            Tls1_2Consts.GetKeyExpansionSpan().CopyTo(seedSpan);
            ServerRandom.CopyTo(seedSpan.Slice(Tls1_2Consts.KeyExpansionLabelSize));
            ClientRandom.CopyTo(seedSpan.Slice(Tls1_2Consts.KeyExpansionLabelSize + Hello.RandomLength));
            var materialSpan = new Span<byte>(_keyData, _materialLength);
            PrfFunctions.P_Hash12(_state.CryptoProvider.HashProvider, _state.CipherSuite.HashType,
                materialSpan, _masterSecret, Tls1_2Consts.MASTER_SECRET_LENGTH, seedSpan);
        }

        public WritableBuffer WriteServerFinished(WritableBuffer buffer, IConnectionStateTls12 state)
        {
            buffer.Write(_serverSpan);
            return buffer;
        }

        public void CompareClientFinishedGenerateServerFinished(ReadableBuffer buffer)
        {
            _state.HandshakeHash.HashData(buffer);
            buffer = buffer.Slice(4);
            var result = CompareFunctions.ConstantTimeEquals(_clientSpan, buffer);


            var hashResult = stackalloc byte[_state.HandshakeHash.HashSize + Tls1_2Consts.ServerFinishedLabelSize];
            var seed = new Span<byte>(hashResult, _state.HandshakeHash.HashSize + Tls1_2Consts.ServerFinishedLabelSize);
            _state.HandshakeHash.InterimHash(hashResult + Tls1_2Consts.ServerFinishedLabelSize, _state.HandshakeHash.HashSize);
            var finishedLabel = Tls1_2Consts.GetServerFinishedSpan();
            finishedLabel.CopyTo(seed);
            PrfFunctions.P_Hash12(_state.CryptoProvider.HashProvider, _state.CipherSuite.HashType, _serverSpan, _masterSecret, Tls1_2Consts.MASTER_SECRET_LENGTH, seed);
        }

        public IBulkCipherInstance GetServerKey()
        {
            return GetKey(1);
        }

        public IBulkCipherInstance GetClientKey()
        {
            return GetKey(0);
        }

        private IBulkCipherInstance GetKey(int keyId)
        {
            var key = _state.CryptoProvider.CipherProvider.GetCipherKey(_state.CipherSuite.BulkCipherType);
            var mSpan = new Span<byte>(_keyData, _materialLength);
            key.SetKey(mSpan.Slice(key.KeyLength * keyId, key.KeyLength));
            mSpan = mSpan.Slice(key.KeyLength * 2 + 4 * keyId, 4);
            var tempIv = stackalloc byte[12];
            var tempSpan = new Span<byte>(tempIv, 12);
            for (int i = 0; i < mSpan.Length; i++)
            {
                tempIv[i] = (byte)(mSpan[i] ^ 0x00);
            }
            key.SetIV(tempSpan);
            return key;
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
