using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using static Interop.LibCrypto;

namespace Leto.Tls13.KeyExchange.OpenSsl11
{
    public sealed class ECFunctionInstance : IKeyShareInstance
    {
        private bool _hasPeerKey;
        private int _keyExchangeSize;
        private int _nid;
        private EVP_PKEY _peerKey;
        private EVP_PKEY _publicPrivateKey;
        private NamedGroup _namedGroup;
        
        public ECFunctionInstance(NamedGroup namedGroup)
        {
            _namedGroup = namedGroup;
            switch(namedGroup)
            {
                case NamedGroup.x25519:
                    _keyExchangeSize = 32;
                    _nid = OBJ_sn2nid("X25519");
                    break;
                case NamedGroup.x448:
                    _keyExchangeSize = 56;
                    _nid = OBJ_sn2nid("X448");
                    break;
            }
        }

        public NamedGroup NamedGroup => _namedGroup;
        public bool HasPeerKey => _hasPeerKey;
        public int KeyExchangeSize => _keyExchangeSize;

        public unsafe void SetPeerKey(ReadableBuffer buffer)
        {
            if(buffer.Length != _keyExchangeSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
            GCHandle handle;
            void* ptr;
            if (buffer.IsSingleSpan)
            {
                ptr = buffer.First.GetPointer(out handle);
            }
            else
            {
                var tmpBuffer = stackalloc byte[buffer.Length];
                var span = new Span<byte>(tmpBuffer, buffer.Length);
                buffer.CopyTo(span);
                ptr = tmpBuffer;
            }
            _peerKey = EVP_PKEY_new();
            ThrowOnError(EVP_PKEY_set_type(_peerKey, _nid));
            ThrowOnError(EVP_PKEY_set1_tls_encodedpoint(_peerKey, ptr, (UIntPtr)buffer.Length));
            
            if(!_publicPrivateKey.IsValid())
            {
                GenerateKeyset();
            }
            _hasPeerKey = true;
        }

        private void GenerateKeyset()
        {
            var keyGenCtx = EVP_PKEY_CTX_new_id((EVP_PKEY_type)_nid, IntPtr.Zero);
            try
            {
                ThrowOnError(EVP_PKEY_keygen_init(keyGenCtx));
                EVP_PKEY keyPair;
                ThrowOnError(EVP_PKEY_keygen(keyGenCtx, out keyPair));
                _publicPrivateKey = keyPair;
            }
            finally
            {
                keyGenCtx.Free();
            }
        }

        public unsafe void WritePublicKey(ref WritableBuffer keyBuffer)
        {
            IntPtr ptr;
            var buffSize = (int)ThrowOnError(EVP_PKEY_get1_tls_encodedpoint(_publicPrivateKey, out ptr));
            try
            {
                keyBuffer.Ensure(buffSize);
                var span = new Span<byte>((byte*)ptr, buffSize);
                span.CopyTo(keyBuffer.Memory.Span);
                keyBuffer.Advance(span.Length);
            }
            finally
            {
                CRYPTO_clear_free(ptr, (UIntPtr)buffSize, "ECFunctionInstance.cs", 97);
            }
        }

        public unsafe byte[] DeriveSecret()
        {
            var ctx = EVP_PKEY_CTX_new(_publicPrivateKey, IntPtr.Zero);
            try
            {
                ThrowOnError(EVP_PKEY_derive_init(ctx));
                ThrowOnError(EVP_PKEY_derive_set_peer(ctx, _peerKey));
                var length = IntPtr.Zero;
                ThrowOnError(EVP_PKEY_derive(ctx, null, ref length));
                var secret = new byte[length.ToInt32()];
                fixed(void* sPtr = secret)
                {
                    ThrowOnError(EVP_PKEY_derive( ctx, sPtr, ref length));
                }
                return secret;
            }
            finally
            {
                ctx.Free();
                Dispose();
            }
        }

        public void Dispose()
        {
            _peerKey.Free();
            _publicPrivateKey.Free();
            GC.SuppressFinalize(this);
        }

        ~ECFunctionInstance()
        {
            Dispose();
        }
    }
}
