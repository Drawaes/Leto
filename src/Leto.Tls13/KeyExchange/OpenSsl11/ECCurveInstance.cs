using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.Hash;
using static Interop.LibCrypto;

namespace Leto.Tls13.KeyExchange.OpenSsl11
{
    public class ECCurveInstance : IKeyshareInstance
    {
        private bool _hasPeerKey;
        private int _keyExchangeSize;
        private NamedGroup _namedGroup;
        private int _curveNid;
        private EVP_PKEY _eKey;
        private EVP_PKEY _clientKey;

        public ECCurveInstance(NamedGroup namedGroup, int keyExchangeSize)
        {
            _keyExchangeSize = keyExchangeSize;
            _namedGroup = namedGroup;
            switch (namedGroup)
            {
                case NamedGroup.secp256r1:
                    _curveNid = OBJ_sn2nid("prime256v1");
                    break;
                case NamedGroup.secp384r1:
                    _curveNid = OBJ_sn2nid("secp384r1");
                    break;
                case NamedGroup.secp521r1:
                    _curveNid = OBJ_sn2nid("secp521r1");
                    break;
            }
        }

        public bool HasPeerKey => _hasPeerKey;
        public int KeyExchangeSize => _keyExchangeSize;
        public NamedGroup NamedGroup => _namedGroup;

        private void GenerateECKeySet()
        {
            if(_eKey.IsValid())
            {
                return;
            }
            var param = CreateParams();
            var keyGenCtx = default(EVP_PKEY_CTX);
            try
            {
                keyGenCtx = EVP_PKEY_CTX_new(param, IntPtr.Zero);
                ThrowOnError(EVP_PKEY_keygen_init(keyGenCtx));
                EVP_PKEY keyPair;
                ThrowOnError(EVP_PKEY_keygen(keyGenCtx, out keyPair));
                _eKey = keyPair;
            }
            finally
            {
                keyGenCtx.Free();
                param.Free();
            }
        }

        private unsafe EVP_PKEY CreateParams()
        {
            const EVP_PKEY_Ctrl_OP op = EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_PARAMGEN | EVP_PKEY_Ctrl_OP.EVP_PKEY_OP_KEYGEN;

            var ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_type.EVP_PKEY_EC, IntPtr.Zero);
            try
            {
                ThrowOnError(EVP_PKEY_paramgen_init(ctx));
                ThrowOnError(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_type.EVP_PKEY_EC, op, EVP_PKEY_Ctrl_Command.EVP_PKEY_CTRL_EC_PARAMGEN_CURVE_NID, _curveNid, null));
                EVP_PKEY key;
                ThrowOnError(EVP_PKEY_paramgen(ctx, out key));
                return key;
            }
            finally
            {
                ctx.Free();
            }
        }

        public unsafe void DeriveSecret(IHashProvider hashProvider, HashType hashType, void* salt, int saltSize, void* output, int outputSize)
        {
            var ctx = EVP_PKEY_CTX_new(_eKey, IntPtr.Zero);
            try
            {
                ThrowOnError(EVP_PKEY_derive_init(ctx));
                ThrowOnError(EVP_PKEY_derive_set_peer(ctx, _clientKey));
                IntPtr len = IntPtr.Zero;
                ThrowOnError(EVP_PKEY_derive(ctx, null, ref len));

                var data = stackalloc byte[len.ToInt32()];
                ThrowOnError(EVP_PKEY_derive(ctx, data, ref len));
                Dispose();
                hashProvider.HmacData(hashType, salt, saltSize, data, len.ToInt32(), output,outputSize);
            }
            finally
            {
                ctx.Free();
            }
        }
    
        public void Dispose()
        {
            _clientKey.Free();
            _eKey.Free();
            GC.SuppressFinalize(this);
        }

        ~ECCurveInstance()
        {
            Dispose();
        }

        public unsafe void SetPeerKey(ReadableBuffer peerKey)
        {
            GenerateECKeySet();

            var group = EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(_eKey));
            var point = EC_POINT_new(group);
            try
            {
                var handle = default(GCHandle);
                try
                {
                    void* ptr;
                    if (peerKey.IsSingleSpan)
                    {
                        ptr = peerKey.First.GetPointer(out handle);
                    }
                    else
                    {
                        var tmpBuffer = stackalloc byte[peerKey.Length];
                        var span = new Span<byte>(tmpBuffer, peerKey.Length);
                        peerKey.CopyTo(span);
                        ptr = tmpBuffer;
                    }
                    ThrowOnError(EC_POINT_oct2point(group, point, ptr, (IntPtr)peerKey.Length, null));
                }
                finally
                {
                    if(handle.IsAllocated)
                    {
                        handle.Free();
                    }
                }
                var ecClientKey = EC_KEY_new_by_curve_name(_curveNid);
                ThrowOnError(EC_KEY_set_public_key(ecClientKey, point));
                _clientKey = EVP_PKEY_new();
                ThrowOnError(EVP_PKEY_assign_EC_KEY(_clientKey, ecClientKey));
                _hasPeerKey = true;
            }
            finally
            {
                point.Free();
            }
        }

        public unsafe void WritePublicKey(ref WritableBuffer keyBuffer)
        {
            GenerateECKeySet();
            var key = EVP_PKEY_get0_EC_KEY(_eKey);
            var pubKey = EC_KEY_get0_public_key(key);
            var group = EC_KEY_get0_group(key);
            IntPtr size = EC_POINT_point2oct(group, pubKey, EC_POINT_CONVERSION.POINT_CONVERSION_UNCOMPRESSED, null, IntPtr.Zero, IntPtr.Zero);
            var s = (ushort)size.ToInt32();
            keyBuffer.Ensure(s);
            GCHandle handle;
            var ptr = keyBuffer.Memory.GetPointer(out handle);
            try
            {
                size = EC_POINT_point2oct(group, pubKey, EC_POINT_CONVERSION.POINT_CONVERSION_UNCOMPRESSED, ptr, size, IntPtr.Zero);
                keyBuffer.Advance(s);
            }
            finally
            {
                if (handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }
    }
}
