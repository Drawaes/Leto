using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using Leto.Tls13.Internal;
using Leto.Tls13.KeyExchange.Internal;
using static Interop.LibCrypto;

namespace Leto.Tls13.KeyExchange.OpenSsl11
{
    public class FiniteFieldInstance : IKeyShareInstance
    {
        private bool _hasPeerKey;
        private int _keyExchangeSize;
        private NamedGroup _namedGroup;
        private DH _localKey;
        private BIGNUM _clientBN;

        public FiniteFieldInstance(NamedGroup namedGroup)
        {
            _namedGroup = namedGroup;
        }

        public bool HasPeerKey => _hasPeerKey;
        public int KeyExchangeSize => _keyExchangeSize;

        public NamedGroup NamedGroup => _namedGroup;

        public unsafe byte[] DeriveSecret()
        {
            var buffer = new byte[_keyExchangeSize];
            fixed(byte* ptr = buffer)
            {
                var written = DH_compute_key(ptr, _clientBN, _localKey);
            }
            Dispose();
            return buffer;
        }

        public unsafe void GenerateKeys(byte[] privateKey, byte[] publicKey)
        {
            if(_localKey.IsAllocated)
            {
                return;
            }
            byte[] q,p;
            byte g;
            switch (_namedGroup)
            {
                case NamedGroup.ffdhe2048:
                    _keyExchangeSize = 256;
                    g = Rfc7919Ffdhe.G2048;
                    q = Rfc7919Ffdhe.Q2048;
                    p = Rfc7919Ffdhe.P2048;
                    break;
                case NamedGroup.ffdhe3072:
                    _keyExchangeSize = 384;
                    g = Rfc7919Ffdhe.G3072;
                    q = Rfc7919Ffdhe.Q3072;
                    p = Rfc7919Ffdhe.P3072;
                    break;
                case NamedGroup.ffdhe4096:
                    _keyExchangeSize = 512;
                    g = Rfc7919Ffdhe.G4096;
                    q = Rfc7919Ffdhe.Q4096;
                    p = Rfc7919Ffdhe.P4096;
                    break;
                case NamedGroup.ffdhe6144:
                    _keyExchangeSize = 768;
                    g = Rfc7919Ffdhe.G6144;
                    q = Rfc7919Ffdhe.Q6144;
                    p = Rfc7919Ffdhe.P6144;
                    break;
                case NamedGroup.ffdhe8192:
                    _keyExchangeSize = 1024;
                    g = Rfc7919Ffdhe.G8192;
                    q = Rfc7919Ffdhe.Q8192;
                    p = Rfc7919Ffdhe.P8192;
                    break;
                default:
                    ExceptionHelper.ThrowException(new ArgumentOutOfRangeException());
                    return;
            }
            fixed(byte* qPtr = q)
            fixed(byte* pPtr = p)
            {
                var qBN = BN_bin2bn(qPtr, q.Length, IntPtr.Zero);
                var gBN = BN_bin2bn(&g, 1, IntPtr.Zero);
                var pBN = BN_bin2bn(pPtr, p.Length, IntPtr.Zero);
                _localKey = DH_new();
                ThrowOnError(DH_set0_pqg(_localKey, pBN, qBN, gBN));
            }
            if (privateKey != null)
            {
                fixed (byte* pPtr = privateKey)
                fixed (byte* pubPtr = publicKey)
                {
                    var privBN = BN_bin2bn(pPtr, privateKey.Length, IntPtr.Zero);
                    var pubBN = BN_bin2bn(pubPtr, publicKey.Length, IntPtr.Zero);
                    ThrowOnError(DH_set0_key(_localKey, pubBN, privBN));
                }
            }
            else
            {
                ThrowOnError(DH_generate_key(_localKey));
            }
        }

        public unsafe void SetPeerKey(ReadableBuffer peerKey)
        {
            GenerateKeys(null, null);
            if(peerKey.Length != _keyExchangeSize)
            {
                Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.illegal_parameter);
            }
            GCHandle handle = default(GCHandle);
            try
            {
                void* ptr;
                if (peerKey.IsSingleSpan)
                {
                    ptr = peerKey.First.GetPointer(out handle);
                }
                else
                {
                    var sBuffer = stackalloc byte[peerKey.Length];
                    peerKey.CopyTo(new Span<byte>(sBuffer, peerKey.Length));
                    ptr = sBuffer;
                }
                _clientBN = BN_bin2bn(ptr, peerKey.Length, IntPtr.Zero);
            }
            finally
            {
                if(handle.IsAllocated)
                {
                    handle.Free();
                }
            }
            _hasPeerKey = true;
        }

        public unsafe void WritePublicKey(ref WritableBuffer keyBuffer)
        {
            BIGNUM priv, pub;
            DH_get0_key(_localKey, out pub, out priv);
            keyBuffer.Ensure(_keyExchangeSize);
            GCHandle handle;
            void* ptr = keyBuffer.Memory.GetPointer(out handle);
            try
            {
                var written = BN_bn2binpad(pub, ptr, _keyExchangeSize);
                keyBuffer.Advance(written);
            }
            finally
            {
                if(handle.IsAllocated)
                {
                    handle.Free();
                }
            }
        }

        public void Dispose()
        {
            _localKey.Free();
        }
    }
}
