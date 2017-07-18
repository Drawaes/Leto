using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using static Leto.Interop.LibCrypto;

namespace Leto.SslStream2.Interop
{
    public unsafe abstract class CustomBioDescription :IDisposable
    {
        private const int BIO_TYPE_MEM = 1 | 0x0400 | 2;
        private const int BIO_TYPE_SOURCE_SINK = 0x0400;
        private BIO_METHOD _methodPointer;

        public CustomBioDescription(string name)
        {
            var index = BIO_get_new_index();
            _methodPointer = BIO_meth_new(index, name);
            BIO_meth_set_write(_methodPointer, (BIO bio, void* p, int length) =>
            {
                var span = new Span<byte>(p, length);
                return Write(bio, span);
            });
            BIO_meth_set_read(_methodPointer, (BIO bio, void* p, int length) =>
            {
                var span = new Span<byte>(p, length);
                return Read(bio, span);
            });
            BIO_meth_set_ctrl(_methodPointer, Control);
            BIO_meth_set_create(_methodPointer, Create);
            BIO_meth_set_destroy(_methodPointer, Destroy);
        }

        public void Dispose() => _methodPointer.Free();

        public BIO New(GCHandle handle)
        {
            var bio = BIO_new(_methodPointer);
            BIO_set_init(bio, 1);
            BIO_set_data(bio, handle);
            return bio;
        }
                
        protected abstract int Write(BIO bio, ReadOnlySpan<byte> input);
        protected abstract int Read(BIO bio, Span<byte> output);
        protected virtual int Create(BIO bio) => 1;
        protected virtual int Destroy(BIO bio)
        {
            BIO_reset_data(bio);
            return 1;
        }
        
        private long Control(BIO bio, BIO_ctrl cmd, long param, void* ptr)
        {
            switch (cmd)
            {
                case BIO_ctrl.BIO_CTRL_FLUSH:
                case BIO_ctrl.BIO_CTRL_POP:
                case BIO_ctrl.BIO_CTRL_PUSH:
                    return 1;
            }
            return 0;
        }
    }
}
