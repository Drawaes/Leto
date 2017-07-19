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
        private CreateDelegate _create;
        private DestroyDelegate _destroy;
        private ReadDelegate _read;
        private WriteDelegate _write;
        private ControlDelegate _control;

        public CustomBioDescription(string name)
        {
            var index = BIO_get_new_index();
            _methodPointer = BIO_meth_new(index, name);
            _write = new WriteDelegate(Write);
            _read = new ReadDelegate(Read);
            _create = new CreateDelegate(Create);
            _destroy = new DestroyDelegate(Destroy);
            _control = new ControlDelegate(Control);

            BIO_meth_set_write(_methodPointer, _write);
            BIO_meth_set_read(_methodPointer, _read);
            BIO_meth_set_ctrl(_methodPointer, _control);
            BIO_meth_set_create(_methodPointer, _create);
            BIO_meth_set_destroy(_methodPointer, _destroy);
        }

        public void Dispose() => _methodPointer.Free();

        public virtual BIO New()
        {
            var bio = BIO_new(_methodPointer);
            BIO_set_init(bio, 1);
            return bio;
        }
        
        private unsafe int Write(BIO bio, void* p, int length)
        {
            var span = new Span<byte>(p, length);
            return Write(bio, span);
        }

        private unsafe int Read(BIO bio, void* p, int length)
        {
            var span = new Span<byte>(p, length);
            return Read(bio, span);
        }

        protected abstract int Write(BIO bio, ReadOnlySpan<byte> input);
        protected abstract int Read(BIO bio, Span<byte> output);
        protected abstract int Create(BIO bio);
        protected abstract int Destroy(BIO bio);
        
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
