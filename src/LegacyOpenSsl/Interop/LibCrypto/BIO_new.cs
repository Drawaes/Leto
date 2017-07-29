using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class LibCrypto
    {
        unsafe static LibCrypto()
        {
            CRYPTO_set_locking_callback(LockStore.Callback);
            ERR_load_crypto_strings();
            SSL_load_error_strings();
            OPENSSL_add_all_algorithms_noconf();
            ThrowOnErrorReturnCode(SSL_library_init());

            _createDelegate = Create;
            _writeDelegate = Write;
            _readDelegate = Read;
            _controlDelegate = Control;

            var name = Marshal.StringToHGlobalAnsi("Custom Bio\0");
            var method = new BIO_METHOD()
            {
                type = BIO_TYPE.BIO_TYPE_SOURCE_SINK,
                name = name,
                create = _createDelegate,
                breadDelegate = _readDelegate,
                bwriteDelegate = _writeDelegate,
                ctrlDelegate = _controlDelegate,
            };

            var size = Marshal.SizeOf(typeof(BIO_METHOD));
            _customStruct = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(method, _customStruct, true);
        }

        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern BIO BIO_new(IntPtr type);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern int BIO_set_ex_data(BIO bio, int idx, IntPtr data);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr BIO_get_ex_data(BIO bio, int idx);
        [DllImport(Libraries.LibCrypto, CallingConvention = CallingConvention.Cdecl)]
        private static extern void BIO_set_flags(BIO b, BIO_FLAGS flags);

        private static IntPtr _customStruct;
        private static CreateDelegate _createDelegate;
        private unsafe static WriteDelegate _writeDelegate;
        private unsafe static ReadDelegate _readDelegate;
        private unsafe static ControlDelegate _controlDelegate;

        private unsafe static int Create(bio_st* bio)
        {
            bio[0].init = 1;
            return 1;
        }

        internal static GCHandle BioGetGCHandle(BIO bio)
        {
            var ptr = BIO_get_ex_data(bio, 0);
            if (ptr == IntPtr.Zero) return default(GCHandle);
            return GCHandle.FromIntPtr(ptr);
        }

        internal static void BioSetGCHandle(BIO bio, GCHandle handle)
        {
            var ptr = GCHandle.ToIntPtr(handle);
            ThrowOnErrorReturnCode(BIO_set_ex_data(bio, 0, ptr));
        }

        internal static void BioResetGCHandle(BIO bio) =>  ThrowOnErrorReturnCode( BIO_set_ex_data(bio, 0, IntPtr.Zero));

        public static BIO BIO_new_custom()
        {
            return BIO_new(_customStruct);
        }

        private static unsafe int Write(BIO bio, void* input, int size)
        {
            var handle = BioGetGCHandle(bio);
            if (!handle.IsAllocated)
            {
                return -1;
            }
            var buffer = handle.Target as SslBuffer;
            if (buffer == null)
            {
                return -1;
            }
            
            var span = buffer.GetWriteSpan(size);
            if (span.Length < size)
            {
                BIO_set_flags(bio, BIO_FLAGS.BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS.BIO_FLAGS_WRITE);
            }
            if(span.Length == 0)
            {
                return 0;
            }
            var inputSpan = new Span<byte>(input, size);

            inputSpan.Slice(0, span.Length).CopyTo(span);
            return span.Length;
        }

        private static unsafe int Read(BIO bio, void* output, int size)
        {
            var handle = BioGetGCHandle(bio);
            if (!handle.IsAllocated)
            {
                return -1;
            }
            var buffer = handle.Target as SslBuffer;
            if (buffer == null)
            {
                return -1;
            }
            var span = buffer.GetReadSpan(size);
            if (span.Length < size)
            {
                BIO_set_flags(bio, BIO_FLAGS.BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS.BIO_FLAGS_READ);
            }
            if(span.Length == 0)
            {
                return 0;
            }
            var outputSpan = new Span<byte>(output, size);

            span.CopyTo(outputSpan);
            return span.Length;
        }

        private static unsafe long Control(BIO bio, BIO_CTRL cmd, long param, void* ptr)
        {
            switch (cmd)
            {
                case BIO_CTRL.BIO_CTRL_FLUSH:
                case BIO_CTRL.BIO_CTRL_POP:
                case BIO_CTRL.BIO_CTRL_PUSH:
                    return 1;
            }
            return 0;
        }
    }
}

