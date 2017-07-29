using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace LegacyOpenSsl.Interop
{
    public static partial class LibCrypto
    {
        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct BIO_METHOD
        {
            public BIO_TYPE type;
            public IntPtr name;
            public WriteDelegate bwriteDelegate; // int (*bwrite) (BIO*, const char*, int);
            public ReadDelegate breadDelegate; //int (*bread) (BIO*, char*, int);
            public void* bputsDelegate; //int (*bputs) (BIO*, const char*);
            public void* bgestsDelegate; //int (*bgets) (BIO*, char*, int);
            public ControlDelegate ctrlDelegate; //long (*ctrl) (BIO*, int, long, void*);
            public CreateDelegate create; //int (*create) (BIO*);
            public DestroyDelegate destroy; //int (*destroy) (BIO*);
            public void* callback_ctrl; //long (*callback_ctrl) (BIO*, int, bio_info_cb*);
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public unsafe delegate int CreateDelegate(bio_st* bio);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public unsafe delegate int ReadDelegate(BIO bio, void* buf, int size);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public unsafe delegate int WriteDelegate(BIO bio, void* buf, int num);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public unsafe delegate long ControlDelegate(BIO bio, BIO_CTRL cmd, long num, void* ptr);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int DestroyDelegate(BIO bio);
    }
}
