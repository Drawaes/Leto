using System;
using System.Collections.Generic;
using System.Text;
using Leto.Interop;
using Leto.SslStream2.Interop;
using SslStream3.Internal;
using static Leto.Interop.LibCrypto;

namespace SslStream3
{
    internal class CustomInputBio : CustomBioDescription
    {
        public CustomInputBio()
            : base("SslStreamInputBio")
        {

        }

        protected override int Create(BIO bio) => 1;

        protected override int Destroy(BIO bio) => 1;

        protected override int Read(BIO bio, Span<byte> output)
        {
            var handle = BIO_get_data(bio);
            if(!handle.IsAllocated)
            {
                return -1;
            }

            var buffer = handle.Target as SslBuffer;
            if(buffer == null)
            {
                return -1;
            }

            var span = buffer.GetReadSpan(output.Length);
            span.CopyTo(output);
            return span.Length;
        }

        protected override int Write(BIO bio, ReadOnlySpan<byte> input)
        {
            var handle = BIO_get_data(bio);
            if (!handle.IsAllocated)
            {
                return -1;
            }

            var buffer = handle.Target as SslBuffer;
            if (buffer == null)
            {
                return -1;
            }

            var span = buffer.GetWriteSpan(input.Length);
            input.Slice(0, span.Length).CopyTo(span);
            return span.Length;
        }
    }
}
