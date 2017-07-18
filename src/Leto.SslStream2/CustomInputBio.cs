using System;
using System.Collections.Generic;
using System.Text;
using Leto.Interop;
using Leto.SslStream2.Interop;
using static Leto.Interop.LibCrypto;

namespace Leto.SslStream2
{
    internal class CustomInputBio : CustomBioDescription
    {
        public CustomInputBio()
            :base("SslStreamInputBio")
        {

        }

        protected override int Read(BIO bio, Span<byte> output)
        {
            var handle = BIO_get_data(bio);
            var sslStream = (SslStreamPOC)handle.Target;
            var span = sslStream.InputBuffer.GetReadSpan(output.Length);
            //Console.WriteLine($"Size of request {output.Length} size actually replied {span.Length} buffer remaining {sslStream.InputBuffer.BytesAvailable}");
            if (span.Length == 0)
            {
                BIO_set_retry_reason(bio, RetryReason.BIO_FLAGS_READ | RetryReason.BIO_FLAGS_SHOULD_RETRY);
                return -1;
            }

            span.CopyTo(output);
            return span.Length;
        }

        protected override int Write(BIO bio, ReadOnlySpan<byte> input)
        {
            var handle = BIO_get_data(bio);
            var sslStream = (SslStreamPOC)handle.Target;
            var span = sslStream.OutputBuffer.GetWriteSpan(input.Length);
            if(span.Length == 0)
            {
                BIO_set_retry_reason(bio, RetryReason.BIO_FLAGS_WRITE | RetryReason.BIO_FLAGS_SHOULD_RETRY);
                return -1;
            }

            if (input.Length > span.Length) input.Slice(0, span.Length);
            input.CopyTo(span);
            return span.Length;
        }
    }
}
