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
            try
            {
                var handle = BIO_get_data(bio);
                if (!handle.IsAllocated)
                {
                    return -1;
                }
                var buffer = (handle.Target as SslStreamPOC)?.InputBuffer;
                if (buffer == null)
                {
                    return -1;
                }

                var span = buffer.GetReadSpan(output.Length);
                //Console.WriteLine($"Size of request {output.Length} size actually replied {span.Length} buffer remaining {sslStream.InputBuffer.BytesAvailable}");
                if (span.Length == 0)
                {
                    BIO_set_retry_reason(bio, RetryReason.BIO_FLAGS_READ | RetryReason.BIO_FLAGS_SHOULD_RETRY);
                    return -1;
                }

                span.CopyTo(output);
                return span.Length;
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Error in read {ex}");
                return -1;
            }
        }

        protected override int Write(BIO bio, ReadOnlySpan<byte> input)
        {
            try
            {
                var handle = BIO_get_data(bio);
                if (!handle.IsAllocated)
                {
                    return -1;
                }
                var buffer = (handle.Target as SslStreamPOC)?.OutputBuffer;
                if (buffer == null)
                {
                    return -1;
                }

                var span = buffer.GetWriteSpan(input.Length);
                if (span.Length == 0)
                {
                    BIO_set_retry_reason(bio, RetryReason.BIO_FLAGS_WRITE | RetryReason.BIO_FLAGS_SHOULD_RETRY);
                    return -1;
                }

                if (input.Length > span.Length) input.Slice(0, span.Length);
                input.CopyTo(span);
                return span.Length;
            }
            catch(Exception ex)
            {
                Console.WriteLine($"Error in write {ex}");
                return -1;
            }
}
    }
}
