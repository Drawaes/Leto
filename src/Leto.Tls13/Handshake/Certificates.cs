using System;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace Leto.Tls13.Handshake
{
    public class Certificates
    {
        public static void ReadCertificates(ReadableBuffer buffer, SecurePipelineListener listener)
        {
            buffer = buffer.Slice(HandshakeProcessor.HandshakeHeaderSize);
            //ignore context
            BufferExtensions.SliceVector<byte>(ref buffer);
            //slice the list
            buffer = BufferExtensions.SliceVector24Bit(ref buffer);
            X509Certificate2Collection collection;
            if(listener.CertificateValidation == null)
            {
                collection = null;
            }
            else
            {
                collection = new X509Certificate2Collection();
            }
            while(buffer.Length > 0)
            {
                var cert = BufferExtensions.SliceVector24Bit(ref buffer);
                var ext = BufferExtensions.SliceVector<ushort>(ref buffer);
                if(cert.Length > 0 && collection != null)
                {
                    var x509 = new X509Certificate2(cert.ToArray());
                    collection.Add(x509);
                }
            }
            if(collection != null)
            {
                if(!listener.CertificateValidation(collection))
                {
                    Alerts.AlertException.ThrowAlert(Alerts.AlertLevel.Fatal, Alerts.AlertDescription.bad_certificate);
                }
            }
        }
    }
}
