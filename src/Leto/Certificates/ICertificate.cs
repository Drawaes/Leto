using System;
using System.Collections.Generic;
using System.Text;

namespace Leto.Certificates
{
    public interface ICertificate
    {
        CertificateType CertificateType { get; }
    }
}
