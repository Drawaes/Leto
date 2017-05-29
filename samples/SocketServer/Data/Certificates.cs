using Leto.Certificates;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SocketServer.Data
{
    public static class Certificates
    {
        public static ICertificate RSACertificate = new ManagedCertificate(new X509Certificate2(@"./Data/TestCert.pfx", "Test123t"), null);
    }
}
