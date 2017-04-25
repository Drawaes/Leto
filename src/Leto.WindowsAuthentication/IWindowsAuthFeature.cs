using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Principal;

namespace Leto.WindowsAuthentication
{
    public interface IWindowsAuthFeature
    {
        WindowsIdentity Identity { get; set; }
        WindowsIdentity GetUser();
        string ProcessHandshake(string tokenName, byte[] token);
    }
}
