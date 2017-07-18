using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace AspnetBench
{
    public class Startup
    {
        public void Configure(IApplicationBuilder app)
        {
            app.UsePlainText();
        }
    }
}
