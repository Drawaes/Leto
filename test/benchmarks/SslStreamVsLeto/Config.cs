using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Environments;
using BenchmarkDotNet.Jobs;

namespace SslStreamVsLeto
{
    public class Config:ManualConfig
    {
        public Config()
        {
            Add(Job.Default.
                With(Platform.X64).
                With(Runtime.Core).
                WithIterationTime(BenchmarkDotNet.Horology.TimeInterval.FromSeconds(2)).
                WithWarmupCount(1).
                WithTargetCount(3));
            Add(new BenchmarkDotNet.Diagnosers.MemoryDiagnoser());
        }
    }
}
