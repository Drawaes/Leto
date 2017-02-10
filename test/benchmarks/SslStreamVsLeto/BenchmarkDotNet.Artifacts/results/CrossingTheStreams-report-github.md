``` ini

BenchmarkDotNet=v0.10.1, OS=Windows
Processor=?, ProcessorCount=8
Frequency=2742189 Hz, Resolution=364.6722 ns, Timer=TSC
dotnet cli version=1.0.0-preview2-1-003177
  [Host]     : .NET Core 4.6.24628.01, 64bit RyuJIT [AttachedDebugger]
  DefaultJob : .NET Core 4.6.25009.03, 64bit RyuJIT


```
        Method |          Mean |     StdErr |      StdDev | Scaled | Scaled-StdDev | Allocated |
-------------- |-------------- |----------- |------------ |------- |-------------- |---------- |
 Stream2Stream |   752.1607 us |  5.9069 us |  22.8773 us |   1.00 |          0.00 |  16.42 kB |
   Stream2Leto | 4,091.9445 us | 57.5220 us | 275.8658 us |   5.44 |          0.39 |  18.51 kB |
