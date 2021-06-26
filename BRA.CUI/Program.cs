using System;
using System.Threading.Tasks;
using BTA.Core;

namespace BRA.CUI
{
    class Program
    {
        static void Main(string[] args)
        {
            string path = @"c:\Temp\P1.jpg";

            Core core = new Core();
            Task<String> result = core.VirusScanFile(path);

            Console.WriteLine(result.Result);
        }
    }
}
