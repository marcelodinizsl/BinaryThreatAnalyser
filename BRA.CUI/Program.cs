using System;
using System.IO;
using System.Threading.Tasks;
using BTA.Core;

namespace BRA.CUI
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("BINARY THREAT ANALYSER TOOL - BTAT\n");
            CheckFile(args);
            StartScan(args[0]);
        }

        private static void StartScan(string filePath)
        {
            Console.WriteLine("Starting scannig .... ");
            AnalyseFile(filePath);
            Console.WriteLine("\nHave a nice day ");
        }

        private static void CheckFile(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("File needed to scan");
                Console.WriteLine("Try Again");
                Environment.Exit(0);
            }

            FileInfo fileInfo = new FileInfo(args[0]);

            if (!fileInfo.Exists)
            {
                Console.WriteLine("File needed to scan");
                Console.WriteLine("Try Again");
                Environment.Exit(0);
            }
        }

        private static void AnalyseFile(string path)
        {
            bool hasResult = false;

            Core core = new Core();
            do
            {
                try
                {
                    Task<String> result = core.VirusScanFile(path);
                    result.Wait();

                   Console.WriteLine("Printing the result");
                   Console.WriteLine(result.Result);
                   hasResult = true;
                }
                catch (IOException exception)
                {
                    Console.WriteLine("Error in the selected file.");
                    Console.WriteLine(exception.Message);
                    break;
                }
                catch (Exception exception)
                {
                    Console.WriteLine("Generic error.");
                    Console.WriteLine(exception.Message);
                    break;
                }
            } while (!hasResult);

            
        }
    }
}
