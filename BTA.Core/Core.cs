using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet;
using VirusTotalNet.Exceptions;
using VirusTotalNet.Results;

namespace BTA.Core
{
    public class Core
    {
        public async Task<string> VirusScanFile(string filePath)
        {
            StringBuilder sb = new StringBuilder();

            VirusTotal virusTotal = new VirusTotal("4636f6893f090d0204bfff61651e544fd38882ef4ddc591ca358d269cf520821")
            {
                UseTLS = true
            };

            FileInfo fileInfo = new FileInfo(filePath);

            if (!fileInfo.Exists)
                return "ERROR: File dont exist";

            //Check if the file has been scanned before.
            FileReport report;

            do
            {
                report = await virusTotal.GetFileReportAsync(fileInfo);

                Thread.Sleep(3000);

            } while (report.ResponseCode != VirusTotalNet.ResponseCodes.FileReportResponseCode.Present);


            if (report != null)
            {
                sb.AppendLine("Reports positives: " + report.Positives);
                sb.AppendLine("Total of anti virus checks" + report.Total);
                sb.AppendLine("Final message" + report.VerboseMsg);

                return sb.ToString();
            }

            return "Error:";
        }
    }
}
