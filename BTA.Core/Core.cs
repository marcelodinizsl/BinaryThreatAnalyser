using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using VirusTotalNet;
using VirusTotalNet.ResponseCodes;
using VirusTotalNet.Results;

namespace BTA.Core
{
    public class Core
    {
        static string API_KEY = "4636f6893f090d0204bfff61651e544fd38882ef4ddc591ca358d269cf520821";
        static int SLEEP_TIME = 25000;
        static int SLEEP_TIME_FROM_SCAN = 3000;

        public async Task<string> VirusScanFile(string filePath)
        {
            VirusTotal virusTotal = GetVirusTotalInstance();
            FileInfo fileInfo = new FileInfo(filePath);
            FileReport finalReport = await CheckFileReport(virusTotal, fileInfo);

            if (finalReport != null)
            {
                StringBuilder resultInfo = BuildFinalReport(finalReport);

                return resultInfo.ToString();
            }

            throw new Exception("ERROR: Problem in the scanning");
        }

        private VirusTotal GetVirusTotalInstance()
        {
            return new VirusTotal(API_KEY)
            {
                UseTLS = true
            };
        }

        private static StringBuilder BuildFinalReport(FileReport finalReport)
        {
            StringBuilder resultInfo = new StringBuilder();
            resultInfo.AppendLine("Scan Id: " + finalReport.ScanId);
            resultInfo.AppendLine("Scan date: " + finalReport.ScanDate);
            resultInfo.AppendLine("Reports positives: " + finalReport.Positives);
            resultInfo.AppendLine("Total of anti-virus usded in the analyse: " + finalReport.Total);
            resultInfo.AppendLine("Final message: " + finalReport.VerboseMsg);
        
            return resultInfo;
        }

        private static async Task<FileReport> CheckFileReport(VirusTotal virusTotal, FileInfo fileInfo)
        {
            FileReport report;
            await virusTotal.ScanFileAsync(fileInfo);
            Thread.Sleep(SLEEP_TIME_FROM_SCAN);

            do
            {
                report = await virusTotal.GetFileReportAsync(fileInfo);

                if (report.ResponseCode != FileReportResponseCode.Present)
                    Thread.Sleep(SLEEP_TIME);

            } while (report.ResponseCode != FileReportResponseCode.Present);

            return report;
        }
    }
}
