using Microsoft.Azure.Devices;
using System;
using System.Linq;
using System.Text;

namespace SendCloudToDevice
{
    class Program
    {
        static string connectionString = "";
        static ServiceClient serviceClient;
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
        }

        public Program()
        {
            Console.WriteLine("Send Cloud to Device message");
            serviceClient = ServiceClient.CreateFromConnectionString(connectionString);
            ReceiveFeedbackAsync();

            Console.WriteLine("Press any key to send a C2D message.");
            Console.ReadLine();

            SendCloudToDeviceAsync();
            Console.ReadLine();
        }

        private async static void SendCloudToDeviceAsync()
        {
            var commandMessage = new Message(Encoding.ASCII.GetBytes("Cloud to device message"));
            commandMessage.Ack = DeliveryAcknowledgement.Full;
            await serviceClient.SendAsync("MyFirstDevice", commandMessage);
        }

        private async static void ReceiveFeedbackAsync()
        {
            var feedbackReceiver = serviceClient.GetFeedbackReceiver();
            Console.WriteLine("\n Receiving c2d feedback from device");

            while (true)
            {
                var feedbackBatch = await feedbackReceiver.ReceiveAsync();
                if (feedbackBatch == null) continue;

                Console.ForegroundColor = ConsoleColor.Yellow;

                Console.WriteLine("Received Feedback:{0}", string.Join(", ", feedbackBatch.Records.Select(f => f.StatusCode)));
                Console.ResetColor();

                await feedbackReceiver.CompleteAsync(feedbackBatch);
            }
        }
    }
}
