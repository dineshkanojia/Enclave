using Microsoft.ServiceBus.Messaging;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ReadDeviceToCloudMessage
{
    class Program
    {
        static string connectionString = "HostName=iothubserviceenclave.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=l9mYh+RAnbh9z5RR5+1Hd+X8IuzKcYl5j7EBSi597rQ=";
        static string IotHubD2CEndPoint = "messages/events";

        static EventHubClient eventHubClient;
        static void Main(string[] args)
        {
            Program program = new Program();
        }

        public Program()
        {
            Console.WriteLine("Receive Message");

            eventHubClient = EventHubClient.CreateFromConnectionString(connectionString, IotHubD2CEndPoint);

            var d2Partitions = eventHubClient.GetRuntimeInformation().PartitionIds;

            CancellationTokenSource cts = new CancellationTokenSource();

            System.Console.CancelKeyPress += (s, e) =>
            {
                e.Cancel = true;
                cts.Cancel();
                Console.WriteLine("Exiting...");
            };

            var task = new List<Task>();

            foreach (string partition in d2Partitions)
            {
                task.Add(ReceiveMessageFromDeviceAsync(partition, cts.Token));
            }

            Task.WaitAll(task.ToArray());
        }

        private static async Task ReceiveMessageFromDeviceAsync(string partition, CancellationToken ct)
        {
            var eventHunReceiver = eventHubClient.GetDefaultConsumerGroup().CreateReceiver(partition, DateTime.UtcNow);

            while (true)
            {
                if (ct.IsCancellationRequested) break;
                EventData eventData = await eventHunReceiver.ReceiveAsync();

                if (eventData == null) continue;

                string data = Encoding.UTF8.GetString(eventData.GetBytes());

                Console.WriteLine("Message Received Partition: {0} Data: {1}", partition, data);
            }
        }
    }
}
