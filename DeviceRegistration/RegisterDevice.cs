using Microsoft.Azure.Devices;
using Microsoft.Azure.Devices.Common.Exceptions;
using System;
using System.Threading.Tasks;

namespace DeviceRegistration
{

    public class RegisterDevice
    {
        static RegistryManager registryManager;
        static string strConnectionString = "HostName=iothubserviceenclave.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=l9mYh+RAnbh9z5RR5+1Hd+X8IuzKcYl5j7EBSi597rQ=";
        private static async Task<string> AddDeviceAsync()
        {
            string deviceId = "hometemperature";
            Device device;
            try
            {
                device = await registryManager.AddDeviceAsync(new Device(deviceId));
            }
            catch (DeviceAlreadyExistsException)
            {
                device = await registryManager.GetDeviceAsync(deviceId);

            }

            Console.WriteLine("Generated Device key:{0}", device.Authentication.SymmetricKey.PrimaryKey);

            return device.Authentication.SymmetricKey.PrimaryKey;
        }

        public string AddDevice()
        {
            registryManager = RegistryManager.CreateFromConnectionString(strConnectionString);
            return AddDeviceAsync().Result;

        }
    }


}
