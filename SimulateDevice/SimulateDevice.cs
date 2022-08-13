using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using DeviceRegistration;
using Microsoft.Azure.Devices.Client;
using Newtonsoft.Json;
using CallingEnclaveWrapper;

namespace SimulateDevice
{
    public class SimulateDevice
    {
        static string IotHubUri = "iothubserviceenclave.azure-devices.net";
        static DeviceClient deviceClient;
        public string deviceId = string.Empty;
        private readonly static byte[] Key = Convert.FromBase64String("AsISxq9OwdZag1163OJqwovXfSWG98m+sPjVwJecfe4=");

        private readonly static byte[] IV = Convert.FromBase64String("Aq0UThtJhjbuyWXtmZs1rw==");

        static void Main(string[] args)
        {
            //Console.WriteLine("Hello World!");
            SimulateDevice simulateDevice = new SimulateDevice();
        }

        public SimulateDevice()
        {

            Console.WriteLine("Simulating Device\n");

            deviceId = new RegisterDevice().AddDevice(); //"AsISxq9OwdZag1163OJqwo";//
            deviceClient = DeviceClient.Create(IotHubUri, new DeviceAuthenticationWithRegistrySymmetricKey("hometemperature", deviceId), TransportType.Mqtt);
            SendMessageToCloudAsync(60, 20, deviceId, "dinesh", "password", "");
        }

        private static async void SendMessageToCloudAsync(double humidity, double temperature, string deviceId, string username, string password, string oldpassword)
        {
            double minTemperature = 20;
            double minHumdity = 60;
            Random rand = new Random();
            CallingEnclaveWrapper.CallingEnclaveWrapper callingApp = new CallingEnclaveWrapper.CallingEnclaveWrapper();
            string encUsername = Encoding.ASCII.GetString(EncryptStringToBytes("dinesh"));
            string encPasword = Encoding.ASCII.GetString(EncryptStringToBytes("password"));
            string endOldpassword = Encoding.ASCII.GetString(EncryptStringToBytes(""));
            int isEnclaveSucess = 0;

            //isEnclaveSucess = if(callingApp.CallEnclaveWrapper(1, deviceId, encUsername, encPasword, endOldpassword);
            Console.WriteLine("Request started > :{0}", DateTime.Now.Millisecond);
            if (callingApp.CallEnclaveWrapper(1, deviceId, encUsername, encPasword, endOldpassword) == 1)
            {
                isEnclaveSucess = 1;
            }
            else if (callingApp.CallEnclaveWrapper(4, deviceId, encUsername, encPasword, endOldpassword) == 1)
            {
                isEnclaveSucess = 1;
            }
            else if (callingApp.CallEnclaveWrapper(3, deviceId, encUsername, encPasword, endOldpassword) == 1)
            {
                isEnclaveSucess = 1;
            }
            else if (callingApp.CallEnclaveWrapper(2, deviceId, encUsername, encPasword, endOldpassword) == 1)
            {
                isEnclaveSucess = 1;
            }
            else
            {
                isEnclaveSucess = 0;
            }

            if (isEnclaveSucess == 1)
            {


                // while (true)
                //  {
                for (int i = 0; i < 30; i++)
                {
                    double currentTemperature = temperature + rand.NextDouble() * 15;
                    double currentHumidity = humidity + rand.NextDouble() * 20;

                    var datapoint = GetTelemetrydata(currentHumidity, currentTemperature, "hometemperature", "", "", "");

                    var messageString = JsonConvert.SerializeObject(datapoint);
                    var message = new Message(Encoding.ASCII.GetBytes(messageString));

                    Console.WriteLine("\nRequest completed > :{0}", DateTime.Now.Millisecond);
                    await deviceClient.SendEventAsync(message);

                    Console.WriteLine("{0} > Sending Message: {1}", DateTime.Now, messageString);
                }
                //await Task.Delay(1000);
                //  }


            }
        }

        public static DataPoint GetTelemetrydata(double humidity, double temperature, string deviceId, string username, string password, string oldpassword)
        {
            DataPoint dataPoint = new DataPoint();
            dataPoint.Deviceid = deviceId;
            dataPoint.Humidity = humidity;
            dataPoint.Temperature = temperature;
            //dataPoint.Username = username;
            // dataPoint.Password = password;
            // dataPoint.OldPassword = oldpassword;
            return dataPoint;

        }

        private static byte[] EncryptStringToBytes(string data)
        {
            byte[] encryptedAuditTrail;

            using (System.Security.Cryptography.Aes newAes = Aes.Create())
            {
                newAes.Key = Key;
                newAes.IV = IV;

                ICryptoTransform encryptor = newAes.CreateEncryptor(Key, IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(data);
                        }
                        encryptedAuditTrail = msEncrypt.ToArray();
                    }
                }
            }

            return encryptedAuditTrail;
        }

        private static string DecryptStringFromBytes(byte[] data)
        {
            string decryptText;

            using (Aes newAes = Aes.Create())
            {
                newAes.Key = Key;
                newAes.IV = IV;

                ICryptoTransform decryptor = newAes.CreateDecryptor(Key, IV);

                using (MemoryStream msDecrypt = new MemoryStream(data))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            decryptText = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }


            return decryptText;
        }
    }
}
