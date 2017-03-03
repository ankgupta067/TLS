using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace TLSServer {
    class Program {
        static SslStream _sslStream = null;
        static void Main(string[] args)
        {
            test();
        }

        private static void test()
        {
            Runserver();
        }

        private static void Runserver()
        {
            try
            {
                var listener = new TcpListener(IPAddress.Any, 443);
                listener.Start();
                Console.WriteLine("Ready ...\n");
                var _message = Console.ReadLine();
                while (string.Compare(_message,"close") != 0)
                {
                    var client = listener.AcceptTcpClient();
                    ManageRequest(client);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Error detected: " + e.Message); 
            }
            finally
            {
                Console.WriteLine("stopped.");
            }
        }

        private static void ManageRequest(TcpClient client)
        {
           
            try {
                bool leaveInnerStreamOpen = true;

                RemoteCertificateValidationCallback validationCallback = 
            ClientValidationCallback;

                LocalCertificateSelectionCallback selectionCallback = 
            ServerCertificateSelectionCallback;

                EncryptionPolicy encryptionPolicy = EncryptionPolicy.AllowNoEncryption;

                //create the SSL stream starting from the NetworkStream associated 
                //with the TcpClient instance 
                  _sslStream = new SslStream(client.GetStream(),
                  leaveInnerStreamOpen, validationCallback, selectionCallback, encryptionPolicy);

                //1. when the client requests it, the handshake begins 
                ServerSideHandshake();

                //2. read client's data using the encrypted stream 
                ReadClientData();

            } catch (Exception ex) {
                Console.WriteLine("\nError detected: " + ex.Message);
            } finally {
                if (_sslStream != null)
                    _sslStream.Close();
                client.Close();
            } 
        }

        private static void ReadClientData()
        {
            var buffer = new byte[1024];
            var x = _sslStream.Read(buffer, 0, 1024);
            Array.Resize(ref buffer,x);
            var _message =  Encoding.UTF8.GetString(buffer);
            Console.WriteLine("Client said: "  + _message); 

        }

        private static void ServerSideHandshake() {
            X509Certificate2 certificate = GetServerCertificate("ssl_server");

            bool requireClientCertificate = false;
            SslProtocols enabledSslProtocols = SslProtocols.Ssl3 | SslProtocols.Tls;
            bool checkCertificateRevocation = true;


            _sslStream.AuthenticateAsServer
              (certificate, requireClientCertificate, enabledSslProtocols, checkCertificateRevocation); 
        }

        private static X509Certificate2 GetServerCertificate(string p) {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            return store.Certificates[0];
        }

        private static X509Certificate ServerCertificateSelectionCallback(object sender, string targethost, X509CertificateCollection localcertificates, X509Certificate remotecertificate, string[] acceptableissuers)
        {
            return localcertificates[0];
        }

        private static bool ClientValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslpolicyerrors)
        {
            return true;
        }
    }
}
