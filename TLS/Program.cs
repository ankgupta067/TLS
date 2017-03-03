using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace TLS {
    class Program {
        static SslStream _sslStream = null;
        private static string _message;
        static void Main(string[] args) {
            RunClient();
        }

        private static void RunClient() {
            while (true) {
                Console.Write("\nInput message: ");

                //read a string from the console. 
                _message = Console.ReadLine();

                if (String.Compare(_message, "close", StringComparison.CurrentCultureIgnoreCase) == 0)
                    break;
                if (!String.IsNullOrEmpty(_message)) {
                    //create the client instance. It will perform calls to the server's 
                    //endpoint (192.168.1.21:443) 
                    TcpClient client = new TcpClient("161.85.19.149", 443);
                    SendMessageToServer(client);
                }
            } 
        }

        private static void SendMessageToServer(TcpClient client)
        {
           
            try {

                bool leaveInnerStreamOpen = false;

                RemoteCertificateValidationCallback validationCallback = 
            ServerValidationCallback;

                LocalCertificateSelectionCallback selectionCallback = 
            ClientCertificateSelectionCallback;

                EncryptionPolicy encryptionPolicy = EncryptionPolicy.RequireEncryption;

                //create the SSL stream starting from the NetworkStream associated 
                //with the TcpClient instance 
                _sslStream = new SslStream(client.GetStream(),
                  leaveInnerStreamOpen, validationCallback, selectionCallback, encryptionPolicy);

                //1. start the authentication process. If it doesn't succeed  
                //an AuthenticationException is thrown 
                ClienSideHandshake();

                //2. send the input message to the server 
                SendDataToServer();

            } catch (AuthenticationException ex) {
                Console.WriteLine("\nAuthentication Exception: " + ex.Message);
            } catch (Exception ex) {
                Console.WriteLine("\nError detected: " + ex.Message);
            } finally {
                if (_sslStream != null)
                    _sslStream.Close();
                client.Close();
            } 
        }

        private static X509Certificate ClientCertificateSelectionCallback(object sender, string targethost, X509CertificateCollection localcertificates, X509Certificate remotecertificate, string[] acceptableissuers)
        {
           return null;
        }

        private static bool ServerValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslpolicyerrors)
        {
            return true;
        }

        private static void SendDataToServer()
        {
            var data = Encoding.UTF8.GetBytes(_message);
            _sslStream.Write(data,0,data.Count());
        }

        private static void ClienSideHandshake()
        {
            string targetHost = "161.85.19.149";
            SslProtocols sslProtocol = SslProtocols.Tls;
            bool checkCertificateRevocation = true;

            //Start the handshake 
            _sslStream.AuthenticateAsClient(targetHost, null, sslProtocol, checkCertificateRevocation); 
        }
    }
}
