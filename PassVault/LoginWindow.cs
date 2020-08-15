using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Numerics;

namespace PassVault
{
    /// <summary>
    /// Interaction logic for LoginWindow.xaml
    /// </summary>
    public partial class LoginWindow : Window
    {
        private static RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();
        public LoginWindow()
        {
            InitializeComponent();
        }

        private void ButtonClickRegister(object sender, RoutedEventArgs e)
        {
            string username = RegisterUserTB.Text.Trim();
            string masterPassword = RegisterPassTB.Password;
            UserLogin.Register(username, masterPassword);
        }

        private void ButtonClickLogin(object sender, RoutedEventArgs e)
        {
            string username = LoginUserTB.Text.Trim();
            string masterPassword = LoginPassTB.Password;
            UserLogin.Login(username, masterPassword);
        }


        //private void Button_Click(object sender, RoutedEventArgs e)
        //{
        //    byte[] randomNumber = new byte[8];
        //    rngCsp.GetBytes(randomNumber);
        //    RandomNumber.Text = BitConverter.ToDouble(randomNumber, 0).ToString();  
        //}

        //private void Button_Click_1(object sender, RoutedEventArgs e)
        //{
        //    // Create a key and save it in a container.
        //    KeyOutput.Text = StoreKey.GenKey_SaveInContainer("MyKeyContainer");
        //}

        //private void Button_Click_2(object sender, RoutedEventArgs e)
        //{
        //    // Retrieve the key from the container.
        //    KeyOutput.Text = StoreKey.GetKeyFromContainer("MyKeyContainer");
        //}

        //private void Button_Click_3(object sender, RoutedEventArgs e)
        //{
        //    // Delete the key from the container.
        //    KeyOutput.Text = StoreKey.DeleteKeyFromContainer("MyKeyContainer");
        //}

        //private void Button_Click_4(object sender, RoutedEventArgs e)
        //{
        //    KeyOutput.Text = StoreKey.getPublicKeyFromContainer("MyKeyContainer");
        //}

        //private void Button_Click_5(object sender, RoutedEventArgs e)
        //{
        //    RSA rsa = new RSA();
        //    byte[] encrptedText = rsa.Encrypt(new byte[] { 1, 2, 3, 4, 5, 6, 7 });
        //    foreach (var i in encrptedText)
        //    {
        //        Debug.Write(i);
        //    }
        //    Debug.WriteLine("");
        //    byte[] decryptedText = rsa.Decrypt(encrptedText);
        //    foreach (var i in decryptedText)
        //    {
        //        Debug.Write(i);
        //    }            

        //}

        //private void BloomFilter(object sender, RoutedEventArgs e)
        //{
        //        BloomFilter bloomFilter = new BloomFilter((float)0.001);
        //    Debug.WriteLine("The password was found: " + bloomFilter.Find("TempPass123"));

        //}
    }
}
