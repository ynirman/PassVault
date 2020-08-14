using System;
using System.Collections.Generic;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace PassVault
{
    /// <summary>
    /// Interaction logic for VaultWindow.xaml
    /// </summary>
    public partial class VaultWindow : Window
    {
        public VaultWindow(string username)
        {
            InitializeComponent();
            GreetingsTB.Text = "Welcome to your secret vault, " + username + ".";
        }

        private void ButtonClickLogoff(object sender, RoutedEventArgs e)
        {
            LoginWindow mw = (LoginWindow)Application.Current.MainWindow;
            mw.Show();
            mw.LoginOutputTB.Text = "";
            mw.RegisterOutputTB.Text = "";
            this.Hide();
        }
    }
}
