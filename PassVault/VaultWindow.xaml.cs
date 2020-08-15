using System;
using System.Collections.Generic;
using System.Diagnostics;
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
        private string username;
        Vault vault;
        public VaultWindow(string username, byte[] vaultKey)
        {
            InitializeComponent();
            this.username = username;
            GreetingsTB.Text = "Welcome to your secret vault, " + this.username + ".";
            vault = new Vault(username, vaultKey);
            vaultGrid.ItemsSource = vault.GetVault();
        }

        private void ButtonClickLogoff(object sender, RoutedEventArgs e)
        {
            LoginWindow mw = (LoginWindow)Application.Current.MainWindow;
            mw.Show();
            mw.LoginOutputTB.Text = "";
            mw.RegisterOutputTB.Text = "";
            this.Hide();
        }

        private void AddNewEntry(object sender, RoutedEventArgs e)
        {
            if (NewService.Text.Trim() == "" || NewPassword.Text.Trim() == "")
            {
                emptyFields.Text = "Please do not leave any empty fields.";
                return;
            }
            vault.AddService(NewService.Text.Trim(), NewPassword.Text);
            vaultGrid.Items.Refresh();
            emptyFields.Text = "Record " + NewService.Text + " was added successfully to the vault!";
            NewService.Text = "";
            NewPassword.Text = "";
        }

    }
}
