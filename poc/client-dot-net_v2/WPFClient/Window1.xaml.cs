using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IdentityModel.Tokens;

namespace WPFClient
{
    /// <summary>
    /// Interaction logic for Window1.xaml
    /// </summary>
    public partial class Window1 : Window
    {
        public Window1()
        {
            InitializeComponent();
        }

        private void buttonWS_Click(object sender, RoutedEventArgs e)
        {
            SecurityToken bootstrapToken = null;

            textBoxResult.AppendText("Getting bootstrap token...\n");

            if (comboBoxBootstrapSTSUrl.SelectedIndex == 0)
            {
                bootstrapToken = TokenUtil.MakeBootstrapSecurityToken();
            }
            else
            {
                // TODO Get BS Token from STS
            }

            textBoxResult.AppendText("Bootstrap token: " + bootstrapToken.ToString() + "\nGetting WS token...\n");

            var wsToken = TokenUtil.GetIssuedToken((string)comboBoxServiceSTSUrl.SelectedValue, (string)comboBoxWSUrl.SelectedValue);
            textBoxResult.AppendText("Webservice token: " + wsToken.ToString());
        }
    }
}
