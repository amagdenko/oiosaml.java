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
using System.Security.Cryptography.X509Certificates;

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

            var certs = CertificateUtil.GetCertificates(StoreName.My, StoreLocation.LocalMachine);
            comboBoxCerts.ItemsSource = certs;
            comboBoxCerts.SelectedValuePath = "Subject";
            comboBoxCerts.DisplayMemberPath = "SubjectName.Name";
        }

        private void buttonWS_Click(object sender, RoutedEventArgs e)
        {
            // Get bootstrap token


            SecurityToken bootstrapToken = null;
            SecurityToken token = null;

            try
            {
                if (string.IsNullOrEmpty(textBoxLocalUrl.Text))
                {
                    textBoxResult.AppendText("No local STS Url selected, using bootstrap token.\n");
                    bootstrapToken = TokenUtil.MakeBootstrapSecurityToken(textBoxServiceUrl.Text);
                }
                else
                {
                    // TODO: Use real bs-token
                    bootstrapToken = TokenUtil.MakeBootstrapSecurityToken(textBoxServiceUrl.Text);
                }


            }
            catch (Exception ex)
            {
                textBoxResult.AppendText("Exception while getting bootstrap-token: " + ex);
                return;
            }

            string selectedCert = null;
            try
            {
                // Get WS Token

                selectedCert = (string)comboBoxCerts.SelectedValue;
                textBoxResult.AppendText("Getting WS token...\n");
                token = TokenUtil.GetIssuedToken(textBoxServiceSTSUrl.Text, textBoxServiceUrl.Text, selectedCert, bootstrapToken);
                
                textBoxResult.AppendText("Webservice token: " + token.ToString());
            }
            catch (Exception ex)
            {
                textBoxResult.AppendText("Exception while getting service-token: " + ex);
                return;
            }

            try
            {
                // Execute WS call
                textBoxResult.AppendText("Calling webservice...\n");
                var res = TokenUtil.ExecuteWS(selectedCert, textBoxServiceUrl.Text, token);
                textBoxResult.AppendText("Webservice result: " + res);
            }
            catch (Exception ex)
            {
                textBoxResult.AppendText("Exception while calling webservice: " + ex);
                return;
            }
        }

        private void Window_Initialized(object sender, EventArgs e)
        {
            
 
        }
    }
}
