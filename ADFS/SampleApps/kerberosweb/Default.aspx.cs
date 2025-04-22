using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Security.Principal;

public partial class _Default : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        if (!IsPostBack)
        {

            string idName = User.Identity.Name.ToString();

            lableWindowsIdentity.Text = WindowsIdentity.GetCurrent().Name.ToString();
            labelisAuthenticated.Text = WindowsIdentity.GetCurrent().IsAuthenticated.ToString();
            labelImpersonation.Text = WindowsIdentity.GetCurrent().ImpersonationLevel.ToString();

            //labelAuthenticationType.Text = WindowsIdentity.GetCurrent().AuthenticationType.ToString();
            labelAuthenticationType.Text = User.Identity.AuthenticationType.ToString();
            labelToken.Text = WindowsIdentity.GetCurrent().Token.ToString();


            labelThreaIdentity.Text = System.Threading.Thread.CurrentPrincipal.Identity.Name.ToString();



        }

    }
}
