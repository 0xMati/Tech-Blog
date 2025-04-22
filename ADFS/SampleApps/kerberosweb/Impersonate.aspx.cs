using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Security.Principal;
using System.IO;
using System.Threading;

public partial class Impersonate : System.Web.UI.Page
{
    protected void Page_Load(object sender, EventArgs e)
    {
        Page.Form.Attributes.Add("onSubmit", "CopyText(); return true;");
        if (!IsPostBack)
        {


            string upn = User.Identity.Name;
            if (User.Identity.Name.Contains('\\'))
            {
                string[] upnarray = User.Identity.Name.Split('\\');
                if (upnarray.Length == 2)
                {
                    upn = upnarray[1] + "@" + upnarray[0] + ".com";
                }
            }


            wi = new WindowsIdentity(upn);
            //wi = new WindowsIdentity("administrator@contoso.com");

            using (WindowsImpersonationContext wicx = wi.Impersonate())
            {
                string idName = User.Identity.Name.ToString();

                labelFilePath.Text = path;
                lableWindowsIdentity.Text = WindowsIdentity.GetCurrent().Name.ToString();
                labelisAuthenticated.Text = WindowsIdentity.GetCurrent().IsAuthenticated.ToString();
                labelImpersonation.Text = WindowsIdentity.GetCurrent().ImpersonationLevel.ToString();

                labelAuthenticationType.Text = WindowsIdentity.GetCurrent().AuthenticationType.ToString();
                labelToken.Text = WindowsIdentity.GetCurrent().Token.ToString();
                labelThreaIdentity.Text = Thread.CurrentPrincipal.Identity.Name.ToString();

                try
                {
                    StreamReader sr;
                    sr = File.OpenText(path);
                    String content = sr.ReadToEnd();
                    //Response.Write("Remote File Content:" + content);
                    sr.Close();

                    Rte1.Visible = true;
                    Rte1.Text = content;
                    Button1.Visible = true;
                }
                catch (Exception ecex)
                {
                    labelStatus.Visible = true;
                    labelStatus.Text = "Error Saving File <br> " + ecex.ToString();
                }
            }
        }

    }

    public WindowsIdentity wi { get; set; }
    //string path = "C:\\local\\remote.txt";
    string path = "\\\\contosodc\\share\\remote.txt";
    protected void Button1_Click(object sender, EventArgs e)
    {
        string upn = User.Identity.Name;
        if (User.Identity.Name.Contains('\\'))
        {
            string[] upnarray = User.Identity.Name.Split('\\');
            if (upnarray.Length == 2)
            {
                upn = upnarray[1] + "@" + upnarray[0] + ".com";
            }
        }


        wi = new WindowsIdentity(upn);
        //wi = new WindowsIdentity("administrator@contoso.com");

        using (WindowsImpersonationContext wicx = wi.Impersonate())
        {
            try
            {
                using (StreamWriter writer = new StreamWriter(path))
                {
                    writer.Write(Rte1.Text);
                }
            }
            catch (Exception ecex)
            {
                labelStatus.Visible = true;
                labelStatus.Text = "Error Saving File <br> " + ecex.ToString();
            }

        }
    }
}