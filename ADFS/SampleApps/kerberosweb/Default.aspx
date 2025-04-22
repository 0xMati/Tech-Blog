<%@ Page Title="Home Page" Language="C#" MasterPageFile="~/Site.master" AutoEventWireup="true"
    CodeFile="Default.aspx.cs" Inherits="_Default" %>

<asp:Content ID="HeaderContent" runat="server" ContentPlaceHolderID="HeadContent">
</asp:Content>
<asp:Content ID="BodyContent" runat="server" ContentPlaceHolderID="MainContent">
    <h2>
        Welcome to Kerberos Web!
    </h2>
   
   <asp:Table ID="Table1" runat="server">
        <asp:TableHeaderRow>
            <asp:TableCell> Object </asp:TableCell>
            <asp:TableCell> Value</asp:TableCell>
        </asp:TableHeaderRow>

        <asp:TableRow>
            <asp:TableCell> Windows Identity </asp:TableCell>
            <asp:TableCell> 
                <asp:Label ID="lableWindowsIdentity" runat="server"></asp:Label></asp:TableCell>
        </asp:TableRow>

         <asp:TableRow>
            <asp:TableCell> IsAuthenticated </asp:TableCell>
            <asp:TableCell> 
                <asp:Label ID="labelisAuthenticated" runat="server"></asp:Label></asp:TableCell>
        </asp:TableRow>

        
        <asp:TableRow>
            <asp:TableCell> ImpersonationLevel </asp:TableCell>
            <asp:TableCell> 
                <asp:Label ID="labelImpersonation" runat="server"></asp:Label></asp:TableCell>
        </asp:TableRow>

        <asp:TableRow>
                <asp:TableCell> Thread Identity</asp:TableCell>
                <asp:TableCell> 
                    <asp:Label ID="labelThreaIdentity" runat="server"></asp:Label>
                    </asp:TableCell>
        </asp:TableRow>


         <asp:TableRow>
                <asp:TableCell> Autorization Data</asp:TableCell>
                <asp:TableCell> 
                    <asp:Label ID="labelAutorizationData" runat="server"></asp:Label>
                    </asp:TableCell>
        </asp:TableRow>
       
        <asp:TableRow>
                <asp:TableCell>AuthenticationType</asp:TableCell>
                <asp:TableCell> 
                    <asp:Label ID="labelAuthenticationType" runat="server"></asp:Label>
                    </asp:TableCell>
        </asp:TableRow>

        
        <asp:TableRow>
                <asp:TableCell>Token</asp:TableCell>
                <asp:TableCell> 
                    <asp:Label ID="labelToken" runat="server"></asp:Label>
                    </asp:TableCell>
        </asp:TableRow>

        

       

    </asp:Table>




   


</asp:Content>
