<%@ Page Title="" Language="C#" MasterPageFile="~/Site.master" AutoEventWireup="true" CodeFile="Impersonate.aspx.cs" Inherits="Impersonate" %>
<%@ Register Assembly="RichTextEditor" Namespace="AjaxControls" TagPrefix="cc1" %>

<asp:Content ID="Content1" ContentPlaceHolderID="HeadContent" Runat="Server">
</asp:Content>
<asp:Content ID="Content2" ContentPlaceHolderID="MainContent" Runat="Server">
<div>
    <asp:Label ID="labelStatus" runat="server" ForeColor="Red" Font-Bold="True"></asp:Label>
</div>

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

         <asp:TableRow>
                <asp:TableCell>File Path</asp:TableCell>
                <asp:TableCell> 
                    <asp:Label ID="labelFilePath" runat="server"></asp:Label>
                    </asp:TableCell>
        </asp:TableRow>
    </asp:Table>
    <cc1:RichTextEditor ID="Rte1" Theme="Blue"  runat="server" Height="200px" Visible="False" />  

    <asp:Button ID="Button1" runat="server" Text="Save" onclick="Button1_Click" Visible="False"  />

</asp:Content>

