Add-PSSnapin Microsoft.Adfs.PowerShell

$filePathBase = "C:\ADFS\ADFS-RP-Output\"
mkdir $filePathBase

$AdfsRelyingPartyTrusts = Get-AdfsRelyingPartyTrust
foreach ($AdfsRelyingPartyTrust in $AdfsRelyingPartyTrusts)
{
  $fileNameSafeIdentifier = $AdfsRelyingPartyTrust.Name.ToString()
  $filePath = $filePathBase + $fileNameSafeIdentifier + '.xml'
  $AdfsRelyingPartyTrust | Export-Clixml $filePath

}