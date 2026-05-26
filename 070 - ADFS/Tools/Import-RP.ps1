# Load the ADFS PowerShell snap-in
#Add-PSSnapin Microsoft.Adfs.PowerShell
$fileEntries = [IO.Directory]::GetFiles("c:\ADFS\ADFS-RP-Output\"); 
foreach($fileName in $fileEntries) 
{ 
  $ADFSRelyingPartyTrust = Import-clixml $fileName
$IdentiferArray = $ADFSRelyingPartyTrust.Identifier
$Identifier = $IdentiferArray[0]
  $NewADFSRelyingPartyTrust = Add-ADFSRelyingPartyTrust -Identifier $Identifier `
    -Name $ADFSRelyingPartyTrust.Name
  $IdentifierUri = $Identifier

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -AutoUpdateEnabled $ADFSRelyingPartyTrust.AutoUpdateEnabled

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -DelegationAuthorizationRules $ADFSRelyingPartyTrust.DelegationAuthorizationRules

  # note we need to do a ToString to not just get the enum number
  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -EncryptionCertificateRevocationCheck `
    $ADFSRelyingPartyTrust.EncryptionCertificateRevocationCheck.ToString()

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
-IssuanceAuthorizationRules $ADFSRelyingPartyTrust.IssuanceAuthorizationRules

  # note we need to do a ToString to not just get the enum number
  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -SigningCertificateRevocationCheck `
    $ADFSRelyingPartyTrust.SigningCertificateRevocationCheck.ToString()

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -WSFedEndpoint $ADFSRelyingPartyTrust.WSFedEndpoint

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -IssuanceTransformRules $ADFSRelyingPartyTrust.IssuanceTransformRules

 # Note ClaimAccepted vs ClaimsAccepted (plural)
 # Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
 #   -ClaimAccepted $ADFSRelyingPartyTrust.ClaimsAccepted

  ### NOTE this does not get imported
  #$ADFSRelyingPartyTrust.ConflictWithPublishedPolicy

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -EncryptClaims $ADFSRelyingPartyTrust.EncryptClaims

  ### NOTE this does not get imported
  #$ADFSRelyingPartyTrust.Enabled

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -EncryptionCertificate $ADFSRelyingPartyTrust.EncryptionCertificate

  # Identifier is actually an array but you can't add it when 
  #   using Set-ADFSRelyingPartyTrust -TargetIdentifier 
  #   so we use -TargetRelyingParty instead
  $targetADFSRelyingPartyTrust = Get-ADFSRelyingPartyTrust -Identifier $Identifier
  Set-ADFSRelyingPartyTrust -TargetRelyingParty $targetADFSRelyingPartyTrust `
    -Identifier $ADFSRelyingPartyTrust.Identifier

  # SKIP we don't need to import these
  # $ADFSRelyingPartyTrust.LastMonitoredTime
  # $ADFSRelyingPartyTrust.LastPublishedPolicyCheckSuccessful
  # $ADFSRelyingPartyTrust.LastUpdateTime

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -MetadataUrl $ADFSRelyingPartyTrust.MetadataUrl

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -MonitoringEnabled $ADFSRelyingPartyTrust.MonitoringEnabled

  # Name is already done
  #Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
  #  -Name $ADFSRelyingPartyTrust.Name

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -NotBeforeSkew $ADFSRelyingPartyTrust.NotBeforeSkew

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -Notes "$ADFSRelyingPartyTrust.Notes"

  ### NOTE this does not get imported
  #$ADFSRelyingPartyTrust.OrganizationInfo

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -ImpersonationAuthorizationRules $ADFSRelyingPartyTrust.ImpersonationAuthorizationRules

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -ProtocolProfile $ADFSRelyingPartyTrust.ProtocolProfile

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -RequestSigningCertificate $ADFSRelyingPartyTrust.RequestSigningCertificate

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -EncryptedNameIdRequired $ADFSRelyingPartyTrust.EncryptedNameIdRequired

  # Note RequireSignedSamlRequests vs SignedSamlRequestsRequired, 
  #Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
  #  -RequireSignedSamlRequests $ADFSRelyingPartyTrust.SignedSamlRequestsRequired  
  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -SignedSamlRequestsRequired $ADFSRelyingPartyTrust.SignedSamlRequestsRequired  

  # Note SamlEndpoint vs SamlEndpoints (plural)
  # The object comes back as a 
  #   [Deserialized.Microsoft.IdentityServer.PowerShell.Resources.SamlEndpoint]
  #   so we will reconstitute 

  # create a new empty array
  $newSamlEndPoints = @()
  foreach ($SamlEndpoint in $ADFSRelyingPartyTrust.SamlEndpoints)
  {
    # Is ResponseLocation defined?
    if ($SamlEndpoint.ResponseLocation)
    {
      # ResponseLocation is not null or empty
      $newSamlEndPoint = New-ADFSSamlEndpoint -Binding $SamlEndpoint.Binding `
        -Protocol $SamlEndpoint.Protocol `
        -Uri $SamlEndpoint.Location -Index $SamlEndpoint.Index `
        -IsDefault $SamlEndpoint.IsDefault
    }
    else
    {  
      $newSamlEndPoint = New-ADFSSamlEndpoint -Binding $SamlEndpoint.Binding `
        -Protocol $SamlEndpoint.Protocol `
        -Uri $SamlEndpoint.Location -Index $SamlEndpoint.Index `
        -IsDefault $SamlEndpoint.IsDefault `
        -ResponseUri $SamlEndpoint.ResponseLocation
    }
    $newSamlEndPoints += $newSamlEndPoint
  }
  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -SamlEndpoint $newSamlEndPoints

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -SamlResponseSignature $ADFSRelyingPartyTrust.SamlResponseSignature

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -SignatureAlgorithm $ADFSRelyingPartyTrust.SignatureAlgorithm

  Set-ADFSRelyingPartyTrust -TargetIdentifier $Identifier `
    -TokenLifetime $ADFSRelyingPartyTrust.TokenLifetime

}

# For comparison testing you can uncomment these lines 
#   to export your new import as a ___.XML.new file
# $targetADFSRelyingPartyTrust = Get-ADFSRelyingPartyTrust -Identifier $Identifier
# $filePath = $xmlFile + ".new"
# $AdfsRelyingPartyTrust | Export-Clixml $filePath