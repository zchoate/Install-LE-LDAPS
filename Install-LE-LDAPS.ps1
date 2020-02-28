<#
.SYNOPSIS
    .
.DESCRIPTION
    
.PARAMETER LEserver
    Set this to LE_STAGE for testing
    Set this to LE_PROD for production
.PARAMETER domain
    Set this to the FQDN for AADDS - ad.contoso.com
    Don't specify anything other than the FQDN of the domain.
    Wildcard certificate will be issued for this domain but is handled by the script.
.PARAMETER contact
    Set this to the contact email for certificate related notifications
.PARAMETER dnsProvider
    Set this to Azure, Cloudflare, or GoDaddy
    This can support other providers but the script should be extended appropriately
    Azure will require the context this script is run under to have permission to modify the DNS Zone.
        dnsApiId and dnsApiSecret don't need to be set in this case.
    Cloudflare only supports Global API key as the API token feature appears to be broken on Cloudflare
    GoDaddy only has an option to create a key/secret
.PARAMETER dnsParameter1
    Azure - update this
    Cloudflare - Cloudflare zone edit token
    GoDaddy - API key here
.PARAMETER dnsParameter2
    Azure - update this
    Cloudflare - Cloudflare all zone read token
    GoDaddy - API secret here
.NOTES
    Version:         0.1
    Author:          Zachary Choate
    Creation Date:   02/26/2020
    URL:             
#>
param(
    [string] $LEserver,
    [string] $domain,
    [string] $contact,
    [string] $dnsProvider,
    [string] $dnsParameter1,
    [string] $dnsParameter2
)

$paServer = $LEserver
$wildcardDomain = "*.$domain"

If($dnsProvider -eq "GoDaddy") {
    $dnsArguments = @{GDKey=$dnsParameter1;GDSecret=$dnsParameter2}
} elseif ($dnsProvider -eq "Cloudflare") {
    $dnsArguments = @{ CFTokenInsecure = $dnsParameter1 }
    $dnsArguments.CFTokenReadAllInsecure = $dnsParameter2
} elseif ($dnsProvider -eq "Azure") {
    $dnsArguments = @{AZSubscriptionId=$context.Subscription.Id;AZAccessToken=$accessToken}
} else { Write-Output "There isn't a supported DNS provider selected. Please choose from Azure, Cloudflare, or GoDaddy. If you need another configured, please modify the script appropriately."}

## Check for Posh-ACME module
If(!(Get-Module -ListAvailable -Name "Posh-ACME")) {
    Write-Output "Install Posh-ACME module by running the command Install-Module Posh-ACME."
    Exit
} 

## Import Posh-ACME module
Import-Module -Name Posh-ACME
# Set server (staging or prod)
Set-PAServer $paServer

# Get current account, update contact if account has been updated, or create a new account.
$acct = Get-PAAccount
If(-not $acct) {
    $acct = New-PAAccount -Contact $contact -KeyLength 4096 -AcceptTOS
} elseif ($acct.contact -ne "mailto:$contact") {
    Set-PAAccount -id $acct.id -Contact $contact
}

# See if there's been an order created
$paOrder = Get-PAOrder -MainDomain $wildcardDomain

If(-not $paOrder) {
    # Run request for new certificate
    $certificate = New-PACertificate $wildcardDomain,$domain -DnsPlugin $dnsProvider -PluginArgs $dnsArguments -AcceptTOS -Contact $contact -Install -Verbose
} else {
    # Insert request for renewal of certificate
    Set-PAOrder -MainDomain $wildcardDomain -DnsPlugin $dnsProvider -PluginArgs $dnsArguments -Install -Verbose 
    $certificate = Submit-Renewal -Verbose -Force
}

$thumbprint = $certificate.Thumbprint
$copyParameters = @{
    'Path' = "HKLM:\Software\Microsoft\SystemCertificates\MY\Certificates\$thumbprint"
    'Destination' = "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\$thumbprint"
    'Recurse' = $true
}
If(!(Test-Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates")) {
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates" -Force
    }
Copy-Item @copyParameters

"dn:
changetype: modify
add: renewServerCertificate
renewServerCertificate: 1
-" | Out-File -FilePath $env:TEMP\ldap-reload.txt

Start-Process ldifde -ArgumentList "-i -f $env:Temp\ldap-reload.txt"