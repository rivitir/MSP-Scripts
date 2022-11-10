<#
This script will download the latest GA release of S1 and install it to the proper client in S1 based on the org name in NinjaRMM and uses the org name environment variable to grab this.
NOTE: The Ninja Org name is used as the Site in SentinelOne THESE MUST MATCH to run successfully.
#>


#Your Variables - Update these to your settings.
$sentinelOneBaseURL = "YOUR_S1_BASE_URL"
$sentinelOneApiKey = "YOUR_API_KEY_GOES_HERE"

#Ignore SSL Errors
add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
$AllProtocols = ([System.Net.SecurityProtocolType]).DeclaredMembers |where-object {'Ssl3','Tls','Tls11','Tls12' -contains $_.Name} | Select-Object -ExpandProperty Name
if($AllProtocols -eq $null)
{
  $AllProtocols = [System.Net.SecurityProtocolType]'Ssl3,Tls'
}
[System.Net.ServicePointManager]::SecurityProtocol = $AllProtocols
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


#get the ninja Org name, massage as necessary to match S1 Site names
$customer = $env:NINJA_ORGANIZATION_NAME


#determine the bit-ness of the OS
if([Environment]::Is64BitOperatingSystem) {
	$arch = "64 bit"    
} else {
	$arch = "32 bit"    
}

#get the site
Add-Type -AssemblyName System.Web
$safecustomer=[System.Web.HTTPUtility]::UrlEncode($customer)
$uri = $sentinelOneBaseURL + "/sites?name=" + $safecustomer
$headers=@{}
$headers.Add("Authorization", "ApiToken $sentinelOneApiKey")
$response = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers -UseBasicParsing
$siteId = (($response.Content | ConvertFrom-Json)).data.sites[0].id
Write-Output "Site Id: $siteId"

#Use Default Group & grab its token
$uri = $sentinelOneBaseURL + "/groups?siteIds=" + $siteId + "&name=Default%20Group"
$headers=@{}
$headers.Add("Authorization", "ApiToken $sentinelOneApiKey")
$response = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers -UseBasicParsing
$groupToken = (($response.Content | ConvertFrom-Json)).data[0].registrationToken
Write-Output "Group Token: $groupToken"

#get the installer path for the most recent GA release
$uri = $sentinelOneBaseURL + '/update/agent/packages?osTypes=windows&fileExtension=.msi&sortBy=version&sortOrder=desc&limit=1&status=ga&osArches=' + $arch
$headers=@{}
$headers.Add("Authorization", "ApiToken $sentinelOneApiKey")
$response = Invoke-WebRequest -Uri $uri -Method GET -Headers $headers -UseBasicParsing
$download = (($response.Content | ConvertFrom-Json)).data[0].link
Write-Output "Download path: $download"

#download the intaller to $env:TEMP directory
$path = "$env:TEMP"
$headers=@{}
$headers.Add("Authorization", "ApiToken $sentinelOneApiKey")
Invoke-WebRequest -Uri $download -Headers $headers -OutFile "$path\SentinelOne.msi"


#Install
$MSIArguments = @(
    "/i"
    ('"{0}"' -f "$path\SentinelOne.msi")
    ('/l* "{0}"' -f "$path\s1-log.txt")
    "/q"
    "/NORESTART"
    ('SITE_TOKEN="{0}"' -f "$groupToken")
)
Start-Process "msiexec.exe" -ArgumentList $MSIArguments -Wait -NoNewWindow 

#cleanup
Remove-Item "$path\SentinelOne.msi" -Force