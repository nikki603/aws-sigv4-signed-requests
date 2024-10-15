<#  
   .Synopsis
     Retrieves the current Universal time in required format for AWS
#>
function UniversalTime{
    $curdate = Get-Date
    $UniversalTime = ($curdate.ToUniversalTime().Year).ToString("0000") `
    + ($curdate.ToUniversalTime().Month).ToString("00") `
    + ($curdate.ToUniversalTime().Day).ToString("00") + "T" `
    + ($curdate.ToUniversalTime().Hour).ToString("00") `
    + ($curdate.ToUniversalTime().Minute).ToString("00") `
    + ($curdate.ToUniversalTime().Second).ToString("00") + "Z"
 
    return $UniversalTime
 }
 
<#  
   .Synopsis
     Retrieves the current Universal time in short-date format used by AWS
#>
function ShortDate{
 
    $curdate = Get-Date
    $Shortdate = ($curdate.ToUniversalTime().Year).ToString("0000") `
    + ($curdate.ToUniversalTime().Month).ToString("00") `
    + ($curdate.ToUniversalTime().Day).ToString("00") 
 
    return $Shortdate
 }
 
 
<#  
   .Synopsis
     Retrieves an SHA hash of a string as required by AWS Signature 4 
#>
 
function sha($message) {
    $sha256 = new-object -TypeName System.Security.Cryptography.SHA256Managed
    $utf8   = new-object -TypeName System.Text.UTF8Encoding
    $hash   = [System.BitConverter]::ToString($sha256.ComputeHash($utf8.GetBytes($message)))
    return $hash.replace('-','').toLower()
}
 
<#  
   .Synopsis
     HMACSHA256 signing function used in the construction of a "Signature 4 " request
#>
function hmacSHA256([byte[]]$key, [string]$message) {
   $hmacsha = New-Object System.Security.Cryptography.HMACSHA256
   $hmacsha.key = $key
   return $hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($message))
}
 
<#  
   .Synopsis
    The AWS Signature version 4 creation routine
#>
function GetSignatureKey([String]$AWSAccessKey,[String]$shortdate,[String]$AWSRegion,[String]$AWSService){
   $kSecret            = [System.Text.Encoding]::UTF8.GetBytes("AWS4"+$AWSAccessKey)
   $kDate              = hmacSHA256 $kSecret $shortdate 
   $kRegion            = hmacSHA256 $kDate $AWSRegion 
   $kService           = hmacSHA256 $kRegion $AWSService 
   $kSigningKey        = hmacSHA256 $kService "aws4_request" 
   return $kSigningKey
}
 
###########
# Main
# Used for constructing requests for the AWS OpenSearch
###########
 <#
  .Synopsis
    Submits a signed request to the AWS OpenSearch and retrieves the results
 
   .Description
    This function demonstrates using PowerShell to submit REST based requests to 
    Amazon's AWS OpenSearch using Signature 4 signing.
 
    The examples show the use of the AWS signature version 4.
 
   .Example
    Get-WebResponse -Method POST `
                -EndpointURI "https://search.myopensearch.com/my-index" `
                -AWSAccessID "MyAccessID" `
                -AWSAccessKey "MySecRetAccEssKey" `
                -AWSToken "MySessionToken" `
                -Region "us-east-1" `
                -Payload $ExamplePayload 
   .Example
    Get-WebResponse -Method "GET" `
                -EndpointURI "https://search.myopensearch.com/_cat/indices" `
                -AWSAccessID "MyAccessID" `
                -AWSAccessKey "MySecRetAccEssKey" `
                -AWSToken "MySessionToken" `
                -Region "us-east-1"
 
 
   .Parameter EndpointURI
      The Fully Qualified endpoint URL
   .Parameter AWSAccessID 
      The Access Key ID  
   .Parameter AWSAccessKey 
      The secret Access Key ID
   .Parameter AWSToken 
      The session token 
   .Parameter Region 
      AWS Region  
   .Parameter Payload 
      A text string representing the body or payload of the request - typically JSON
 #>
function Get-WebResponse{
[CmdletBinding()]
param(
      [Parameter(Mandatory = $true,
		          Position = 0,
                  HelpMessage="The method of web request such as POST, GET")]
      [string]
      [ValidateNotNullOrEmpty()]
      $Method,
 
      [Parameter(Mandatory = $true,
		           Position = 1,
                   HelpMessage="AWS endpoint URI to query")]
      [string]
      [ValidateNotNullOrEmpty()]
      $EndpointURI,
 
      [Parameter(Mandatory = $true,
		           Position = 2,
                   HelpMessage="AWS Access Key ID")]
      [string]
      [ValidateNotNullOrEmpty()]
      $AWSAccessID,
 
      [Parameter(Mandatory = $true,
		           Position = 3,
                   HelpMessage="AWS Secret Access Key")]
      [string]
      [ValidateNotNullOrEmpty()]
      $AWSAccessKey,

      [Parameter(Mandatory = $true,
		           Position = 4,
                   HelpMessage="AWS Session Token")]
      [string]
      [ValidateNotNullOrEmpty()]
      $AWSToken,

      [Parameter(Mandatory = $true,
		           Position = 5,
                   HelpMessage="AWS Region")]
      [string]
      [ValidateNotNullOrEmpty()]
      $Region,
 
      [Parameter(Mandatory = $false,
		           Position = 6,
                   HelpMessage="The Payload / Body of a request")]
      [string]
      $Payload = ""
 
) #end param
 
 
$EndpointURI = $EndpointURI.replace("https://","")

$AWSService       = "es"
$AWSRegion        = $Region
 
#Process query string if exists
if ($EndpointURI.Contains("?")){
   $URIParams      = $EndpointURI.Substring(($EndpointURI.IndexOf("/")),($EndpointURI.Length -$EndpointURI.IndexOf("/") ))
   $CanonicalURI   = $URIParams.Substring(0,($URIParams.IndexOf("?") ))
   $CanonicalQuery = ($URIParams.Substring(($URIParams.IndexOf("?")),($URIParams.Length -$URIParams.IndexOf("?") ))).Replace("?","")
   $CanonicalQuery = $CanonicalQuery.Replace("=","%3D")
   $CanonicalQuery = $CanonicalQuery.Replace("&","%26") 
}
else
{
  $CanonicalURI    = $EndpointURI.Substring(($EndpointURI.IndexOf("/")),($EndpointURI.Length -$EndpointURI.IndexOf("/") ))
}

$shortdate      = Shortdate
$universaltime  = UniversalTime
$PayloadBytes   = ([System.Text.Encoding]::UTF8.GetBytes($Payload)).Length 
$fullHostname   = $EndpointURI.Substring(0,($EndpointURI.IndexOf("/")))
$URI            =  "https://$($fullHostname)$($CanonicalURI)"

write-host "AWSAccessID      = $($AWSAccessID)"  
write-host "AWSAccessKey     = $($AWSAccessKey)"
write-host "AWSToken         = $($AWSToken)"         
write-host "AWSService       = $($AWSService)"           
write-host "AWSRegion        = $($AWSRegion)"           
write-host "CanonicalURI     = $($CanonicalURI)"        
write-host "CanonicalQuery   = $($CanonicalQuery)"      
write-host "RequestMethod    = $($Method)"
write-host "URI              = $($URI)"
write-host "PayloadBytes     = $($PayloadBytes)"
 
############################################
#  Create the Canonical Request
############################################
 
$CanonicalRequest = "" 
$CanonicalRequest = $Method +"`n"
$CanonicalRequest = $CanonicalRequest + $CanonicalURI +"`n"
if(!$CanonicalQuery){ #no query string
    $CanonicalRequest = $CanonicalRequest + $CanonicalQuery  +"`n"
}
else #query string exists
{
    $CanonicalQuery = $CanonicalQuery.Replace("=","%3D")
    $CanonicalQuery = $CanonicalQuery.Replace("&","%26")
    $CanonicalRequest = $CanonicalRequest + $CanonicalQuery +"=" +"`n"
}

############################################
#  Canonical Headers and values
############################################

$CanonicalHeaderHashTable = @{} 
$CanonicalHeaderHashTable.Add("host",$fullHostname)
$CanonicalHeaderHashTable.Add("x-amz-date",$universaltime)
$CanonicalHeaderHashTable.Add("x-amz-security-token",$AWSToken)

if($PayloadBytes -ne 0){
    write-host "Payload received"
    $CanonicalHeaderHashTable.Add("content-length",$($PayloadBytes))
    $CanonicalHeaderHashTable.Add("content-type","application/json")
}
 
$CanonicalHeaderHashTable.GetEnumerator() | Sort-Object Name | % {
    [string]$newheader = ""
    $newheader = ($_.Key) +":" + $_.Value 
    $newheader = $newheader.Trim()
    $newheader = $newheader.Replace("`r","")
    $CanonicalRequest = $CanonicalRequest + $newheader +"`n"
    }
 
$CanonicalRequest = $CanonicalRequest +"`n"
 
#Each key from the Canonical Header HashTable needs to be listed
[System.Collections.ArrayList]$SignedHeadersArray = @()

$CanonicalHeaderHashTable.GetEnumerator() | Sort-Object Name | % {
        $null = $SignedHeadersArray.Add($_.Key)
    }

$SignedHeadersList = ($SignedHeadersArray -join ";") 
$CanonicalRequest = $CanonicalRequest + $SignedHeadersList +"`n"

$CanonicalRequest = $CanonicalRequest + $(sha $Payload) 

############################################
#  Create the Signed String
############################################

# Add Algorithm
$Signedstring = "AWS4-HMAC-SHA256" +"`n"
#  Add UTC Request Date
$Signedstring = $Signedstring +$universaltime + "`n"
#  Add CredentialScope
$Signedstring = $Signedstring +    "$($shortdate)/$($AWSRegion)/$($AWSService)/aws4_request" + "`n"
#  Add Canonical Request Hash
$Signedstring = $Signedstring + $(sha $CanonicalRequest)# +"`n"
 
############################################
#  Sign the Signed String
############################################
 
$kSigningKey = GetSignatureKey $AWSAccessKey $shortdate $AWSRegion $AWSService
$encSignedString    = hmacSHA256 $kSigningKey $Signedstring 
[string]$hexstring = [System.BitConverter]::ToString($encSignedString )
$signature = $hexstring.replace("-","")
$signature = $signature.ToLower()
 

############################################
#  Add Headers for web request
############################################

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Clear()
 
$CanonicalHeaderHashTable.GetEnumerator() | Sort-Object Name | % {
    if($_.Key -eq "host"){
        # do nothing
    }
    else{ 
        $headers.Add(($_.Key),($_.value)) 
    }
    }

$headers.Add("authorization", "AWS4-HMAC-SHA256 Credential=$($AWSAccessID)/$($shortdate)/$($AWSRegion)/$($AWSService)/aws4_request, SignedHeaders=$($SignedHeadersList), Signature=$($signature)")

$headers.GetEnumerator() | % {
    write-host $_.Key
    write-host $_.value
}    

if($PayloadBytes -ne 0){
    $Result = Invoke-RestMethod -Uri $URI -Body $Payload -Method $Method -Headers $Headers -SkipHeaderValidation
} else {
    $endpoint = ""
    if(!$CanonicalQuery) {
        $endpoint = "$($URI)"
    }
    else {
        $endpoint = "$($URI)?$($CanonicalQuery)"
    }
    write-host $CanonicalQuery
    write-host $endpoint
    write-host $headers
    $Result = Invoke-RestMethod -Uri $endpoint -Method $Method -SkipHeaderValidation -Headers $headers 
}
 
write-host ($Result | ConvertTo-Json -Depth 100)
return $Result
}


Import-Module AWSPowerShell.NetCore -DisableNameChecking

$region = "us-east-1"
$roleArn = "arn:aws:iam::1234567890:role/myuser"
$index = "test-index-01"

# Assume the IAM role
$sts = Get-STSCallerIdentity -Region $region
Write-Host ($sts | ConvertTo-Json)
$creds = (Use-STSRole -RoleArn $roleArn -RoleSessionName "OpenSearchSession").Credentials
Write-Host ($creds | ConvertTo-Json)

# Extract the temporary IAM credentials from the response
$accessKeyId = $creds.AccessKeyId
$secretKey = $creds.SecretAccessKey
$sessionToken = $creds.SessionToken


# Add document to index
$requestBody = @{
    name  = 'blueberry'
    color = 'blue'
}
$jsonString = $requestBody | ConvertTo-Json -Depth 100 -Compress
Get-WebResponse -Method "POST" `
                -EndpointURI "https://search.myopensearch.com/$($index)/_doc" `
                -AWSAccessID $accessKeyId `
                -AWSAccessKey $secretKey `
                -AWSToken $sessionToken `
                -Region $region `
                -Payload $jsonString

# Search index documents
$requestBody = @{
    query = @{
        match = @{
            color = "blue"
        }
    }
}

$jsonString = $requestBody | ConvertTo-Json -Depth 100 -Compress
Get-WebResponse -Method "GET" `
                -EndpointURI "https://search.myopensearch.com/$($index)/_search" `
                -AWSAccessID $accessKeyId `
                -AWSAccessKey $secretKey `
                -AWSToken $sessionToken `
                -Region $region `
                -Payload $jsonString
