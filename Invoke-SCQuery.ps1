################################################################################################################################
# Author: JD Crandell ## Version 2.0 #
################################################################################################################################
# References: https://docs.tenable.com/sccv/api/index.html
################################################################################################################################

function New-SecurityCenterToken{
    <#
    .Synopsis
       Establishes a connection to Security Center
    #>

    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP = $SecurityCenterIP,
    [System.Management.Automation.PSCredential]$Credential = $Credential
    )

     ## Ignores the fact that server is using a self-signed certificate.
     if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
    $certCallback = @"
        using System;
        using System.Net;
        using System.Net.Security;
        using System.Security.Cryptography.X509Certificates;
        public class ServerCertificateValidationCallback
        {
            public static void Ignore()
            {
                if(ServicePointManager.ServerCertificateValidationCallback ==null)
                {
                    ServicePointManager.ServerCertificateValidationCallback += 
                        delegate
                        (
                            Object obj, 
                            X509Certificate certificate, 
                            X509Chain chain, 
                            SslPolicyErrors errors
                        )
                        {
                            return true;
                        };
                }
            }
        }
"@ 

    Add-Type $certCallback
    }
    [ServerCertificateValidationCallback]::Ignore()
 



    $Login = New-Object PSObject 
    $Login | Add-Member -MemberType NoteProperty -Name username -Value ($Credential.UserName) 
    $Login | Add-member -MemberType Noteproperty -Name password -Value ($Credential.GetNetworkCredential().password) 
    $Data = (ConvertTo-Json -compress $Login) 


    # Login to SC5 
    $ret = Invoke-WebRequest -URI https://$SecurityCenterIP/rest/token -Method POST -Body $Data -UseBasicParsing -SessionVariable sv
    # extract the token 
    $token = (convertfrom-json $ret.Content).response.token   
    $SessionAndToken = @($sv,$token) 
    $SessionAndToken
}

################################################################################################################################

function Get-ScanSeverities {
    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token  
    ) 

        # Create the objects to be used for the query
    # Create the vulnId object with and embed the filter object
    [PSCustomObject]$vulnId = [ordered]@{
    name                = ""
    description         = ""
    context             ="analysis"
    status              = "-1"
    createdTime         = "0"
    modifiedTime        = "0"
    groups              = @()
    tags                = ""
    type                = "vuln"
    tool                = "sumseverity"
    sourceType          = "cumulative"
    startOffset         = "0"
    endOffset           = "10000"    
    filters             = @()
    vulnTool            = "sumseverity"
    }

    # Create the vulnType object that will be converted to json.
    [PSCustomObject]$vulnType = [ordered]@{
    query               = ($vulnId)
    sourceType          = "cumulative"
    type                = "vuln"
    }


    # Convert the object to JSON using depth of 4...
    # Convertto-Json uses a default depth of 2 and will not create proper json formatted information for the webserver to parse.
    $jsonVulnType = ConvertTo-Json $vulnType -Depth 4 

    # Run the query and convert the results to PSObject.
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/analysis" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Body $jsonVulnType -Websession $sv -Method Post 
    $jsonContent = $ret.content
    $response = ConvertFrom-Json $jsonContent 

    [PSCustomObject]$severityArray = [ordered]@{
    Critical            = ($response.response.results[0].count)
    High                = ($response.response.results[1].count)
    Medium              = ($response.response.results[2].count)
    Low                 = ($response.response.results[3].count)
    Info                = ($response.response.results[4].count)
    }

    return $severityArray
}

################################################################################################################################

function Remove-Query {
    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token,
    [System.Int32]$QueryID = $DeleteQueryId
    ) 

    # Delete the query
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/query/$QueryID" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Websession $sv -Method Delete
    $jsonContent = $ret.content
    $response = ConvertFrom-Json $jsonContent 
    return $response.response
}

################################################################################################################################

function Get-QuerySyntaxJson {
    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token,
    [System.Int32]$QueryID = $QueryID
    ) 

    # Get the query
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/query/$QueryID" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Websession $sv -Method Get
    $jsonContent = $ret.content | ConvertFrom-Json | ConvertTo-Json -Depth 10
    return $jsonContent
}

################################################################################################################################

function Get-Queries {
    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token
    ) 


    # Get the query
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/query" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Websession $sv -Method Get
    $jsonContent = $ret.content
    $response = ConvertFrom-Json $jsonContent 
    $results = $response.response.usable | Format-Table id,name,tool,type
    return $results
}

################################################################################################################################

function Remove-SecurityCenterToken {
    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token
    ) 

    # Delete the token
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/token" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Websession $sv -Method Delete
    $jsonContent = $ret.content
    $response = ConvertFrom-Json $jsonContent 
    Return $response
}

################################################################################################################################

function Get-MSBulletinQueryResults {
        
        
    # Gets the results of a query for all the MSBulletins that need to be patched.
       

    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token
    ) 

    
    # Create the objects to be used for the query
    # Create the vulnId object
    [PSCustomObject]$vulnId = [ordered]@{
    name                = ""
    description         = ""
    context             ="analysis"
    status              = "-1"
    createdTime         = "0"
    modifiedTime        = "0"
    groups              = @()
    tags                = ""
    type                = "vuln"
    tool                = "summsbulletin"
    sourceType          = "cumulative"
    startOffset         = "0"
    endOffset           = "10000"    
    filters             = @()
    vulnTool            = "summsbulletin"
    }

    # Create the vulnType object that will be converted to json.
    [PSCustomObject]$vulnType = [ordered]@{
    query               = ($vulnId)
    sourceType          = "cumulative"
    type                = "vuln"
    }


    # Convert the object to JSON using depth of 4...
    # Convertto-Json uses a default depth of 2 and will not create proper json formatted information for the webserver to parse.
    $jsonVulnType = ConvertTo-Json $vulnType -Depth 4 

    # Run the query and convert the results to PSObject.
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/analysis" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Body $jsonVulnType -Websession $sv -Method Post 
    $jsonContent = $ret.content
    $response = ConvertFrom-Json $jsonContent 

    return $response.response.results.msbulletinid
}

################################################################################################################################

function Get-AllIavmQueryResults {
        
        
    # Gets the results of an iavm query.
       

    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token
    ) 

    
    # Create the objects to be used for the query
    # Create the vulnId object
    [PSCustomObject]$vulnId = [ordered]@{
    name                = ""
    description         = ""
    context             ="analysis"
    status              = "-1"
    createdTime         = "0"
    modifiedTime        = "0"
    groups              = @()
    tags                = ""
    type                = "vuln"
    tool                = "sumiavm"
    sourceType          = "cumulative"
    startOffset         = "0"
    endOffset           = "10000"    
    filters             = @()
    vulnTool            = "sumiavm"
    }

    # Create the vulnType object that will be converted to json.
    [PSCustomObject]$vulnType = [ordered]@{
    query               = ($vulnId)
    sourceType          = "cumulative"
    type                = "vuln"
    }


    # Convert the object to JSON using depth of 4...
    # Convertto-Json uses a default depth of 2 and will not create proper json formatted information for the webserver to parse.
    $jsonVulnType = ConvertTo-Json $vulnType -Depth 4 

    # Run the query and convert the results to PSObject.
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/analysis" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Body $jsonVulnType -Websession $sv -Method Post 
    $jsonContent = $ret.content
    $response = ConvertFrom-Json $jsonContent 

    $results = $response.response.results | sort iavmid -Descending | Format-Table

    return $results
}

################################################################################################################################

function Get-IavmQueryResults {
    # Gets the results of an iavm query.
    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token,
    [string]$IavmId = $IavmId
    ) 

    
    # Create the objects to be used for the query
    # Create filter object
    [PSCustomObject]$iavmFilter = [ordered]@{
    filterName          = "iavmID"
    operator            = "="
    value               = ($IavmId)
    }

    # Create the vulnId object with and embed the filter object
    [PSCustomObject]$vulnId = [ordered]@{
    name                = ""
    description         = ""
    context             ="analysis"
    status              = "-1"
    createdTime         = "0"
    modifiedTime        = "0"
    groups              = @()
    tags                = ""
    type                = "vuln"
    tool                = "listvuln"
    sourceType          = "cumulative"
    startOffset         = "0"
    endOffset           = "10000"    
    filters             = @($($iavmFilter))
    vulnTool            = "listvuln"
    }

    # Create the vulnType object that will be converted to json.
    [PSCustomObject]$vulnType = [ordered]@{
    query               = ($vulnId)
    sourceType          = "cumulative"
    type                = "vuln"
    }


    # Convert the object to JSON using depth of 4...
    # Convertto-Json uses a default depth of 2 and will not create proper json formatted information for the webserver to parse.
    $jsonVulnType = ConvertTo-Json $vulnType -Depth 4 

    # Run the query and convert the results to PSObject.
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/analysis" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Body $jsonVulnType -Websession $sv -Method Post 
    $jsonContent = $ret.content
    $response = ConvertFrom-Json $jsonContent 

    [PSCustomObject]$results = @{
    Ip = $response.response.results.ip
    dnsName = $response.response.results.dnsName
    netbiosName = $response.response.results.netbiosName
    }

    return $results
}

################################################################################################################################

function Get-KbQueryResults {
    # Gets the results of an iavm query.
    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token
    ) 

    
    # Create the objects to be used for the query
    [PSCustomObject]$windowsHosts = [ordered]@{
    id                  = "3"
    name                = "Windows Hosts"
    description         = "The operating system detected has Windows installed./n/nThis will be helpful for those getting started with SecurityCenter."
    }

    # Create filter object
    [PSCustomObject]$assetFilter1 = [ordered]@{
    filterName          = "asset"
    operator            = "="
    value               = ($windowsHosts)
    }

    [PSCustomObject]$assetFilter2 = [ordered]@{
    filterName          = "pluginName"
    operator            = "="
    value               = "KB"
    }

    [PSCustomObject]$criticalSeverityFilter = [ordered]@{
    id                  = "4"
    name                = "Critical"
    description         = "Critical Severity"
    }

    [PSCustomObject]$highSeverityFilter = [ordered]@{
    id                  = "3"
    name                = "High"
    description         = "High Severity"
    }

    [PSCustomObject]$mediumSeverityFilter = [ordered]@{
    id                  = "2"
    name                = "Medium"
    description         = "Medium Severity"
    }

    [PSCustomObject]$lowSeverityFilter = [ordered]@{
    id                  = "1"
    name                = "Low"
    description         = "Low Severity"
    }

    [PSCustomObject]$assetFilter3 = [ordered]@{
    filterName          = "severity"
    operator            = "="
    value               = @($($criticalSeverityFilter,$highSeverityFilter,$mediumSeverityFilter,$lowSeverityFilter))
    }

    # Create the vulnId object with and embed the filter object
    [PSCustomObject]$vulnId = [ordered]@{
    name                = ""
    description         = ""
    context             ="analysis"
    status              = "-1"
    createdTime         = "0"
    modifiedTime        = "0"
    groups              = @()
    tags                = ""
    type                = "vuln"
    tool                = "listvuln"
    sourceType          = "cumulative"
    startOffset         = "0"
    endOffset           = "10000"    
    filters             = @($($assetFilter1,$assetFilter2,$assetFilter3))
    vulnTool            = "listvuln"
    }

    # Create the vulnType object that will be converted to json.
    [PSCustomObject]$vulnType = [ordered]@{
    query               = ($vulnId)
    sourceType          = "cumulative"
    type                = "vuln"
    }


    # Convert the object to JSON...
    # Convertto-Json uses a default depth of 2 and will not create proper json formatted information for the webserver to parse.
    $jsonVulnType = ConvertTo-Json $vulnType -Depth 10 

    # Run the query and convert the results to PSObject.
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/analysis" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Body $jsonVulnType -Websession $sv -Method Post 
    $jsonContent = $ret.content
    $response = ConvertFrom-Json $jsonContent 

    $pluginNames = $response.response.results.name
    $Matches = ""
    $kbs = $pluginNames | foreach {$toss = ($_ -match "KB\d{7}"); $Matches.Values}

    return $kbs
}

################################################################################################################################

function Get-ClassCSummaryQueryResults {
    # Gets the results of an iavm query.
    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token
    ) 

    
    # Create the objects to be used for the query
    # Create the vulnId object
    [PSCustomObject]$vulnId = [ordered]@{
    name                = ""
    description         = ""
    context             ="analysis"
    status              = "-1"
    createdTime         = "0"
    modifiedTime        = "0"
    groups              = @()
    tags                = ""
    type                = "vuln"
    tool                = "sumclassc"
    sourceType          = "cumulative"
    startOffset         = "0"
    endOffset           = "10000"    
    filters             = @()
    vulnTool            = "sumclassc"
    }

    # Create the vulnType object that will be converted to json.
    [PSCustomObject]$vulnType = [ordered]@{
    query               = ($vulnId)
    sourceType          = "cumulative"
    type                = "vuln"
    }


    # Convert the object to JSON...
    # Convertto-Json uses a default depth of 2 and will not create proper json formatted information for the webserver to parse.
    $jsonVulnType = ConvertTo-Json $vulnType -Depth 4 

    # Run the query and convert the results to PSObject.
    $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/analysis" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Body $jsonVulnType -Websession $sv -Method Post 
    $jsonContent = $ret.content
    $response = ConvertFrom-Json $jsonContent 

    $results = $response.response.results


    return $results
}

################################################################################################################################

function Get-CvePerClassCQueryResults {
    # Gets the results of an iavm query.
    [CmdletBinding()]
    param (
    [string]$SecurityCenterIP =$SecurityCenterIP,
    [Microsoft.PowerShell.Commands.WebRequestSession]$sv = $sv,
    [System.Int32]$token = $token
    ) 

    $results = Get-ClassCSummaryQueryResults
    $subnets = $results.ip


    foreach ($subnet in $subnets){
        # Create the objects to be used for the query
        [PSCustomObject]$filter = [ordered]@{
        filterName          = "ip"
        operator            = "="
        value               = ($subnet)
        }

        # Create the vulnId object
        [PSCustomObject]$vulnId = [ordered]@{
        name                = ""
        description         = ""
        context             ="analysis"
        status              = "-1"
        createdTime         = "0"
        modifiedTime        = "0"
        groups              = @()
        tags                = ""
        type                = "vuln"
        tool                = "sumcve"
        sourceType          = "cumulative"
        startOffset         = "0"
        endOffset           = "1000000"    
        filters             = @(($filter))
        vulnTool            = "sumcve"
        }

        # Create the vulnType object that will be converted to json.
        [PSCustomObject]$vulnType = [ordered]@{
        query               = ($vulnId)
        sourceType          = "cumulative"
        type                = "vuln"
        }


        # Convert the object to JSON...
        # Convertto-Json uses a default depth of 2 and will not create proper json formatted information for the webserver to parse.
        $jsonVulnType = ConvertTo-Json $vulnType -Depth 6 

        # Run the query and convert the results to PSObject.
        $ret = Invoke-WebRequest -URI "https://$SecurityCenterIP/rest/analysis" -UseBasicParsing -Headers @{"X-SecurityCenter"="$token"} -Body $jsonVulnType -Websession $sv -Method Post 
        $jsonContent = $ret.content
        $response = ConvertFrom-Json $jsonContent 

        $cves = $response.response.results.cveID

        [PSCustomObject]$results = [ordered]@{
        ($subnet)           = ($cves)
        }
        $results

    }


}

################################################################################################################################

<#
.Synopsis
   Connect to Security Center and runs various queries or tasks.
.DESCRIPTION
   Establishes a connection to Security Center Server.  Can provide a list of KBs and MS Bulletins needed in your environment that you can 
   supply to your WSUS.  Pulls the total vulnerabilities in your environment. Pulls all Iavm hits in your environment. Pulls host information 
   for specific IavmIDs.  Pulls Class C summary.  Pulls Cves per Class C subnet.
.EXAMPLE
   Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds
   This will result in default output of all the queries already available on the server.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -QueryId
    Returns the JSON syntax of a query based on the queryId.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -DeleteQueryId
    Deletes a query on the server.
.Example
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -Severities
    Returns the Critical, High, Medium, Low, and Informational vulnerability totals.
.EXAMPLE
   Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -Kbs
   This will return a list of KBs that need to be applied to assets in your environment.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -MsBulletins
    Returns all the MS Bulletins that need to be applied to your environment.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -AllIavm
    Returns all the Iavm hits.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -IavmId 2015-A-0001
    Returns Ip, Dns Name, and NetBios Name of machines that are affected by IavmId provided.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -IavmId 2015-A-0001 -IpList
    Returns Ip of machines that are affected by IavmId provided.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -IavmId 2015-A-0001 -DnsList
    Returns Dns Name of machines that are affected by IavmId provided.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -IavmId 2015-A-0001 -NetBiosName
    Returns NetBios Name of machines that are affected by IavmId provided.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -ClassCSummary
    Returns the summary of your Class C networks.
.EXAMPLE
    Invoke-SCQuery -SecurityCenterIp $ip -Credential $creds -CvePerClassC
    Returns the Cves found in each class C network in your environment. 
.NOTES
   Author: JD Crandell
.LINK
   https://docs.tenable.com/sccv/api/index.html
#>
function Invoke-SCQuery {


    param(
        [Parameter(HelpMessage="Security Center Ip Address",
                   Mandatory=$true
        )]
        [string]$SecurityCenterIP,

        [Parameter(HelpMessage="Enter credentials for a user with Security Manager privileges",
                   Mandatory=$true
        )]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(HelpMessage="Get the Json syntax of a query id"
        )]
        [string]$QueryId,

        [Parameter(HelpMessage="Delete a query."
        )]
        [string]$DeleteQueryId,

        [Parameter(HelpMessage="Get the Cat I, Cat II, Cat III, Cat IV, and Info vulnerability counts."
        )]
        [switch]$Severities,

        [Parameter(HelpMessage="Get the KBs that need to be applied to systems in your environment"
        )]
        [switch]$Kbs,
        
        [Parameter(HelpMessage="Get the MsBulletins that need to be applied to the systems in your environment"
        )]
        [switch]$MsBulletins,

        [Parameter(HelpMessage="Get all the Iavm hits"
        )]
        [switch]$AllIavm,

        [Parameter(HelpMessage="Enter the IavmID in the form: 2015-A-0001"
        )]
        [string]
        $IavmId,

        [Parameter(HelpMessage="Set this if you want the Iavm results to return a list of Ips.")] 
        [switch] 
        $IpList,

        [Parameter(HelpMessage="Set this if you want the Iavm results to  return a list of DNS names.")] 
        [switch] 
        $DnsList,

        [Parameter(HelpMessage="Set this if you want the Iavm results to  return a list of NetBIOS names")] 
        [switch] 
        $NetBiosName,

        [Parameter(HelpMessage="Set this if you want the Class C Summary")] 
        [switch] 
        $ClassCSummary,

        [Parameter(HelpMessage="Set this if you want the CVEs per Class C subnet")] 
        [switch] 
        $CvePerClassC
    )

    # Authenticate
    $sessionAndToken = (New-SecurityCenterToken)
    $sv = $sessionAndToken[0]
    $token = $sessionAndToken[1]

    # Get the Json format of a query.
    if($QueryId){
        Get-QuerySyntaxJson
    }

    # Delete a query
    elseif($DeleteQueryId){
        Remove-Query
    }
         
    # Run query for Severities
    elseif ($Severities){
        Get-ScanSeverities
    }

    # Run query for all iavms
    elseif($AllIavm){
        Get-AllIavmQueryResults
    }

    # Run query for particular iavm
    elseif ($IavmId){
        $results = Get-IavmQueryResults
            if ($IpList){
            return $results.Ip
            }
            elseif ($dnsList){
            return $results.dnsName
            }
            elseif ($netbiosName){
            return $results.netbiosName
            }
            else{
            return $results
            }
    }

    # Run query for Kbs
    elseif ($Kbs){
        return Get-KbQueryResults
    }

    # Run query for MsBulletins
    elseif($MsBulletins){
        return Get-MSBulletinQueryResults
    }

    # Run class C summary query
    elseif($ClassCSummary){
        Get-ClassCSummaryQueryResults 
    }

    # Get the Cves per Class C subnet
    elseif($CvePerClassC){
        Get-CvePerClassCQueryResults
    }

    # Get all the queries on the Security Center server (default behavior)
    else{
        Get-Queries
    }

    # Cleanup
    $cleanup = Remove-SecurityCenterToken

}
