function Disable-SSLValidation {
    $Script:OriginalCertificatePolicy = [System.Net.ServicePointManager]::CertificatePolicy

    add-type @" 
using System.Net; 
using System.Security.Cryptography.X509Certificates; 
public class TrustAllCertsPolicy : ICertificatePolicy { 
    public bool CheckValidationResult( ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { 
        return true; 
    }
}
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

function Enable-SSLValidation {
    [System.Net.ServicePointManager]::CertificatePolicy = $Script:OriginalCertificatePolicy
}

function Invoke-ASACommand {
    param (
        [Parameter(Mandatory)]$Command
    )
    Disable-SSLValidation
    $URI = Get-ASAURI
    $Credential = Get-ASACredential
    Add-Type -AssemblyName System.Web
    $URLEncodedCommand = [System.Web.HttpUtility]::UrlEncode($Command)
    Invoke-RestMethod  -Uri $URI/admin/exec/$URLEncodedCommand -Credential $Credential
    Enable-SSLValidation
}

function Set-ASAURI {
    param(
        [Parameter(Mandatory)]$Host,
        $Port = 443
    )
    "https://$($Host):$($Port)" | Export-Clixml $env:USERPROFILE\ASAURI.xml
}

function Get-ASAURI {
    Import-Clixml $env:USERPROFILE\ASAURI.xml
}

function Set-ASACredential {
    param(
        [Parameter(Mandatory)][System.Management.Automation.PSCredential]$Credential
    )
    $Credential | Export-Clixml $env:USERPROFILE\ASACredential.xml
}

function Get-ASACredential {
    Import-Clixml $env:USERPROFILE\ASACredential.xml
}

function Get-NATedIPAddresses {
}

function Get-ASARunningConfiguration {
    Invoke-ASACommand -Command "show run"
}

function Get-ASANatDetail {
    Invoke-ASACommandWithTemplate -Command "show nat detail"
}

function Get-CiscoASAPowerShellModulePath {
    (Get-Module -ListAvailable CiscoASAPowerShell).ModuleBase
}

function Invoke-TervisNetworkSSHCommandWithTemplate {
    param(
        $SSHSession,
        $Command,
        $FunctionName = (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name
    )
    $CommandTemplate = Get-Content "$PSScriptRoot\$FunctionName.Template" | Out-String
    Invoke-SSHCommandWithTemplate -SSHSession $SSHSession -Command "show ip arp" -CommandTemplate $CommandTemplate
}

function New-ASACommandResultTemplate {
    param(
        $Command,
        $FunctionName
    )
    $ModulePath = Get-CiscoASAPowerShellModulePath
    $CommandResult = Invoke-ASACommand -Command $Command
    $CommandResult | Out-File "$ModulePath\Templates\$FunctionName.Template" -Encoding ascii
}

function Edit-ASACommandResultTemplate {
    param(
        $FunctionName
    )
    $ModulePath = Get-CiscoASAPowerShellModulePath
    Invoke-Item "$ModulePath\Templates\$FunctionName.Template" 
}

function Invoke-ASACommandWithTemplate {
    param(
        [Parameter(Mandatory)]$Command,
        $FunctionName = (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name
    )
    $Result = Invoke-ASACommand -Command $Command
    $ModulePath = Get-CiscoASAPowerShellModulePath
    $Result | ConvertFrom-String -TemplateFile "$ModulePath\Templates\$FunctionName.Template"
}

function Get-ASAVPNSessiondbRAIkev1Ipsec {
    Invoke-ASACommandWithTemplate -Command "show vpn-sessiondb ra-ikev1-ipsec"
}

function Get-ASARunningConfigObject {
    Invoke-ASACommandWithTemplate -Command "show running-config object"
}

function Get-ASAGlobalACL {
    Invoke-ASACommandWithTemplate -Command "show access-list global_access"
}

function Get-ASARunningConfigAccessListGlobalAccess {
    (Invoke-ASACommand -Command "show running-config access-list global_access") -split "`n" |
    Invoke-ASAParseACLConfigurationLine
}

function Get-ASARunningConfigObjectGroup {
    Invoke-ASACommandWithTemplate -Command "show running-config object-group"
}

function Invoke-ASAParseACLConfigurationLine {
#http://www.cisco.com/c/en/us/td/docs/security/asa/asa90/configuration/guide/asa_90_cli_config/acl_extended.html
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Line
    )
    process {
        $Tokens = $Line -split " "
        $TokenQueue = New-Object system.collections.queue
        $Tokens | % { $TokenQueue.Enqueue($_) }
    
        $TokensToConsume = @"
access-list
global_access
"@ -split "`r`n"

        While ($TokenQueue.Peek() -in $TokensToConsume) {
            $TokenQueue.Dequeue() | Out-Null
        }

        $ACL = [PSCustomObject]@{}

        Get-ACLConfigurationLineACLType -ACL $ACL -TokenQueue $TokenQueue
        Get-ACLConfigurationLineAction -ACL $ACL -TokenQueue $TokenQueue
        Get-ACLConfigurationProtocolArguement -ACL $ACL -TokenQueue $TokenQueue
        Get-ACLConfigurationAddressArguement -ACL $ACL  -Type Source -TokenQueue $TokenQueue
        Get-ACLConfigurationPortArguement -ACL $ACL -Type Source -TokenQueue $TokenQueue
        Get-ACLConfigurationAddressArguement -ACL $ACL -Type Destination -TokenQueue $TokenQueue
        Get-ACLConfigurationPortArguement -ACL $ACL -Type Destination -TokenQueue $TokenQueue

        $ACL
    }
}

function Get-ACLConfigurationLineACLType {
    param(
        [Parameter(Mandatory)]$TokenQueue,
        [Parameter(Mandatory)]$ACL
    )
    if ($TokenQueue.Count -eq 0) { return }

    $Token = $TokenQueue.Dequeue()
    $ACL | Add-Member -Name AccessListType -Value $Token -MemberType NoteProperty

    if ($Token -in "remark") {
        $ACL | Add-Member -Name Remark -Value $($TokenQueue -join " ") -MemberType NoteProperty
        $TokenQueue.Clear()
    }
}

function Get-ACLConfigurationLineAction {
    param(
        [Parameter(Mandatory)]$TokenQueue,
        [Parameter(Mandatory)]$ACL
    )
    if ($TokenQueue.Count -eq 0) { return }

    $ACL | Add-Member -Name Action -Value $TokenQueue.Dequeue() -MemberType NoteProperty
}

function Get-ACLConfigurationProtocolArguement {
    param(
        [Parameter(Mandatory)]$TokenQueue,
        [Parameter(Mandatory)]$ACL
    )
    if ($TokenQueue.Count -eq 0) { return }

    if ($TokenQueue.Peek() -in "tcp","icmp","ip","udp") {
        $ACL | Add-Member -Name ProtocolArguementType -Value "ProtocolName" -MemberType NoteProperty
    } else {
        $ACL | Add-Member -Name ProtocolArguementType -Value $TokenQueue.Dequeue() -MemberType NoteProperty
    }
    $ACL | Add-Member -Name ProtocolArguement -Value $TokenQueue.Dequeue() -MemberType NoteProperty    
}

function Get-ACLConfigurationAddressArguement {
    param(
        [Parameter(Mandatory)]$TokenQueue,
        [ValidateSet("Source","Destination")][Parameter(Mandatory)]$Type,
        [Parameter(Mandatory)]$ACL
    )
    if ($TokenQueue.Count -eq 0) { return }

    if ($TokenQueue.Peek() -in "any","any4","any6") {
        $ACL | Add-Member -Name "$($Type)AddressArguementType" -Value "FormOfAny" -MemberType NoteProperty
    } else {
        $ACL | Add-Member -Name "$($Type)AddressArguementType" -Value $TokenQueue.Dequeue() -MemberType NoteProperty
    }
    $ACL | Add-Member -Name "$($Type)AddressArguement" -Value $TokenQueue.Dequeue() -MemberType NoteProperty    
}

function Get-ACLConfigurationPortArguement {
    param(
        [Parameter(Mandatory)]$TokenQueue,
        [ValidateSet("Source","Destination")][Parameter(Mandatory)]$Type,
        [Parameter(Mandatory)]$ACL
    )
    if ($TokenQueue.Count -eq 0) { return }

    if ($TokenQueue.Peek() -in "lt","gt","eq","neq","range") {
        $ACL | Add-Member -Name "$($Type)PortArguementOperator" -Value $TokenQueue.Dequeue() -MemberType NoteProperty
        $ACL | Add-Member -Name "$($Type)PortArguementPort" -Value $TokenQueue.Dequeue() -MemberType NoteProperty
    }
}

function New-ASAACLConfigurationLine {
    param (
        [ValidateSet("Extended","Remark")]$Type,
        [ValidateSet("Extended","Remark")]$Action
    )
}