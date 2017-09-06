function Set-MachineAccountAttribute
{
    <#
    .SYNOPSIS
    This function can populate an attribute for an account that was added through New-MachineAccount. Write
    access to the attribute is required. This function should be used with the same user that created the
    machine account.

    .DESCRIPTION
    The user account that creates a machine account is granted write access to some attributes. These attributes
    can be leveraged to help an added machine account blend in better or change values that were restricted by
    validation when the account was created.

    Here is a list of some of the usual write access enabled attributes:

    AccountDisabled
    description
    displayName
    DnsHostName
    ServicePrincipalName
    userParameters
    userAccountControl
    msDS-AdditionalDnsHostName
    msDS-AllowedToActOnBehalfOfOtherIdentity
    SamAccountName
    
    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER Domain
    The targeted domain.

    .PARAMETER MachineAccount
    The username of the machine account that will be modified.

    .PARAMETER Attribute
    The machine account attribute.

    .PARAMETER Value
    The machine account attribute value.

    .EXAMPLE
    Set-MachineAccountAttribute -MachineAccount payroll -Attribute description -Value "Payroll app server"

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$true)][String]$Attribute,
        [parameter(Mandatory=$true)]$Value
    )

    if($MachineAccount.EndsWith('$'))
    {
        $machine_account = $MachineAccount.SubString(0,$MachineAccount.Length - 1)
    }
    else
    {
        $machine_account = $MachineAccount  
    }

    if(!$Domain)
    {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }

    if(!$DistinguishedName)
    {

        $distinguished_name = "CN=$machine_account,CN=Computers"

        $DCArray = $Domain.Split(".")

        ForEach($DC in $DCArray)
        {
            $distinguished_name += ",DC=$DC"
        }

    }
    else 
    {
        $distinguished_name = "$DistinguishedName"
    }

    $account = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$distinguished_name"

    try
    {
        $account.InvokeSet($Attribute,$Value)
        $account.SetInfo()
        Write-Output "[+] $attribute updated"
    }
    catch
    {
        $error_message = $_.Exception.Message
        $error_message = $error_message -replace "`n",""
        Write-Output "[-] $error_message"
    }

}