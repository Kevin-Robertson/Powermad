function New-MachineAccount
{
    <#
    .SYNOPSIS
    This function adds a machine account with a specified password to Active Directory through an encrypted LDAP
    add request. By default standard domain users can add up to 10 systems to AD (see ms-DS-MachineAccountQuota).

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause 
    
    .DESCRIPTION
    The main purpose of this function is to leverage the default ms-DS-MachineAccountQuota attribute setting which
    allows all domain users to add up to 10 computers to a domain. The machine account and HOST SPNs are added
    directly through an LDAP connection to a domain controller and not by attaching the host system to Active
    Directory. This function does not modify the domain attachment and machine account associated with the host
    system.

    Note that you will not be able to remove the account without elevating privilege.

    .PARAMETER Credential
    Credentials for adding the machine account. Note that machine accounts can also add machine accounts.

    .PARAMETER Domain
    The targeted domain.

    .PARAMETER DomainController
    Domain controller to target in FQDN format.

    .PARAMETER DistinguishedName
    Distinguished name for the computers OU.

    .PARAMETER MachineAccount
    The username of the machine account that will be added.

    .PARAMETER Password
    The securestring of the password for the machine account.

    .EXAMPLE
    New-MachineAccount -MachineAccount iamapc
    Add a machine account with the current user's session.

    .EXAMPLE
    $user_account_creds = Get-Credential
    New-MachineAccount -MachineName iamapc -Credential $user_account_creds
    Add a machine account with creds from another user.

    .EXAMPLE
    $machine_account_password = ConvertTo-SecureString 'Summer2017!' -AsPlainText -Force
    $user_account_password = ConvertTo-SecureString 'Spring2017!' -AsPlainText -Force
    $user_account_creds = New-Object System.Management.Automation.PSCredential('domain\user',$user_account_password)
    New-MachineAccount -MachineName iamapc -Password $machine_account_password -Credential $user_account_creds
    Add a machine account with creds from another user and also avoid the machine account password prompt.

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)][String]$DistinguishedName,
        [parameter(Mandatory=$false)][String]$Domain,
        [parameter(Mandatory=$false)][String]$DomainController,
        [parameter(Mandatory=$true)][String]$MachineAccount,
        [parameter(Mandatory=$false)][System.Security.SecureString]$Password,
        [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$Credential
    )

    $null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")

    if(!$Password)
    {
        $password = Read-Host -Prompt "Enter a password for the new machine account" -AsSecureString
    }

    $password_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $password_cleartext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($password_BSTR)

     if(!$DomainController)
    {

        try
        {
            $current_domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $DomainController = $current_domain.DomainControllers[0].Name
            $domain = $current_domain.Name
        }
        catch
        {
            Write-Output "[-] domain controller not located"
            throw
        }

    }

    if(!$Domain)
    {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
    }
    
    $domain = $domain.ToLower()
    $machine_account = $MachineAccount

    if($MachineAccount.EndsWith('$'))
    {
        $sam_account = $MachineAccount
        $machine_account = $machine_account.SubString(0,$machine_account.Length - 1)
    }
    else 
    {
        $sam_account = $machine_account + "$"
    }

    Write-Verbose "[+] SAMAccountName=$sam_account" 

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

    Write-Verbose $distinguished_name
    $password_cleartext = [System.Text.Encoding]::Unicode.GetBytes('"' + $password_cleartext + '"')
    $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($DomainController,389)

    if($Credential)
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier,$Credential.GetNetworkCredential())
    }
    else
    {
        $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
    }
    
    $connection.SessionOptions.Sealing = $true
    $connection.SessionOptions.Signing = $true
    $connection.Bind()
    $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
    $request.DistinguishedName = $distinguished_name
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass","Computer")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "SamAccountName",$sam_account)) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "userAccountControl","4096")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "DnsHostName","$machine_account.$Domain")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "ServicePrincipalName","HOST/$machine_account.$Domain",
        "RestrictedKrbHost/$machine_account.$Domain","HOST/$machine_account","RestrictedKrbHost/$machine_account")) > $null
    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "unicodePwd",$password_cleartext)) > $null
    Remove-Variable password_cleartext

    try
    {
        $connection.SendRequest($request) > $null
        Write-Output "[+] machine account $machine_account added"
    }
    catch
    {
        Write-Output "[-] something went wrong"
    }

}