# **Powermad**

Repo for PowerShell tools that don’t fit my other projects.

## Invoke-DNSUpdate

This function can be used to add/delete dynamic DNS records if the default setting of enabled secure dynamic updates is configured on a domain controller. A, AAAA, CNAME, MX, PTR, SRV, and TXT records are currently supported. Invoke-DNSUpdate is modeled after BIND`s nsupdate tool when using the '-g' or 'gsstsig' options. 

An account/session with permission to perform secure dynamic updates is required. By default, authenticated users have the 'Create all child objects' permission on the Active Directory-integrated zone. Most records that do not currently exist in an AD zone can be added/deleted. Limitations for authenticated users can include things like being prevented from adding SRV records that interfere with the AD Kerberos records. Older existing dynamic records can sometimes be hijacked. Note that wpad and isatap are on a block list by default starting with Server 2008. You can add wpad and isatap if they don't exist. They just won’t work if blocked. See @mubix’s post for more details on the block list:

* https://room362.com/post/2016/wpad-persistence/

This function supports only GSS-TSIG through Kerberos AES256-CTS-HMAC-SHA1-96 using two separate methods. By default, the function will have Windows perform all Kerberos steps up until the AP-REQ is sent to DNS on the DC. This method will work with either the current session context or with specified credentials. The second method performs Kerberos authentication using just PowerShell code over a TCPClient connection. This method will accept a password or AES256 hash and will not place any tickets in the client side cache.

##### Examples:

* Add an A record  
`Invoke-DNSUpdate -DNSType A -DNSName www.test.local -DNSData 192.168.100.125`  

* Delete an A record  
`Invoke-DNSUpdate -DNSType A -DNSName www.test.local` 

* Add an SRV record  
`Invoke-DNSUpdate -DNSType SRV -DNSName _autodiscover._tcp.test.local -DNSData system.test.local -DNSPriority 100 -DNSWeight 80 -DNSPort 443`  

## New-MachineAccount

This function can leverage the default ms-DS-MachineAccountQuota attribute setting which allows all domain users to add up to 10 computers to a domain. The new machine account is added directly through an LDAP add request to a domain controller and not by impacting the host system’s attachment status to Active Directory.

The LDAP add request is modeled after the add request used when joining a system to a domain. The following (mostly validated by the DC) attributes are set:

* objectClass = Computer  
* SamAccountName = Machine account name with trailing $  
* userAccountControl = 4096  
* DnsHostName = FQDN  
* ServicePrincipalName = 2 HOST and 2 RestrictedKrbHost SPNs using both the FQDN and account name  
* unicodePwd = the specified password  

A new machine account can be used for tasks such as leveraging privilege provided to the ‘Domain Computers’ group or as an additional account for domain enumeration. By default, machine accounts do not have logon locally permission. You can either use tools/clients that accept network credentials directly or through the use of ‘runsas /netonly’ or @harmj0y’s Invoke-UserImpersonation/Invoke-RevertToSelf included with PowerView.

* https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon

Machine accounts created with standard users will have the mS-DS-CreatorSID populated with the standard user’s SID.

Note that ms-DS-MachineAccountQuota does not provide the ability for authenticated users to delete added machine accounts from AD. Elevated privilege will need to be acquired to remove the account if you want to avoid passing the task off to your client.

##### Examples:

* Add a new machine account  
`New-MachineAccount -MachineAccount iamapc` 

* Use the added account with runas /netonly  
`runas /netonly /user:domain\iamapc$ powershell` 

## Disable-MachineAccount

This function can disable a machine account that was added through New-MachineAccount. This function should be used with the same user that created the machine account.

## Set-MachineAccountAttribute

This function can populate some attributes for an account that was added through New-MachineAccount, if a user has write access. This function should be used with the same user that created the machine account.  

Here is a list of some of the usual write access enabled attributes:  

* AccountDisabled  
* description  
* displayName  
* DnsHostName  
* ServicePrincipalName  
* userParameters  
* userAccountControl  
* msDS-AdditionalDnsHostName  
* msDS-AllowedToActOnBehalfOfOtherIdentity  
* SamAccountName  

##### Examples:

* Remove the trailing '$' from the SamAccountName attribute
`Set-MachineAccountAttribute -MachineName iamapc -Attribute SamAccountName -Value iamapc`

* Use the modified account with runas /netonly  
`runas /netonly /user:domain\iamapc powershell` 

## Get-MachineAccountAttribute

This function can return values populated in machine account attributes.

## Get-KerberosAESKey

This function can generate Kerberos AES 256 and 128 keys from a known username and password.