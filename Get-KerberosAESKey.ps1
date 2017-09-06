function Get-KerberosAESKey
{
    <#
    .SYNOPSIS
    Generate Kerberos AES 128/256 keys from a known username/hostname, password, and kerberos realm. The
    results have been verified against the test values in RFC3962, MS-KILE, and my own test lab.
    
    https://tools.ietf.org/html/rfc3962
    https://msdn.microsoft.com/library/cc233855.aspx

    Author: Kevin Robertson (@kevin_robertson)  
    License: BSD 3-Clause   

    .PARAMETER Password
    [String] Valid password.

    .PARAMETER Salt
    [String] Concatenated string containing the realm and username/hostname.
    AD username format = uppercase realm + case sensitive username (e.g., TEST.LOCALusername, TEST.LOCALAdministrator)
    AD hostname format = uppercase realm + the word host + lowercase hostname without the trailing '$' + . + lowercase
    realm (e.g., TEST.LOCALhostwks1.test.local)

    .PARAMETER Iteration
    [Integer] Default = 4096: Int value representing how many iterations of PBKDF2 will be performed. AD uses the
    default of 4096.
    
    .PARAMETER OutputType
    [String] Default = AES: (AES,AES128,AES256,AES128ByteArray,AES256ByteArray) AES, AES128, and AES256 will output strings.
    AES128Byte and AES256Byte will output byte arrays.

    .EXAMPLE
    Get-KerberosAESKey -Password password -Salt ATHENA.MIT.EDUraeburn -Iteration 1
    Verify results against first RFC3962 sample test vectors in section B.
    
    .EXAMPLE
    Get-KerberosAESKey -Salt TEST.LOCALuser
    Generate keys for a valid AD user.

    .LINK
    https://github.com/Kevin-Robertson/Powermad
    #>

    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$true)][String]$Salt,
        [parameter(Mandatory=$false)][System.Security.SecureString]$Password,
        [parameter(Mandatory=$false)][ValidateSet("AES","AES128","AES256","AES128ByteArray","AES256ByteArray")][String]$OutputType = "AES",
        [parameter(Mandatory=$false)][Int]$Iteration=4096
    )
    
    if(!$Password)
    {
        $password = Read-Host -Prompt "Enter password" -AsSecureString
    }

    $password_BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $password_cleartext = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($password_BSTR)
    
    [Byte[]]$password_bytes = [System.Text.Encoding]::UTF8.GetBytes($password_cleartext)
    [Byte[]]$salt_bytes = [System.Text.Encoding]::UTF8.GetBytes($Salt)
    $AES256_constant = 0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4
    $AES128_constant = 0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93
    $IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 
    $PBKDF2 = New-Object Security.Cryptography.Rfc2898DeriveBytes($password_bytes,$salt_bytes,$iteration)
    $PBKDF2_AES256_key = $PBKDF2.GetBytes(32)
    $PBKDF2_AES128_key = $PBKDF2_AES256_key[0..15]
    $PBKDF2_AES256_key_string = ([System.BitConverter]::ToString($PBKDF2_AES256_key)) -replace "-",""
    $PBKDF2_AES128_key_string = ([System.BitConverter]::ToString($PBKDF2_AES128_key)) -replace "-",""
    Write-Verbose "PBKDF2 AES128 Key: $PBKDF2_AES128_key_string"
    Write-Verbose "PBKDF2 AES256 Key: $PBKDF2_AES256_key_string"
    $AES = New-Object "System.Security.Cryptography.AesManaged"
    $AES.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $AES.Padding = [System.Security.Cryptography.PaddingMode]::None
    $AES.IV = $IV
    # AES 256
    $AES.KeySize = 256
    $AES.Key = $PBKDF2_AES256_key
    $AES_encryptor = $AES.CreateEncryptor()
    $AES256_key_part_1 = $AES_encryptor.TransformFinalBlock($AES256_constant,0,$AES256_constant.Length)
    $AES256_key_part_2 = $AES_encryptor.TransformFinalBlock($AES256_key_part_1,0,$AES256_key_part_1.Length)
    $AES256_key = $AES256_key_part_1[0..15] + $AES256_key_part_2[0..15]
    $AES256_key_string = ([System.BitConverter]::ToString($AES256_key)) -replace "-",""    
    # AES 128
    $AES.KeySize = 128
    $AES.Key = $PBKDF2_AES128_key
    $AES_encryptor = $AES.CreateEncryptor()
    $AES128_key = $AES_encryptor.TransformFinalBlock($AES128_constant,0,$AES128_constant.Length)
    $AES128_key_string = ([System.BitConverter]::ToString($AES128_key)) -replace "-",""
    Remove-Variable password_cleartext
    
    switch($OutputType)
    {
    
        'AES'
        {
            Write-Output "AES128 Key: $AES128_key_string"
            Write-Output "AES256 Key: $AES256_key_string"
        }
        
        'AES128'
        {
            Write-Output "$AES128_key_string"
        }
        
        'AES256'
        {
            Write-Output "$AES256_key_string"
        }
        
        'AES128ByteArray'
        {
            Write-Output $AES128_key
        }
        
        'AES256ByteArray'
        {
            Write-Output $AES256_key
        }
        
    }
    
}