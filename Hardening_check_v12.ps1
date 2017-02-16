<#  Program name : hardening check
    Arthur:  imtbsc
    version no.:  0.12
    date: Feb2017  #>

clear-host

$start_date = get-date

write-host 'Windows 2012 R2 - Hardening review started @ '$start_date

$global:Result_set = @()
$global:error_set = @()
$global:FailedCase = 0
$global:SuccessCase = 0
$global:selfsigned = 0
$global:selfsigned_set = ''

Function Failed-cipher-report
{
    $name = $args[0]
    $swt_valid_value = switch($args[1]){0 {"Disabled"} 1 {"Enabled"} default {"NOT FOUND"} }
    $remark = $args[2]

    $CaseProperties = @{
            Test_Case =  $remark + $name + ' - SHOULD BE ' + $swt_valid_value
            Test_Actual = 'NOT CONFIG'
            Test_Expected = $swt_valid_value
            Test_Result = 'FAILED' 
            }
    $global:FailedCase = $global:FailedCase + 1  
    
    $global:Result_set += New-Object PSObject -Property $CaseProperties 
}

Function return_SID {
    $SID = $args[0]
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $objSID.Translate( [security.principal.ntaccount] )
    #Write-Host "Resolved user name: " $objUser.Value
    return $objUser.Value
}

Function audit-user-rights
{

    $parm = $args[0]        # parm for the testing
    $valid_count = $args[1] # valid count of SID required - can only support 1/0
    $valid_value = $args[2] # valid value of the SID required - can only support 1 SID
    $remark = $args[3]      # remark for the display
    
    $content = Get-content C:\temp\secedit_user_mapped.inf
    
    $found_parm = $false
    
    Get-Content c:\temp\secedit_user_mapped.inf | 
    ForEach-Object {
        $line = $_
        
        if ($line.split('=')[0].trim() -eq $parm.trim()) {

                $found_parm = $true
                $found_value = $line.split('=')[1].trim()
                            
                if ($valid_count -eq 1){

                    if ($found_value -match $valid_value) 
                    {               
                        $CaseProperties = @{
                        Test_Case = $remark + '-' + $parm + ' SHOULD BE GRANTED TO ' + $valid_value
                        Test_Actual = '{'+$found_value+'}'
                        Test_Expected = $valid_value
                        Test_Result = 'PASSED'}    
                        $global:SuccessCase = $global:SuccessCase + 1  
                    }
                                        
                    if ($found_value -notmatch $valid_value) 
                    {               
                        $CaseProperties = @{
                        Test_Case = $remark + '-' + $parm + ' SHOULD BE GRANTED TO ' + $valid_value
                        Test_Actual = '{'+$found_value+'}'
                        Test_Expected = $valid_value
                        Test_Result = 'FAILED'}    
                        $global:FailedCase = $global:FailedCase + 1  
                    }
                    
                    
                $global:Result_set += New-Object PSObject -Property $CaseProperties
                 
                }

                if ($valid_count -eq 0){
                    
                    if ($found_value -eq '') 
                    {               
                        $CaseProperties = @{
                        Test_Case = $remark + '-' + $parm + ' SHOULD BE GRANTED TO NO ONE'
                        Test_Actual = '{'+$found_value+'}'
                        Test_Expected = "<blank>"
                        Test_Result = 'PASSED'}    
                        $global:SuccessCase = $global:SuccessCase + 1  
                    } 
                    else 
                    {               
                        $CaseProperties = @{
                        Test_Case = $remark + '-' + $parm + ' SHOULD BE GRANTED TO NO ONE'
                        Test_Actual = '{'+$found_value+'}'
                        Test_Expected = "<blank>"
                        Test_Result = 'FAILED'}    
                        $global:FailedCase = $global:FailedCase + 1  
                    }

                    $global:Result_set += New-Object PSObject -Property $CaseProperties 

                }
                            
        }
    }
    
    if($found_parm -eq $false) {
       $global:error_set += "Parm - <"+$parm+"> cannot be found from secedit"
    }

}


Function Audit-self-signed-cert
{
    $FQDN_local = [System.Net.Dns]::GetHostByName(($env:computerName))
    $host_local = $env:computername
    $local_signed_cert = Get-ChildItem cert: -Recurse -SSLServerAuthentication | where {$_.Issuer -match 'localhost' -or $_.Issuer -match $host_local -or $_.Issuer -match $fqdn_local.HostName -or $_.issuer -match 'cathaypacific'}
    if ($Local_signed_cert.Count -gt 0) 
    {
            $CaseProperties = @{
                Test_Case = 'No Self-signed certificate should be used'
                Test_Actual = $local_signed_cert.count
                Test_Expected = 0  
                Test_Result = 'FAILED'        
            }
            $global:FailedCase = $global:FailedCase + 1 
            $global:Result_set += New-Object PSObject -Property $CaseProperties 
    }
    else 
    {
            $CaseProperties = @{
                Test_Case = 'No Self-signed certificate should be used'
                Test_Actual = $local_signed_cert.count
                Test_Expected = 0  
                Test_Result = 'PASSED'        
            }
            $global:SuccessCase = $global:SuccessCase + 1 
            $global:Result_set += New-Object PSObject -Property $CaseProperties 
    }
    
    $global:selfsigned = $Local_signed_cert.Count 

    $global:selfsigned_set = $local_signed_cert
}


Function Test-Software-installed
{ 
    $name = $args[0]
    $remark = $args[1]
 
    $Softwareinstall = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -eq $name}
          
    if ($Softwareinstall.Name -eq $name) 
    {
        $CaseProperties = @{
        Test_Case =  $remark + '-' + $name + ' - SHOULD BE Installed' 
        Test_Actual = 'INSTALLED'
        Test_Expected = 'INSTALLED'
        Test_Result = 'PASSED'
        }
        $global:SuccessCase = $global:SuccessCase + 1  
    }
    else
    {     
        $CaseProperties = @{
        Test_Case =  $remark + '-' + $name + ' - SHOULD BE Installed' 
        Test_Actual = 'NOT INSTALLED'
        Test_Expected = 'INSTALLED'
        Test_Result = 'FAILED'
        }
            
        $global:FailedCase = $global:FailedCase + 1  
    }
    $global:Result_set += New-Object PSObject -Property $CaseProperties

}

Function audit-guest-admin-account
{
    $content = Get-content C:\temp\secedit1.inf
    $found_admin = $false
    $found_guest = $false

    foreach ($line in $content)
    {
        $parm = $line.split('=')[0]
        $value = $line.split('=')[1]
        

        # --- ADMINISTRATOER CHECK ---#
        if ($parm.trim() -eq 'NewAdministratorName') 
        {
            $found_admin=$true
            $value = $value.ToUpper().trim()
            
            if ($value -notmatch  "\.*ADMIN\.*" )
            {
                    $CaseProperties = @{
                    Test_Case =  'New admin name SHOULD NOT have admin keyword'
                    Test_Actual = $value
                    Test_Expected = 'name does not have "admin"'
                    Test_Result = 'PASSED' 
                    }
                    $global:SuccessCase = $global:SuccessCase + 1  
            }
            Else
            {     
                    $CaseProperties = @{
                    Test_Case =  'New admin name SHOULD NOT have admin keyword'
                    Test_Actual = $value
                    Test_Expected = 'name does not have "admin"'
                    Test_Result = 'FAILED' 
                    }
                    $global:FailedCase = $global:FailedCase + 1  
            }

        $global:Result_set += New-Object PSObject -Property $CaseProperties

        }


        #--- GUEST CHECK ---#
        if ($parm.trim() -eq 'NewGuestName') 
        {
            $found_guest=$true
            $value = $value.ToUpper().trim()
            
            if ($value -notmatch  "\.*GUEST\.*" )
            {
                    $CaseProperties = @{
                    Test_Case =  'New guest name SHOULD NOT have guest keyword'
                    Test_Actual = $value
                    Test_Expected = 'name does not have "guest"'
                    Test_Result = 'PASSED' 
                    }
                    $global:SuccessCase = $global:SuccessCase + 1  
            }
            Else
            {     
                    $CaseProperties = @{
                    Test_Case =  'New guest name SHOULD NOT have guest keyword'
                    Test_Actual = $value
                    Test_Expected = 'name does not have "guest"'
                    Test_Result = 'FAILED' 
                    }
                    $global:FailedCase = $global:FailedCase + 1  
            }

        $global:Result_set += New-Object PSObject -Property $CaseProperties

        }

    }
    <#-
    if ($found_admin -eq $false) 
        {
            $CaseProperties = @{
            Test_Case =  'New admin name SHOULD NOT have admin keyword'
            Test_Actual = '<cannot found admin>'
            Test_Expected = 'NO admin'
            Test_Result = 'FAILED' 
            }
            $global:FailedCase = $global:FailedCase + 1 
            $global:Result_set += New-Object PSObject -Property $CaseProperties
        }
     if ($found_guest -eq $false) 
        {
            $CaseProperties = @{
            Test_Case =  'New guest name SHOULD NOT have guest keyword'
            Test_Actual = '<cannot found guest>'
            Test_Expected = 'NO guest'
            Test_Result = 'FAILED' 
            }
            $global:FailedCase = $global:FailedCase + 1 
            $global:Result_set += New-Object PSObject -Property $CaseProperties
        }
    -#>
}


Function Test-RegistryValue
{
    $path = $args[0]
    $name = $args[1]
    
    $exists = Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue
    If (($exists -ne $null) -and ($exists.Length -ne 0)) {
        Return $true
    }
    Return $false
}

Function audit-policy-allowedpath
{
    $Reg_path = $args[0]
    $Item = $args[1]
    $valid_value = $args[2]
    $remark = $args[3]
    
    if (Test-RegistryValue Registry::$Reg_path $item )
        {
            if (test-path -Path Registry::$Reg_path)
            {
                $Reg = Get-ItemProperty -Path Registry::$Reg_path $Item -ErrorAction SilentlyContinue
        
                $merged_reg = $Reg.$item -join ',' 
                $display_reg = $merged_reg.substring(0,16) + '...'
                $display_valid_value = $valid_value.substring(0,16) + '...'

                if ($merged_reg  -eq $valid_value) 
                {
                    $CaseProperties = @{
                    Test_Case =  $remark + ' SHOULD BE ' + $display_valid_value  
                    Test_Actual = $display_reg
                    Test_Expected = $display_valid_value
                    Test_Result = 'PASSED' 
                    }
                    $global:SuccessCase = $global:SuccessCase + 1  
                }
                else
                {     
                    $CaseProperties = @{
                    Test_Case =  $remark + ' SHOULD BE ' + $display_valid_value  
                    Test_Actual = $display_reg
                    Test_Expected = $display_valid_value
                    Test_Result = 'FAILED' 
                    }
            
                    $global:FailedCase = $global:FailedCase + 1  
                }
            $global:Result_set += New-Object PSObject -Property $CaseProperties
            }
        }
    else 
        {
        $global:error_set += "Registry - {"+$reg_path+"} "+ $item +" cannot be found."
        }
}

Function audit-UserAccountControl 
{
    $parm = $args[0] 
    $validvalue = $args[1]
    $remark = $args[2]
    
    $filterAdminToken = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" $parm
    $actual = $filterAdminToken.$parm 
    
    if ($actual -eq $validvalue ) 
    {
        $CaseProperties = @{
        Test_Case =  $remark + ' - SHOULD BE ' + $validvalue
        Test_Actual = $actual
        Test_Expected = $validvalue
        Test_Result = 'PASSED' 
        }
        $global:SuccessCase = $global:SuccessCase + 1  
    }
    else
    {     
        $CaseProperties = @{
        Test_Case =  $remark + ' - SHOULD BE ' + $validvalue
        Test_Actual = $actual
        Test_Expected = $validvalue
        Test_Result = 'FAILED'  
        }
            
        $global:FailedCase = $global:FailedCase + 1  
    }
    $global:Result_set += New-Object PSObject -Property $CaseProperties
}


Function audit-policy-registry
{
    $Reg_path = $args[0]
    $Item = $args[1]
    $valid_value = $args[2]
    $remark = $args[3]
    
    if (Test-RegistryValue Registry::$Reg_path $item )
        {
            if (test-path -Path Registry::$Reg_path)
            {
                $Reg = Get-ItemProperty -Path Registry::$Reg_path $Item -ErrorAction SilentlyContinue
        
                if ($Reg.$item -contains $valid_value) 
                {
                    $CaseProperties = @{
                    Test_Case =  $remark + ' SHOULD BE ' + $valid_value  
                    Test_Actual = $REG.$item 
                    Test_Expected = $valid_value
                    Test_Result = 'PASSED' 
                    }
                    $global:SuccessCase = $global:SuccessCase + 1  
                }
                else
                {     
                    $CaseProperties = @{
                    Test_Case =  $remark + ' SHOULD BE ' + $valid_value  
                    Test_Actual = $REG.$item
                    Test_Expected = $valid_value
                    Test_Result = 'FAILED' 
                    }
            
                    $global:FailedCase = $global:FailedCase + 1  
                }
            $global:Result_set += New-Object PSObject -Property $CaseProperties
            }
        }
    else 
        {
        $global:error_set += "Registry - {"+$reg_path+"} "+ $item +" cannot be found."
        }
}

Function prep-policy-txt
{
    secedit /export /cfg c:\temp\secedit.inf /log c:\temp\secedit_log.log /quiet

    Get-Content c:\temp\secedit.inf | where-object {$_ -notmatch '^\[' } | set-content c:\temp\secedit1.inf
    Remove-Item c:\temp\secedit.inf

     (Get-Content c:\temp\secedit1.inf) `
    -replace "SeAssignPrimaryTokenPrivilege", "Replace a process-level token"  `
    -replace "SeAuditPrivilege" ,"Generate security audits"`
    -replace "SeBackupPrivilege" ,"Back up files and directories"`
    -replace "SeBatchLogonRight" ,"Log on as a batch job"`
    -replace "SeChangeNotifyPrivilege" ,"Bypass traverse checking"`
    -replace "SeCreateGlobalPrivilege" ,"Create global objects"`
    -replace "SeCreatePagefilePrivilege" ,"Create a pagefile"`
    -replace "SeCreatePermanentPrivilege" ,"Create permanent shared objects"`
    -replace "SeCreateSymbolicLinkPrivilege" ,"Create symbolic links"`
    -replace "SeCreateTokenPrivilege" ,"Create a token object"`
    -replace "SeDebugPrivilege" ,"Debug programs"`
    -replace "SeDenyBatchLogonRight" ,"Deny logon as a batch file"`
    -replace "SeDenyInteractiveLogonRight" ,"Deny local logon"`
    -replace "SeDenyNetworkLogonRight" ,"Deny Access to this computer from the network"`
    -replace "SeDenyRemoteInteractiveLogonRight" ,"Deny logon through terminal services"`
    -replace "SeDenyServiceLogonRight" ,"Deny logon as a service"`
    -replace "SeEnableDelegationPrivilege" ,"Enable computer and user accounts to be trusted for delegation"`
    -replace "SeImpersonatePrivilege" ,"Impersonate a client after authentication"`
    -replace "SeIncreaseBasePriorityPrivilege" ,"Increase scheduling priority"`
    -replace "SeIncreaseQuotaPrivilege" ,"Adjust memory quotas for a process"`
    -replace "SeIncreaseWorkingSetPrivilege" ,"Increase a process working set"`
    -replace "SeInteractiveLogonRight" ,"Log on locally"`
    -replace "SeLoadDriverPrivilege" ,"Load and unload device drivers"`
    -replace "SeLockMemoryPrivilege" ,"Lock pages in memory"`
    -replace "SeMachineAccountPrivilege" ,"Add workstations to the domain"`
    -replace "SeManageVolumePrivilege" ,"Manage the files on a volume"`
    -replace "SeNetworkLogonRight" ,"Access this Computer from the Network"`
    -replace "SeProfileSingleProcessPrivilege" ,"Profile a single process"`
    -replace "SeRelabelPrivilege" ,"Modify an object label"`
    -replace "SeRemoteInteractiveLogonRight" ,"Allow logon through terminal services"`
    -replace "SeRemoteShutdownPrivilege" ,"Force shutdown from a remote system"`
    -replace "SeRestorePrivilege" ,"Restore files and directories"`
    -replace "SeSecurityPrivilege" ,"Manage auditing and security log"`
    -replace "SeServiceLogonRight" ,"Logon as a service"`
    -replace "SeShutdownPrivilege" ,"Shut down the system"`
    -replace "SeSyncAgentPrivilege" ,"Synchronize directory service data"`
    -replace "SeSystemEnvironmentPrivilege" ,"Modify firmware environment values"`
    -replace "SeSystemProfilePrivilege" ,"Profile system performance"`
    -replace "SeSystemTimePrivilege" ,"Change the system time"`
    -replace "SeTakeOwnershipPrivilege" ,"Take ownership of files or other objects"`
    -replace "SeTcbPrivilege" ,"Act as part of the operating system"`
    -replace "SeTimeZonePrivilege" ,"Change the time zone"`
    -replace "SeTrustedCredManAccessPrivilege" ,"Access Credential Manager as a trusted caller"`
    -replace "SeUndockPrivilege" ,"Remove computer from docking station"`
    -replace "SeUnsolicitedInputPrivilege" ,"Read unsolicited data from a terminal device"  | Set-Content c:\temp\secedit_user_right.inf

    (Get-Content c:\temp\secedit_user_right.inf) |
    ForEach-Object {
         $line = $_
         $parm = $line.split('=')[0]
         $value = $line.split('=')[1]
         $count = $value.split(',').Getupperbound(0)+1
                  
         if ($count -ge 1 -and $value -match "S-") 
         {
            for ($i=1;$i -le $count; $i++){
                
                $orig_SID = $value.split(',')[$i-1].Trim().trimstart('*')
                
                if ($orig_SID -match "S-")
                {
                    $mapped_user =  return_SID $value.split(',')[$i-1].Trim().TrimStart('*')
                    $line = $line -replace $orig_SID,$mapped_user
                }
            }  
            $line >> C:\temp\secedit_user_mapped.inf
         }
         else {$line >> C:\temp\secedit_user_mapped.inf }
     }
     
     Remove-Item c:\temp\secedit_user_right.inf

}

Function clean-policy-txt
{
Remove-Item c:\temp\secedit1.inf
Remove-Item c:\temp\secedit_log.log
Remove-Item c:\temp\secedit_user_mapped.inf
}


Function audit-policy 
{
    $content = Get-Content c:\temp\secedit1.inf

    $policyitem = $args[0] 
    $policyexpectedvalue = $args[1]
    $remark = $args[2]
    $found = $false
    foreach ($line in $content)
    {
        $parm = $line.split('=')[0]
        $value = $line.split('=')[1]
            
        if ($parm.Trim() -eq $policyitem) 
            {
            $found = $true
            if ($value.trim() -eq $policyexpectedvalue)
                {
                    $CaseProperties = @{
                    Test_Case =  $remark + '-' + $parm + 'SHOULD BE ' + $policyexpectedvalue
                    Test_Actual = $value 
                    Test_Expected = $policyexpectedvalue
                    Test_Result = 'PASSED' 
                    }
                    $global:SuccessCase = $global:SuccessCase + 1  
                }
            Else
                 {     
                    $CaseProperties = @{
                    Test_Case =   $remark + '-' + $parm + ' SHOULD BE ' + $policyexpectedvalue
                    Test_Actual = $value
                    Test_Expected = $policyexpectedvalue
                    Test_Result = 'FAILED' 
                    }
                    $global:FailedCase = $global:FailedCase + 1  
                }

            }
        
    }
    $global:Result_set += New-Object PSObject -Property $CaseProperties

    #if ($found -eq $true) {}
    <#-else {
        $CaseProperties = @{
                    Test_Case =   $remark + '-' + $parm + ' SHOULD BE ' + $policyexpectedvalue
                    Test_Actual = 'NOT FOUND'
                    Test_Expected = $policyexpectedvalue
                    Test_Result = 'FAILED' 
                    }
        $global:FailedCase = $global:FailedCase + 1  
        $global:Result_set += New-Object PSObject -Property $CaseProperties
    }-#>
    
}

Function audit-ntlm-auth
{
    $ntlmconfig = Get-ItemProperty Registry::"\HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\"
    
    $hex_ntlmcliconfig = [convert]::tostring($ntlmconfig.NtlmMinClientSec,16)  # Client NTLM Setup
    $hex_ntlmserconfig = [convert]::tostring($ntlmconfig.NtlmMinServerSec,16)  # Server NTLM Setup
    
    $swt_ntlmcliconfig = switch($hex_ntlmcliconfig) {
        00000100 { "Netware"}
        00000200 { "NTLM"}
        00000400 { "Anonymous"}
        00001000 { "Domain supplied"}
        00002000 { "Workstation" }
        00004000 { "LocalCall" }
        00008000 { "NTLMv2 Session Key" }
        00080000 { "target" }
        20000000 { "128-bit"}
        40000000 { "Key-Exchange" }
        80000000 { "56-bit" }
        20080000 { "128bit + NTLMv2"}
        default {"unknown"}
    }
 
    $swt_ntlmserconfig = switch($hex_ntlmserconfig) {
        00000100 { "Netware"}
        00000200 { "NTLM"}
        00000400 { "Anonymous"}
        00001000 { "Domain supplied"}
        00002000 { "Workstation" }
        00004000 { "LocalCall" }
        00008000 { "NTLM2 Key" }
        00800000 { "target" }
        20000000 { "128-bit"}
        40000000 { "Key-Exchange" }
        80000000 { "56-bit" }
        20080000 { "128bit + NTLMv2"}
        default {"unknown"}
    }
    
    if ($hex_ntlmcliconfig -eq 20080000) 
    {
        $CaseProperties = @{
        Test_Case =  'Sec Option-NTLM (CLIENT) - SHOULD BE supporting strong (128-bit)+NTLMv2'
        Test_Actual = $swt_ntlmcliconfig
        Test_Expected = '128bit+NTLMv2'
        Test_Result = 'PASSED' 
        }
        $global:SuccessCase = $global:SuccessCase + 1  
    }
    else
    {     
        $CaseProperties = @{
        Test_Case =  'Sec Option-NTLM (CLIENT) - SHOULD BE supporting strong (128-bit)+NTLMv2'
        Test_Actual = $swt_ntlmcliconfig
        Test_Expected = '128bit+NTLMv2'
        Test_Result = 'FAILED' 
        }
            
        $global:FailedCase = $global:FailedCase + 1  
    }
    $global:Result_set += New-Object PSObject -Property $CaseProperties

    
    if ($hex_ntlmserconfig -eq 20080000) 
    {
        $CaseProperties = @{
        Test_Case =  'Sec Option-NTLM (SERVER) - SHOULD BE supporting strong (128-bit)+NTLMv2'
        Test_Actual = $swt_ntlmserconfig
        Test_Expected = '128bit+NTLMv2'
        Test_Result = 'PASSED' 
        }
        $global:SuccessCase = $global:SuccessCase + 1  
    }
    else
    {     
        $CaseProperties = @{
        Test_Case =  'Sec Option-NTLM (SERVER) - SHOULD BE supporting strong (128-bit)+NTLMv2'
        Test_Actual = $swt_ntlmserconfig
        Test_Expected = '128bit+NTLMv2'
        Test_Result = 'FAILED' 
        }
            
        $global:FailedCase = $global:FailedCase + 1  
    }
    $global:Result_set += New-Object PSObject -Property $CaseProperties

}

<# - function: check on the cipher and match if they are enabled / disabled -#>
Function audit-RDP-MinEncrypt
{
$NLAEncrypt = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices `
-Filter "TerminalName='RDP-tcp'").MinEncryptionLevel

    $swt_NLAEncrypt = switch($NLAEncrypt){0 {"Low"} 1 {"Medium"} 2 {"High"} 3 {"FIPS"} }

    if ($NLAEncrypt -eq 2){

            $CaseProperties = @{
            Test_Case =  'RDP - Encryption Level - SHOULD BE High(2)'
            Test_Actual = $swt_NLAEncrypt
            Test_Expected = 'High'
            Test_Result = 'PASSED' 
            }
            $global:SuccessCase = $global:SuccessCase + 1  
    }
    else
    {     
            $CaseProperties = @{
            Test_Case =  'RDP - Encryption Level - SHOULD BE High(2)'
            Test_Actual = $swt_NLAEncrypt
            Test_Expected = 'High'
            Test_Result = 'FAILED' 
            }
            
            $global:FailedCase = $global:FailedCase + 1  
    }
        $global:Result_set += New-Object PSObject -Property $CaseProperties
    
}

Function audit-RDP-NLAAuth
{
    $NLAAuth = (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices  -Filter "TerminalName='RDP-tcp'").UserAuthenticationRequired

    $swt_NLAAuth = switch($NLAAuth){0 {"Disabled"} 1 {"Enabled"} }

    if ($NLAAuth -eq 1){

            $CaseProperties = @{
            Test_Case =  'RDP Network Level Auth (NLA) - SHOULD BE Enabled'
            Test_Actual = $swt_NLAAuth
            Test_Expected = 'Enabled'
            Test_Result = 'PASSED' 
            }
            $global:SuccessCase = $global:SuccessCase + 1  
    }
    else
    {     
            $CaseProperties = @{
            Test_Case =  'RDP Network Level Auth (NLA) - SHOULD BE Enabled'
            Test_Actual = $swt_NLAAuth
            Test_Expected = 'Enabled'
            Test_Result = 'FAILED' 
            }
            
            $global:FailedCase = $global:FailedCase + 1  
    }
        $global:Result_set += New-Object PSObject -Property $CaseProperties
    
    <#-need to include back to registry check -#>
    
    if (Test-path -path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"){ 
        $promptforpwd = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\" "fPromptForPassword" -ErrorAction SilentlyContinue}
    else{$promptforpwd = 0}
    
    if ($promptforpwd.fPromptForPassword -eq 1) 
    {
        $CaseProperties = @{
        Test_Case =  'RDP - PromptForPassword - SHOULD BE ENABLED' 
        Test_Actual = 'Enabled'
        Test_Expected = 'Enabled'
        Test_Result = 'PASSED' 
        }
        $global:SuccessCase = $global:SuccessCase + 1  
    }
    else
    {     
        $CaseProperties = @{
        Test_Case =  'RDP - PromptForPassword - SHOULD BE ENABLED' 
        Test_Actual = 'Not found or disabled'
        Test_Expected = 'Enabled'
        Test_Result = 'FAILED' 
        }
            
        $global:FailedCase = $global:FailedCase + 1  
    }
    $global:Result_set += New-Object PSObject -Property $CaseProperties

}

Function audit-test-cipher
{
    
    $name = $args[0].PSChildName
    $value = $args[0].Enabled
    $valid_value = $args[1]
    $remark = $args[2]
    
    if ($value -gt 0) {$value = 1}
    if ($remark -eq $null) {$remark = ""}else{$remark = $remark + '/'}
    $swt_value = switch($value){0 {"Disabled"} 1 {"Enabled"} default {"NOT FOUND"} }
    $swt_valid_value = switch($valid_value){0 {"Disabled"} 1 {"Enabled"} default {"NOT FOUND"} }
 
    if ($value -eq $valid_value ){

            $CaseProperties = @{
            Test_Case =  $remark + $name + ' - SHOULD BE ' + $swt_valid_value
            Test_Actual = $swt_value
            Test_Expected = $swt_valid_value
            Test_Result = 'PASSED' 
            }
            $global:SuccessCase = $global:SuccessCase + 1  
    }
    else
    {   $CaseProperties = @{
            Test_Case =  $remark + $name + ' - SHOULD BE ' + $swt_valid_value
            Test_Actual = $swt_value
            Test_Expected = $swt_valid_value
            Test_Result = 'FAILED' 
            }
            $global:FailedCase = $global:FailedCase + 1  
    }
        $global:Result_set += New-Object PSObject -Property $CaseProperties 
    
   
}

Function GetPKICipherReg 
{     
    $ReturnValues = new-object PSObject 
    $Time = Get-Date 
    #Do Registry data collection. 
 
     
    #RC4/128/128
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128") 
        {$RC4128128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" 
         audit-test-cipher $RC4128128Reg 0   #RC4128128 should be disabled
        }
    else{ Failed-cipher-report 'RC4/128/128' 0 ''}


    #AES/128/128
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128") 
        {$AES128128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 128/128"
        audit-test-cipher $AES128128Reg 1   #AES128128 should be enabled
        }
     else{ Failed-cipher-report 'AES/128/128' 0 ''}
    
    #AES/256/256
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256") 
        {$AES256256Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\AES 256/256"
         audit-test-cipher $AES256256Reg 1   #AES128128 should be enabled
        }
    else{ Failed-cipher-report 'AES/256/256' 0 ''}

    #3DES/168/168
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168") 
        {$TripleDES168Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168"
        audit-test-cipher $TripleDES168Reg 0   #Triple DES 168 should be disabled
        }
    else{ Failed-cipher-report '3DES/168/168' 0 ''}

    #RC4/56/128
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128") 
        {$RC456128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128"
        audit-test-cipher $RC456128Reg 0   #RC4/56/128 should be disabled
        }
    else{ Failed-cipher-report 'RC4/56/128' 0 ''}
                
    #DES/56/56
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56") 
        {$DES5656Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56"
        audit-test-cipher $DES5656Reg 0   #DES/56/56 should be disabled
        }
    else{ Failed-cipher-report 'DES/56/56' 0 ''}
    
    #RC4/40/128
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128") 
        {$RC440128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128"
        audit-test-cipher $RC440128Reg 0   #RC4/40/128 should be disabled
        }
    else{ Failed-cipher-report 'RC4/40/128' 0 ''}

    #NULL
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL") 
        {$NULLReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\NULL"
        audit-test-cipher $NULLReg 0   #NULL should be disabled
        } 
    else{ Failed-cipher-report 'NULL' 0 ''}

    #RC2 40/128
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128") 
        {$RC240128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" 
        audit-test-cipher $RC240128Reg 0   #RC2/40/128 should be disabled
        }
    else{ Failed-cipher-report 'RC2/40/128' 0 ''}

    #RC2 128/128
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128") 
        {$RC2128128Reg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128"
        audit-test-cipher $RC2128128Reg 0   #RC2/40/128 should be disabled
        }
    else{ Failed-cipher-report 'RC2/128/128' 0 ''}

    #hashes MD5
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5") 
        {$MD5HashReg = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5
        audit-test-cipher $MD5HashReg 0   #MD5hash should be disabled
        }
    else{ Failed-cipher-report 'MD5' 0 'HASH-'}


    #hashes SHA
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA") 
        {$SHAHashReg = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA
        audit-test-cipher $SHAHashReg 0   #SHA1hash should be disabled
        }
    else{ Failed-cipher-report 'SHA1' 0 'HASH-'}
        
    #hashes SHA256
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256") 
        {$SHA256HashReg = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA256
        audit-test-cipher $SHA256HashReg 1   #SHA256hash should be disabled
        }
    else{ Failed-cipher-report 'SHA256' 1 'HASH-'}

    #hashes SHA384
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384") 
        {$SHA384HashReg = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA384
        audit-test-cipher $SHA384HashReg 1   #SHA384hash should be disabled
        }
    else{ Failed-cipher-report 'SHA384' 1 'HASH-'}

    #hashes SHA512
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512") 
        {$SHA512HashReg = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA512
        audit-test-cipher $SHA512HashReg 1   #SHA512hash should be disabled
        }
    else{ Failed-cipher-report 'SHA512' 1 'HASH-'}

    #CIPHER ORDER ???? -> to be determined
    #if (Test-path -path Registry::"HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002") 
    #    {$NCRYPTSChannelReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002"} 
    #if (Test-path -path Registry::"HKLM\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003") 
    #   {$NCRYPTSChannelSigReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010003"}     
    

    #Disabling RSA use in KeyExchange PKCS  
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS") 
        {$PKCSKeyXReg = Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS
         audit-test-cipher $PKCSKeyXReg 1   #PKCSKeyXReg should be disabled
        }
    else{ Failed-cipher-report 'PKCS' 1 ''}

    #PCT1.0
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client") 
        {$PCT1ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Client"
        audit-test-cipher $PCT1ClientReg 0 'PCT1.0'   #PCT1.0 should be disabled
        }
    else{ Failed-cipher-report 'PCT1.0 Client' 0 ''}

    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server") 
        {$PCT1ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\PCT 1.0\Server"
        audit-test-cipher $PCT1ServerReg 0 'PCT1.0'  #PCT1.0 should be disabled
        }
    else{ Failed-cipher-report 'PCT1.0 Server' 0 ''}

    #SSL2.0
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client") 
        {$SSL2ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client"
        audit-test-cipher $SSL2ClientReg 0 'SSL2.0'  #SSL2.0 should be disabled
        }
    else{ Failed-cipher-report 'SSL2.0 Client' 0 ''}
        
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server") 
        {$SSL2ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server"
        audit-test-cipher $SSL2ServerReg 0 'SSL2.0'  #SSL2.0 should be disabled
        }
    else{ Failed-cipher-report 'SSL2.0 Server' 0 ''}

    #SSL3.0
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client") 
        {$SSL3ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
        audit-test-cipher $SSL3ClientReg 0 'SSL3.0'  #SSL3.0 should be disabled
        }
    else{ Failed-cipher-report 'SSL3.0 Client' 0 ''}

    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server") 
        {$SSL3ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" 
        audit-test-cipher $SSL3ServerReg 0 'SSL3.0' #SSL3.0 should be disabled
        }
    else{ Failed-cipher-report 'SSL3.0 Server' 0 ''}

    #TLS1.0
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client") 
        {$TLS1ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
        audit-test-cipher $TLS1ClientReg 1 'TLS1.0' #TLS1.0 should be enabled - as of 2016 guideline
        }
    else{ Failed-cipher-report 'TLS1.0 Client' 1 ''}

    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server") 
        {$TLS1ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
        audit-test-cipher $TLS1ServerReg 1 'TLS1.0'  #TLS1.0 should be enabled - as of 2016 guideline
        }
    else{ Failed-cipher-report 'TLS1.0 Server' 1 ''}
    #TLS1.1
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client") 
        {$TLS11ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
        audit-test-cipher $TLS11ClientReg 1 'TLS1.1'  #TLS1.1 should be enabled
        }
    else{ Failed-cipher-report 'TLS1.1 Client' 1 ''}


    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server") 
        {$TLS11ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server"
        audit-test-cipher $TLS11ServerReg 1 'TLS1.1'  #TLS1.1 should be enabled 
        }
    else{ Failed-cipher-report 'TLS1.1 Server' 1 ''}

    #TLS1.2
    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client") 
        {$TLS12ClientReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
        audit-test-cipher $TLS12ClientReg 1 'TLS1.2'  #TLS1.2 should be enabled
        }
    else{ Failed-cipher-report 'TLS1.2 Client' 1 ''}

    if (Test-path -path Registry::"HKLM\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server") 
        {$TLS12ServerReg = Get-ItemProperty -Path Registry::"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
        audit-test-cipher $TLS12ServerReg 1 'TLS1.2'  #TLS1.2 should be enabled
        }
    else{ Failed-cipher-report 'TLS1.2 Server' 1 ''}
}

Function Audit-test-logmode
{
    
    $logname = $args[0]
    $valid_logmode = $args[1]
    $valid_logsize = $args[2]

    $Log = Get-Winevent -ListLog $logname -Force | select LogMode

    if ($Log.LogMode -ne 'Retain')
    {

        $CaseProperties = @{
        Test_Case =  $logname + ' log archive mode - SHOULD BE ' + $valid_logmode
        Test_Actual = $Log.LogMode
        Test_Expected = $valid_logmode
        Test_Result = 'FAILED' 
        }
        $global:FailedCase = $global:FailedCase + 1       
    }
    else
    {
        $CaseProperties = @{
        Test_Case =  $logname + ' log archive mode - SHOULD BE ' + $valid_logmode
        Test_Actual = $Log.LogMode
        Test_Expected = $valid_logmode
        Test_Result = 'PASSED' 
        }
        $global:SuccessCase = $global:SuccessCase + 1  
    }
    
    $global:Result_set += New-Object PSObject -Property $CaseProperties


    $Logsize = Get-Winevent -ListLog $logname | select MaximumSizeInBytes
    
    if ($Logsize.MaximumSizeInByte -lt $valid_logsize)
    {
        $CaseProperties = @{
            Test_Case = $Logname + ' log filesize (bytes) - SHOULD BE at least ' + $valid_logsize 
            Test_Actual = $Logsize.MaximumSizeInBytes 
            Test_Expected = $valid_logsize   
            Test_Result = 'FAILED'        
        }
        $global:FailedCase = $global:FailedCase + 1 
        
    }
    else
    {
        $CaseProperties = @{
        Test_Case = $Logname + ' log filesize (bytes) - SHOULD BE at least ' + $valid_logsize 
        Test_Actual = $Logsize.MaximumSizeInBytes 
        Test_Expected = $valid_logsize   
        Test_Result = 'FAILED'        
        }    
        $global:SuccessCase = $global:SuccessCase + 1  
    }

    $global:Result_set += New-Object PSObject -Property $CaseProperties

}

Function Audit-test-auditpol
{
    $name = $args[0]
    $value = $args[1]
    $valid_item = $args[2]
    $valid_value = $args[3]

     if ($name -eq $valid_item) 
       {
            
            if ($value -eq $valid_value)
            {
                $CaseProperties = @{
                Test_Case = $name + ' - SHOULD BE audited as ' + $valid_value
                Test_Actual = $value
                Test_Expected = $valid_value  
                Test_Result = 'PASSED'        
                }
                $global:SuccessCase = $global:SuccessCase + 1              
                
            }            
            else
            {
                $CaseProperties = @{
                Test_Case = $name + ' - SHOULD BE audited as ' + $valid_value
                Test_Actual = $value
                Test_Expected = $valid_value 
                Test_Result = 'FAILED'        
                }       
                $global:FailedCase = $global:FailedCase + 1
            }    
                  
       $global:Result_set += New-Object PSObject -Property $CaseProperties 
       
       }

}


<## MAIN FUNCTIONS ##>


<# --- SECURITY / APPLICATION / SYSTEM / SETUP LOG CONFIGURATION REVIEW ---#>

    <# Test the security log size and log mode #>
    Audit-test-logmode 'security' 'Retain' 201326592

    <# Test the system log size and log mode #>
    Audit-test-logmode 'system' 'Retain' 201326592

    <# Test the system log size and log mode #>
    Audit-test-logmode 'setup' 'Retain' 201326592

    <# Test the system log size and log mode #>
    Audit-test-logmode 'application' 'Retain' 33554432

<# --- CIPHER SUITE REVIEW --- #>
    <# CHECK THE CIPHER SUITE SUPPORTED ON THE WINDOWS SERVER #>
    GetPKICipherReg 


<# Test the audit policy application status #>
AuditPol /Get /Category:* /R > C:\Temp\AuditPol.csv

$audititem = Import-Csv C:\Temp\AuditPol.csv -Delimiter ',' |
ForEach-Object {
       
       $input_name = $_.Subcategory.trim()
       $input_value = $_."Inclusion Setting".trim()
       
       <# 17.1 Credential Validation #>
       audit-test-auditpol $input_name $input_value 'Credential Validation' 'Success and Failure'

       <# 17.2.1 Application Group Management #>     
       audit-test-auditpol $input_name $input_value 'Application Group Management' 'Success and Failure'

       <# 17.2.2 Computer Account Management #>     
       audit-test-auditpol $input_name $input_value 'Computer Account Management' 'Success and Failure'

       <# 17.2.3 Distribution Group Management#>     
       audit-test-auditpol $input_name $input_value 'Distribution Group Management' 'Success and Failure'
 
       <# 17.2.4 Other Account Management Events #>     
       audit-test-auditpol $input_name $input_value 'Other Account Management Events' 'Success and Failure'
 
       <# 17.2.5 Security Group Management #>     
       audit-test-auditpol $input_name $input_value 'Security Group Management' 'Success and Failure'

       <# 17.2.6 User Account Management #>     
       audit-test-auditpol $input_name $input_value 'User Account Management' 'Success and Failure'

       <# 17.3.1 Process Creation #>     
       audit-test-auditpol $input_name $input_value 'Process Creation' 'Success'

       <# 17.4.1 Directory Service Access#>     
       audit-test-auditpol $input_name $input_value 'Directory Service Access' 'Success and Failure'

       <# 17.4.2 Directory Service Changes #>     
       audit-test-auditpol $input_name $input_value 'Directory Service Changes' 'Success and Failure'

       <# 17.5.1   Account Lockout#>     
       audit-test-auditpol $input_name $input_value 'Account Lockout' 'Success'

       <# 17.5.2   Logoff#>     
       audit-test-auditpol $input_name $input_value 'Logoff' 'Success'

       <# 17.5.3   Logon#>     
       audit-test-auditpol $input_name $input_value 'Logon' 'Success and Failure'

       <# 17.5.4   Other Logon/Logoff Events#>     
       audit-test-auditpol $input_name $input_value 'Other Logon/Logoff Events' 'Success and Failure'

       <# 17.6     Removable Storage#>     
       audit-test-auditpol $input_name $input_value 'Removable Storage' 'Success and Failure'

       <# 17.7.1   Policy Change#>     
       audit-test-auditpol $input_name $input_value 'Audit Policy Change' 'Success and Failure'

       <# 17.7.2   Authentication Policy Change #>     
       audit-test-auditpol $input_name $input_value 'Authentication Policy Change' 'Success and Failure'

       <# 17.8    Sensitive Privilege Use#>     
       audit-test-auditpol $input_name $input_value 'Sensitive Privilege Use' 'Success and Failure'

       <# 17.9.1  IPsec Driver#>     
       audit-test-auditpol $input_name $input_value 'IPsec Driver' 'Success and Failure'

       <# 17.9.2  Other System Events#>     
       audit-test-auditpol $input_name $input_value 'Other System Events' 'Success and Failure'

       <# 17.9.3  Security State Change#>     
       audit-test-auditpol $input_name $input_value 'Security State Change' 'Success and Failure'

       <# 17.9.4  Security System Extension#>     
       audit-test-auditpol $input_name $input_value 'Security System Extension' 'Success and Failure'

       <# 17.9.5  Security Integrity#>     
       audit-test-auditpol $input_name $input_value 'Security Integrity' 'Success and Failure'
       
       audit-test-auditpol $input_name $input_value 'File System' 'Success and Failure'

       audit-test-auditpol $input_name $input_value 'Registry' 'Success and Failure'

       audit-test-auditpol $input_name $input_value 'Special Logon' 'Success and Failure'


}


<# CHECK THE NLA ENABLED ON RDP #>
audit-RDP-NLAAuth

<# CHECK THE Minimum Encryption Level on RDP #>
audit-RDP-MinEncrypt


prep-policy-txt
    
<#--- PASSWORD POLICY REVIEW ---#>
    audit-policy 'PasswordHistorySize' 24 'Password Policy'      #1  24 passwords will be remembered
    audit-policy 'MaximumPasswordAge' 90 'Password Policy'       #2  90days of maximum password age
    audit-policy 'MinimumPasswordAge' 1 'Password Policy'        #3  1day minimum password age
    audit-policy 'MinimumPasswordLength' 8 'Password Policy'     #4  8 character for password length
    audit-policy 'PasswordComplexity' 1 'Password Policy'        #5  Complexity should be met
    audit-policy 'ClearTextPassword' 0  'Password Policy'        #6  Store passwords using reversible encryption - disabled
    
<#--- LOGON POLICY ---#>
    audit-policy 'LockoutDuration' 0 'Lockout Policy'            #7  Account lock out duration 0 minus
    audit-policy 'LockoutBadCount' 5 'Lockout Policy'            #8  Account lockout threadhold 5 times
    audit-policy 'ResetLockoutCount' 99999 'Lockout Policy'      #9  Reset account lockout after 99999 min
    audit-policy 'ForceLogoffWhenHourExpire' 1 'Lockout Policy'  #11  Disconnect client when logon hours expires
    
<#--- EVENT AUDIT LOGGING policy ---#>
    audit-policy 'AuditAccountLogon' 0 'Event Auditing'        #1 no auditing for account logon events
    audit-policy 'AuditAccountManage' 0 'Event Auditing'       #2 no auditing for account manage
    audit-policy 'AuditDSAccess' 0  'Event Auditing'           #3 no auditing for DS access
    audit-policy 'AuditLogonEvents' 0  'Event Auditing'        #4 no auditing for AuditAccountLogon
    audit-policy 'AuditObjectAccess' 0 'Event Auditing'        #5 no auditing for AuditObjectAccess
    audit-policy 'AuditPolicyChange' 0 'Event Auditing'        #6 no auditing for AuditPolicyChange
    audit-policy 'AuditPrivilegeUse' 0 'Event Auditing'        #7 no auditing for AuditPrivilegeUse
    audit-policy 'AuditProcessTracking' 0 'Event Auditing'     #8 no auditing for AuditProcessTracking
    audit-policy 'AuditSystemEvents' 0 'Event Auditing'        #9 no auditing for AuditSystemEvent 
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\" 'CrashOnAuditFail' 0 'Event Auditing-ShutdownIfAuditFail'
    #10 (audit: shutdown system immediately if unable to log security audits
    
<# ---- SECURITY OPTIONS ---- #>
    
    # 1 NTLM SSP (NTLM v2)
    audit-ntlm-auth

    # 2 Network Access: remotely accessible registry pathes
    audit-policy-allowedpath "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths\" 'Machine' "System\CurrentControlSet\Control\Print\Printers,System\CurrentControlSet\Services\Eventlog,Software\Microsoft\OLAP Server,Software\Microsoft\Windows NT\CurrentVersion\Print,Software\Microsoft\Windows NT\CurrentVersion\Windows,System\CurrentControlSet\Control\ContentIndex,System\CurrentControlSet\Control\Terminal Server,System\CurrentControlSet\Control\Terminal Server\UserConfig,System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration,Software\Microsoft\Windows NT\CurrentVersion\Perflib,System\CurrentControlSet\Services\SysmonLog" 'Sec Option-AllowedPath'

    # 3+4 Admin should not be admin + Guest should not be guest
    audit-guest-admin-account
    
    # 5 Accounts: Guest account status
    # cannot be automated

    # 6 Network access: Allow anonymous SID/Name translation
    # cannot be found 

    # 7 Accounts: Limit local account use of blank passwords to console logon only
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa" 'LimitBlankPasswordUse' 0 'Sec Option-Accounts-Limit use of blank pwd'
    
    # 8 Device: Allow to format/eject removable media
    audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" 'AllocateDASD' 1 'Sec Option-Device: Allow format/eject remov media'

    # 9 Device: Prevent users from installing printer drivers
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" 'AddPrinterDrivers' 1 'Sec Option-Prevent Printer Drivers'

    # 10 Device: Restrict CD-ROM access - #audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" 'AllocateCDRoms' 1 'Devices: Restrict CD-ROM access'
    # cannot be found

    # 11 Devices: Restrict floppy access - #audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" 'Allocatefloppies' 1 'Devices: Restrict floppy access'
    # cannot be found

    # 12 Domain member: Digitally encrypt or sign secure channel data (always)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\" 'RequireSignOrSeal' 1 'Sec Option-Always Digitally encrypt/sign secure channel data'

    # 13 Domain member: Digitally encrypt secure channel data (when possible)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\" 'SealSecureChannel' 1 'Sec Option-Outgoing secure channel data signed when possible.'

    # 14 Domain member: Digitally sign secure channel data (when possible)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\" 'SignSecureChannel' 1 'Sec Option-When possible, Digitally encrypt/sign secure channel data'

    # 15 Domain member: Disable machine account password changes
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\" 'DisablePasswordChange' 0 'Sec Option-Disable Machine Account Password Changes'
    
    # 16 Domain member: Maximum Machine Account Password Age”
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\" 'MaximumPasswordAge' 30 'Sec Option-Maximum Machine Account Password Age'

    # 17 Domain member: Require Strong Session Key
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\" 'RequireStrongKey' 1 'Sec Option-Require Strong Session key'

    # 18 NOT FOR DOMAIN MEMBER
    # 19 NOT FOR DOMAIN MEMBER
    # 20 NOT FOR DOMAIN MEMBER

    # 21 Interactive Logon - do not dispay last name
    audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" 'DontDisplayLastUserName' 1 'Sec Option-Interactive logon-Do not display last name'

    # 22 Interactive Logon - do not require ctrl-alt-del
    audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\" 'DisableCAD' 0 'Sec Option-Interactive logon-Do not require Ctrl-alt-del'

    # 23 CANNOT BE AUTOMATED
    audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" 'CachedLogonsCount' 0 'Sec Option-Previous logons to cache'

    # 24 Prompt user to change password before expiration
    audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" 'PasswordExpiryWarning' 14 'Sec Option-Prompt user to change password'

    # 25 CANNOT FIND THE REGISTRY CORRESPONDING

    # 26 SMARTCARD REMOVAL BEHAVIOR (scremove) SHOULD BE 'lock workstation' (i.e 1)
    audit-policy-registry "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'SCRemoveOption' 1 'Sec Option-SmartCardRemove option'

    # 27 LEGALNOTICETEXT SHOULD BE 'NOTHING' (i.e 1)
    audit-policy-registry "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" 'LegalNoticeText' '' 'Sec Option-LegalNoticeText' 
    
    # 28 NOT FOUND
    # 29 NOT FOUND
    
    # 30 Microsoft network client: Digitally sign communications (always)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\" 'RequireSecuritySignature' 1 'Sec Option-Enable client-Digitally sign communications (always)'

    # 31 NOT FOUND
    # 32 NOT FOUND
    # 33 NOT FOUND
    
    # 34 Microsoft network server: Digitally sign communications (always)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\" 'RequireSecuritySignature' 1 'Sec Option-Enable server-Digitally sign communications (always)'

    # 35 Microsoft network server: Digitally sign communications (if client agrees)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\" 'EnableSecuritySignature' 1 'Sec Option-SMB server must perform packet signing when possible'

    # 36 Microsoft network server: Disconnect clients when logon hours expire
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\" 'EnableForcedLogoff' 1 'Sec Option-Force disconnected when their logon hours expire'
    
    # 37 Network access: Do not allow anonymous enumeration of SAM accounts
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\" 'RestrictAnonymous' 1 'Sec Option-Do not allow anonymous enumeration of SAM accounts'

    # 38 Network access: Do not allow anonymous enumeration of SAM accounts and shares
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\" 'RestrictAnonymousSAM' 1 'Sec Option-Do not allow anonymous enumeration of SAM accounts and share'

    # 39 cannot be automated

    # 40 cannot be automated

    # 41 Network access: Named pipes that can be accessed anonymously
    # audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\" 'NullSessionPipes' $NULL 'Sec Option-Network access: Named pipes that can be accessed anonymously'

    # 42 Network access: Remotely accessible registry paths
    audit-policy-allowedpath "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths\" 'Machine' "System\CurrentControlSet\Control\ProductOptions,System\CurrentControlSet\Control\Server Applications,Software\Microsoft\Windows NT\CurrentVersion" 'Sec Option-AllowedExactPath'
    
    # 43 Network access: Restrict anonymous access to Named Pipes and Shares
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\" 'RestrictNullSessAccess' 1 'Sec Option-Restrict anonymous access to Named Pipes and Shares'

    # 44 Network access: Shares that can be accessed anonymously
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\" 'NullSessionShares' '' 'Sec Option-Shares can be access anonymously'

    # 45 Network access: Sharing and security model for local accounts
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\" 'ForceGuest' 0 'Sec Option-Network access: Sharing and security model for local accounts'

    # 46 Network access: Prevent Storage of LAN Manager Hash
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\" 'NoLMHash' 1 'Sec Option-prevent the storage of the LAN Manager hash of passwords'

    # 47 Network access: LAN Manager authentication level is 5
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa\" 'LmCompatibilityLevel' 5 'Sec Option-Network security: LAN Manager authentication level'

    # 48 Network access: LDAP Client Signing Requirement
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP\" 'LDAPClientIntegrity' 1 'Sec Option-Network security: LDAP client signing requirements'

    # 49 ntlm -> checked already at 1st item

    # 50 Network access: Recovery console: Allow automatic administrative logon
    audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\" 'SecurityLevel' 0 'Sec Option-Recovery console: Disable automatic administrative logons'

    # 51 NOT FOUND

    # 52 NOT FOUND

    # 53 NOT FOUND

    # 54 System objects: Require case insensitivity for non-Windows subsystems
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\" 'ObCaseInsensitive' 1 'Sec Option-System objects: Require case insensitivity for non-Windows subsystems'

    # 55 System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\" 'ProtectionMode' 1 'Sec Option-Strengthen default permissions of internal system objects'

    # 56 NOT FOUND
    
    # 57 cannot be automate

    # 58 DISABLE - Use Certificate Rules on Windows Executables for Software Restriction Policies 
    audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers\" 'AuthenticodeEnabled' 0 'Sec Option-Use Certificate Rules on Windows Executables for Software Restriction Policies'

    # 59 MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)
    audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" 'AutoAdminLogon' 0 'Sec Option-MSS: (AutoAdminLogon) Enable Automatic Logon (not recommended)'

    # 60 MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\" 'DisableIPSourceRouting' 2 'Sec Option-MSS: Disable IP Source Routing'
    
    # 61 MSS: MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF generated routes
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\" 'EnableICMPRedirect' 0 'Sec Option-MSS: Enable ICMP Redirect'
    
    # 62 MSS: (KeepAliveTime) How often keep-alive packets are sent in milliseconds
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\" 'KeepAliveTime' 300000 'Sec Option-MSS: Keep Alive packets'

    # 63 MSS: Configure IPSec exemptions for various types of network traffic
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\IPSEC\" 'NoDefaultExempt' 3 'Sec Option-MSS: Configure IPSec exemptions'

    # 64 MSS: ignore NetBIOS name release requests except from WINS servers
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Netbt\Parameters\" 'NoNameReleaseOnDemand' 1 'Sec Option-MSS: Ignore NetBIOS except from WINS'

    # 65 not found

    # 66 MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\" 'PerformRouterDiscovery' 0 'Sec Option-MSS: Allow IRDP to detect and configure Default Gateway addresses'

    # 67 Enable Safe DLL search mode (recommended)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\" 'SafeDllSearchMode' 1 'Sec Option-MSS: Enable Safe DLL search mode'

    # 68 The time in seconds before the screen saver grace period expires
    audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\" 'ScreenSaverGracePeriod' 5 'Sec Option-MSS: ScreenSaverGracePeriod'

    # 69 MSS: (TCPMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default) 
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip\Parameters\" 'TcpMaxDataRetransmissions' 3 'Sec Option-MSS: TCPMaxDataRetransmissions for un-ACK'

    # 70 MSS: (WarningLevel) Percentage threshold for the security event log at which the system will generate a warning
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Eventlog\Security\" 'WarningLevel' 90 'Sec Option: Percentage Threshold for security log to generate warning'

    # 71 MSS: (DisableIPSourceRouting IPv6) IP source routing protection level (protects against packet spoofing)
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters\" 'DisableIpSourceRouting' 2 'Sec Option-MSS: Disable Source routing (IPv6)'

    # 72 MSS: (TCPMaxDataRetransmissions) How many times unacknowledged data is retransmitted for IPv6 (3 recommended, 5 is default) 
    audit-policy-registry "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip6\Parameters\" 'TcpMaxDataRetransmissions' 3 'Sec Option: Percentage Threshold for security log to generate warning'

<# ---- USER ACCOUNT CONTROL ---- #>
    Audit-UserAccountControl 'FilterAdministratorToken'   1 'UAC--Admin Approval Mode for the Built-in Admin account'
    Audit-UserAccountControl 'ConsentPromptBehaviorAdmin' 3 'UAC--Behavior of the elevation prompt for admin in Admin Approval Mode'
    Audit-UserAccountControl 'ConsentPromptBehaviorUser'  0 'UAC--Behavior of the elevation prompt for standard users'
    Audit-UserAccountControl 'EnableInstallerDetection'   1 'UAC--Detect application installations and prompt for elevation'
    Audit-UserAccountControl 'EnableSecureUIAPaths'       1 'UAC--Only elevate UIAccess appl that are installed in secure locations'
    Audit-UserAccountControl 'EnableLUA'                  1 'UAC--Run all admin in Admin Approval Mode'
    Audit-UserAccountControl 'PromptOnSecureDesktop'      1 'UAC--Switch to the secure desktop when prompt for elevation'
    Audit-UserAccountControl 'EnableVirtualization'       1 'UAC--Virtualize file and registry write failures to per-user locations'
    Audit-UserAccountControl 'EnableUIADesktopToggle'     0 'UAC--Allow UIAccess app to prompt for elevation without using the secure desktop'

<# ---- INTERNET COMMUNICATIONS ---- #>
    #1 - Turn off downloading of print drivers over HTTP
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\" 'DisableWebPnPDownload' 1 'INTERNET:Disable PNP Download'
    
    #2 - Turn off the "Publish to Web" task for files and folders
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" 'NoPublishingWizard' 1 'INTERNET:Disable Publish to Web option'
   
    #3 - Turn off Internet download for Web publishing and online ordering wizards
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\" 'NoWebServices' 1 'INTERNET:Disable Web publishing and online ordering wizards '
    
    #4 - Turn off printing over HTTP
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\" 'DisableHTTPPrinting' 1 'INTERNET:Disable HTTP Printing'
    
    #5 - Turn off Search Companion content file updates
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SearchCompanion\" 'DisableContentFileUpdates' 1 'INTERNET:Disable Content File Update'
    
    #6 - Turn off the Windows Messenger Customer Experience Improvement Program
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client\" 'CEIP' 1 'INTERNET:Disable Messenger Client Experience prog'
    
    #7 - Turn off Windows Update device driver searching
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching\" 'DontSearchWindowsUpdate' 1 'INTERNET:Do not search windows update'
    


<# ---- ADDITIONAL SECURITY OPTIONS ---- #>
    #1 - DO NOT PROCESS LEGACY RUN LIST
    #NOT FOUND
    
    #2 - DO NOT PROCESS RUN ONCE LIST
    #NOT FOUND

    #3 - Registry policy processing
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}\" 'NoGPOListChanges' 0 'Add Sec--Enable Group Policy reprocess even no change'
    
    #4 - Disable Offer Remote Assistance
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" 'fAllowUnsolicited' 0 'Add Sec--Disable Offer Remote Assistance'
   
    #5 - Solicited Remote Assistance
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Terminal Services\" 'fAllowToGetHelp' 0 'Add Sec--Disable Solicited Remote Assistance'

    #6 - Restrictions for Unauthenticated RPC clients
    #NOT FOUND

    #7 - RPC Endpoint Mapper Client Authentication
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Rpc\" 'EnableAuthEpResolution' 1 'Add Sec--Enable Authentication RPC client auth'

    #8 - Turn off Autoplay
    Audit-policy-registry "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\" 'NoDriveTypeAutoRun' 255 'Add Sec--Turnoff all-drive-autoplay mode'

    #9 - Enumerate administrator accounts on elevation
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\" 'EnumerateAdministrators' 0 'Add Sec--Disable Enumerate administrator accounts on elevation'

<# ---- USER RIGHTS ----#>
    # Access this computer from the network
    audit-user-rights "Access this Computer from the Network" 1 'Administrators' 'UserRights'
    audit-user-rights "Access this Computer from the Network" 1 'Authenticated Users' 'UserRights'
        
    # Adjust memory quotas for a process
    audit-user-rights "Adjust memory quotas for a process" 1 "Administrators"  'User Rights-' 
    audit-user-rights "Adjust memory quotas for a process" 1 "Local Service"  'User Rights-' 
    audit-user-rights "Adjust memory quotas for a process" 1 "Network Service"  'User Rights-' 

    # Back up files and directories
    audit-user-rights "Back up files and directories" 1 "Administrators"  'User Rights-' 
    audit-user-rights "Back up files and directories" 1 "Backup Operators"  'User Rights-' 
    
    # Bypass traverse checking
    audit-user-rights "Bypass traverse checking" 1 "Administrators" 'User Rights-' 
    audit-user-rights "Bypass traverse checking" 1  "Authenticated Users"  'User Rights-'
    audit-user-rights "Bypass traverse checking" 1  "Local Service"  'User Rights-'
    audit-user-rights "Bypass traverse checking" 1  "Network Service"  'User Rights-'
    audit-user-rights "Bypass traverse checking" 1  "Window Manager Group"  'User Rights-'
    
    # Change the system time
    audit-user-rights "Change the system time" 1 "Local Service" 'User Rights-'
    audit-user-rights "Change the system time" 1 "Administrators" 'User Rights-'

    # Create a pagefile
    audit-user-rights "Create a pagefile" 1 "Administrators" 'User Rights-'

    # Create a token object
    audit-user-rights "Create a token object" 0 "" 'User Rights-'

    #Create global objects
    audit-user-rights "Create global objects" 1 "Administrators" 'User Rights-'
    audit-user-rights "Create global objects" 1 "Local Service" 'User Rights-'
    audit-user-rights "Create global objects" 1 "Network Service" 'User Rights-'
    audit-user-rights "Create global objects" 1 "Service" 'User Rights-'

    #Create permanent shared objects
    audit-user-rights "Create permanent shared objects" 0 "" 'User Rights-'

    #Debug Programs
    audit-user-rights "Debug programs" 1 "Administrator" 'User Rights-'

    #Deny access to this computer from the network
    audit-user-rights "Deny access to this computer from the network" 0 "" 'User Rights-'

    #Enable computer and user accounts to be trusted for delegation
    audit-user-rights "Enable computer and user accounts to be trusted for delegation" 0 "Guests" 'User Rights-'

    #Force shutdown from a remote system
    audit-user-rights "Force shutdown from a remote system" 1 'Administrators' 'User Rights-'
    audit-user-rights "Force shutdown from a remote system" 1 'Server Operators' 'User Rights-'

    #Impersonate a client after authentication
    audit-user-rights "Impersonate a client after authentication" 1 'Administrators' 'User Rights-'
    audit-user-rights "Impersonate a client after authentication" 1 'Service' 'User Rights-'
    audit-user-rights "Impersonate a client after authentication" 1 'Local Service' 'User Rights-'
    audit-user-rights "Impersonate a client after authentication" 1 'Network Service' 'User Rights-'
    
    #Increase scheduling priority
    audit-user-rights "Increase scheduling priority" 1 'Administrators' 'User Rights-'

    #Load and unload device drivers
    audit-user-rights "Load and unload device drivers" 1 'Administrators' 'User Rights-'

    #Lock pages in memory
    audit-user-rights "Lock pages in memory" 0 '' 'User Rights-'

    #Manage auditing and security log
    audit-user-rights "Manage auditing and security log" 1 'Administrators' 'User Rights-'

    #Modify firmware environment values
    audit-user-rights "Modify firmware environment values" 1 'Administrators' 'User Rights-'

    #Perform volume maintenance tasks
    audit-user-rights "Perform volume maintenance tasks" 1 'Administrators' 'User Rights-'
    
    #Profile single process
    audit-user-rights "Profile a single process" 1 'Administrators' 'User Rights-'
  
    #Profile system performance
    audit-user-rights "Profile system performance" 1 'Administrators' 'User Rights-'
  
    #Remove computer from docking station
    audit-user-rights "Remove computer from docking station" 1 'Administrators' 'User Rights-'

    #Replace process level token
    audit-user-rights "Replace a process-level token" 1 'Local Service' 'User Rights-'
    audit-user-rights "Replace a process-level token" 1 'Network Service' 'User Rights-'

    #Shut down the system
    audit-user-rights "Shut down the system" 1 'Administrators' 'User Rights-'
    audit-user-rights "Shut down the system" 1 'Server Operators' 'User Rights-'

    #Add workstations to the domain
    audit-user-rights "Add workstations to the domain" 0 '' 'User Rights-'
    
    #Log on locally
    audit-user-rights "Log on locally" 1 'Administrators' 'User Rights-'

    #Allow logon through terminal services
    audit-user-rights "Allow logon through terminal services" 1 'Administrators' 'User Rights-'

    #Change the time zone
    audit-user-rights "Change the time zone" 1 'Administrators' 'User Rights-'
    audit-user-rights "Change the time zone" 1 'Local Service' 'User Rights-'
        
    #Create symbolic links
    audit-user-rights "Create symbolic links" 1 'Administrators' 'User Rights-'

    #Deny local logon
    audit-user-rights "Deny local logon" 1 'Guest' 'User Rights-'
    
    #Deny logon through terminal services
    audit-user-rights "Deny logon through terminal services" 1 'Guest' 'User Rights-'

    #Generate security audits
    audit-user-rights "Generate security audits" 1 'Local Service' 'User Rights-'
    audit-user-rights "Generate security audits" 1 'Network Service' 'User Rights-'


    #Increase a process working set
    audit-user-rights "Increase a process working set" 1 'Users' 'User Rights-'

    #Log on as a batch job
    audit-user-rights "Log on as a batch job" 1 'Administrators' 'User Rights-'
    audit-user-rights "Log on as a batch job" 1 'Backup Operators' 'User Rights-'
    audit-user-rights "Log on as a batch job" 1 'Performance Log Users' 'User Rights-'

    #Restore files and directories
    audit-user-rights "Restore files and directories" 1 'Administrators' 'User Rights-'
    audit-user-rights "Restore files and directories" 1 'Backup Operators' 'User Rights-'

    #Take ownership of files or other objects
    audit-user-rights "Take ownership of files or other objects" 1 'Administrators' 'User Rights-'
    
    #Access credential Manager as a trusted caller
    audit-user-rights "Access credential Manager as a trusted caller" 0 '' 'User Rights-'

    #Synchronize directory service data
    audit-user-rights "Synchronize directory service data" 0 '' 'User Rights-'
    

<# ---- WINRM AUDIT ----#>
    #A - WIN Remote Mgmt - Disable Basic authentication (Server)
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Service\" 'AllowBasic' 0 'add sec--Disable WINRM (Server) basic authentication'
    #B - WIN Remote Mgmt - Disable Basic authentication (Client)
    Audit-policy-registry "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WinRM\Client\" 'AllowBasic' 0 'add sec--Disable WINRM (Client) basic authentication'

<# ---- NECESSARY SOFTWARE CHECK ---- #>        
    Test-Software-installed "Symantec Endpoint Protection" "Anti-Virus"  #- Anti-virus installation check
    #Test-Software-installed "Microsoft System Center Configuration Manager Client" "SCCM" #-SCCM installation check


<# ---- SELF-SIGNED CERTIFICATE CHECK ---- #>        
Audit-self-signed-cert

<# --- clean up the files after uses ---#>
clean-policy-txt
Remove-Item C:\Temp\AuditPol.csv

<# ---- SUMMARY FORMATTING ---- #>
$end_date = get-date
$elapsed = NEW-TIMESPAN –Start $start_date –End $End_date

write-host 'Windows 2012 R2 - Hardening review ended   @ '$end_date
write-host 'Elapsed time = ' $elapsed

write-host "#--------------------------------------------------------------------"
write-host "#-------------------- TEST SUMMARY ----------------------------------"
write-host "#--------------------------------------------------------------------"

write-host "Total Failed case: " $global:FailedCase 
write-host "Total Passed case: " $global:SuccessCase
write-host "Total Error case (missing registry/parm): " $global:error_set.Count


$global:error_set 
$global:result_set | format-table -AutoSize Test_Result,Test_Expected,Test_Case,Test_Actual | Out-String -Width 170

write-host "Suspected self-signed certificate installed: " $global:selfsigned
if ($global:selfsigned -gt 0 ){ $global:selfsigned_set | FT Thumbprint,Issuer}

<# ------------------------------------------------------- #>
<# DISPLAY THE LATEST APPLIED PATCH INFORMATION FOR REVIEW #>
<# ------------------------------------------------------- #>

write-host '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'
write-host '!!<MANUAL REVIEW > Please check on the following LATEST PATCHES!!!'
write-host '!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!'

<# ------ for windows-update enabled hosts ----
$Session = New-Object -ComObject "Microsoft.Update.Session"
$Searcher = $Session.CreateUpdateSearcher()
$historyCount = $Searcher.GetTotalHistoryCount()

$Searcher.QueryHistory(0, $historyCount) | Select-Object Title,  Date #>

$wmiobject = Get-WmiObject -Class Win32_QuickFixEngineering | Select PATH,@{n="InstallDate";e={[datetime]$_.psbase.properties["InstalledOn"].Value}} -ExcludeProperty InstallDate 

$wmiobject = $wmiobject | Sort-Object -Descending InstallDate

$wmiobject | ForEach-Object{
    $string1 = [string]$_.Path 
    $date = [Datetime]$_.InstallDate
    $KBID = $string1.split('"')[1]
    $lineout = $KBID +'-'+$date 
    $lineout = $lineout.Split(' ')[0] 
    write-output $lineout

} 