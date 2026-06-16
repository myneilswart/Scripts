@echo off

:: PowerShell script to extract wi-fi profiles and passwords

echo Extracting wi-fi profiles and passwords...
powershell -Command "$output = @(); ForEach ($profile in (netsh wlan show profiles | Select-String ':\s(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() })) { $password = (netsh wlan show profile name=$profile key=clear | Select-String 'Key Content\s+:\s(.+)$' | ForEach-Object { $_.Matches.Groups[1].Value.Trim() }); if ($password) { $output += 'Profile: ' + $profile + ' | Password: ' + $password } else { $output += 'Profile: ' + $profile + ' | Password: Not available' } }; $output | Tee-Object -FilePath ([Environment]::GetFolderPath('Desktop') + '\windows-wifi.txt')"
echo.
echo Results have been saved to windows-wifi.txt on your Desktop!
echo ANY KEY WILL CLOSE THIS TERMINAL!
pause