# better to use schtasks or crontab in linux
# automatically updates the json report every 10 min
# adds logs to scripts/fetch.log

while($true) {
  # run fecth script and store the logs
  $output = & "C:\Users\Yahia\AppData\Local\Programs\Python\Python311\python.exe" "D:\Other\Control Point internship assessment\scripts\fetch.py" 2>&1

  # timestamp
  $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

  # add output to log file
  "$timestamp`n$output`n" | Out-File -FilePath "D:\Other\Control Point internship assessment\scripts\fetch.log" -Append
    
  # print time stamp to check the script worked
  Write-Host "Check completed at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
    
  # Wait 600sec = 10min
  Start-Sleep -Seconds 600
}