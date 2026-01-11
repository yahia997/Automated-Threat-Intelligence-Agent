# better to use schtasks or crontab in linux
# automatically updates the json report every 10 min

while($true) {
  # run fecth script every 10 min (full path)
  python "D:\Other\Control Point internship assessment\scripts\fetch_class.py"
    
  # print time stamp to check the script worked
  Write-Host "Check completed at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Cyan
    
  # Wait 600sec = 10min
  Start-Sleep -Seconds 600
}