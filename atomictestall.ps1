$atomicsRoot = "C:\AtomicRedTeam\atomics"
$successList = @()
$failList = @ ()

#Get folders that start with T (e.g., T1059, T1003.001)
$techniques = Get-ChildItem -Path $atomicsRoot -Directory | 
	Where-Object { $_.Name -match '^T\d{4}(\.\d{3})?$' } |
	Select-Object -ExpandProperty Name
	
foreach ($t in $techniques) {
	Write-Host "Running technique: $t"
	try {
		Invoke-AtomicTest $t -Confirm:$false
		Write-Host "Success: $t"
		$successList += $t
	} catch {
		Write-Host "Failed: $t"
		$failList += $t
		continue
	}
	
	#run Cleanup
	Write-Host "Cleaning up technique: $t"
	try{
		Invoke-AtomicTest $t -Cleanup -Confirm:$false
	} catch {
		Write-Host "Cleanup failed for: $t"
	}
}

#Summary
Write-Host ""
Write-Host "Summary"
Write-Host "-------"

Write-Host "Successful techniques:"
$successList | ForEach-Object { Write-Host " $($_)" }

Write-Host ""
Write-Host "Failed techniques:"
$failList  | ForEach-Object { Write-Host " $($_)" }

#Write results to files
$successList | Out-File -FilePath ".\success.txt" -Encoding UTF8
$failList	 | Out-File -FilePath ".\fail.txt" -Encoding UTF8

Write-Host ""
Write-Host "Logs written to success.txt and fail.txt"