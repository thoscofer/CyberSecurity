<#VIRUS TOTAL DOWNLOAD CHECKER#>

 

<# move to the downloads location on current user#>
$hostname = hostname
cd C:\Users\Administrator.$hostname\Downloads

 

<# get all files in Downloads directory and get the hash for each file#>
$hashes = @()
$hashes = Get-ChildItem -Path "C:\Users\Administrator.$hostname\Downloads" -Recurse | ForEach-Object { Get-FileHash $_.FullName} | Select Hash

 

$hashes = $hashes | ForEach-Object{$_.hash}

 


<# check hashes against VIRUS TOTAL #>

 

$VTApiKey = "GET YOU AN API KEY FROM VT"

 

## Set TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

 

Function submit-VTHash($VThash)
{
    $VTbody = @{resource = $VThash; apikey = $VTApiKey}
    $VTresult = Invoke-RestMethod -Method GET -Uri 'https://www.virustotal.com/vtapi/v2/file/report' -Body $VTbody

 

    return $vtResult
}

 


## Loop through hashes
    foreach ($hash in $hashes)
        {
            ## Set sleep value to respect API limits (4/min) - https://developers.virustotal.com/v3.0/reference#public-vs-premium-api
                if ($samples.count -ge 4) {$sleepTime = 15}
                else {$sleepTime = 1 }
            
            ## Submit the hash!
                $VTresult = submit-VTHash($hash)
            
            ## Color positive results
                if ($VTresult.positives -ge 1) {
                    $fore = "Magenta"
                    $VTpct = (($VTresult.positives) / ($VTresult.total)) * 100
                    $VTpct = [math]::Round($VTpct,2)
                }
                else {
                    $fore = (get-host).ui.rawui.ForegroundColor
                    $VTpct = 0
                }

 

            ## Display results
                Write-Host "================================================================="
                Write-Host -f Cyan "Resource    : " -NoNewline; Write-Host $VTresult.resource
                Write-Host -f Cyan "Scan date   : " -NoNewline; Write-Host $VTresult.scan_date
                Write-Host -f Cyan "Positives   : " -NoNewline; Write-Host $VTresult.positives
                Write-Host -f Cyan "Total Scans : " -NoNewline; Write-Host $VTresult.total
                Write-Host -f Cyan "Permalink   : " -NoNewline; Write-Host $VTresult.permalink
                Write-Host -f Cyan "Percent     : " -NoNewline; Write-Host $VTpct "%" 
                
                Start-Sleep -seconds $sleepTime
        }