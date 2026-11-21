# Doc OpenAI API key tu .venv\openai.key (file nay bi .gitignore, khong len Git, khong len EC2).
# Khong bao gio in key ra man hinh.
#
#   .\scripts\openai_key.ps1 models   # liet ke model ma key dung duoc (de chon -c chat_model=...)
#   .\scripts\openai_key.ps1 test <model>  # thu 1 cau hoi voi dung tham so cua chatbot (ton < 1 xu)
#   .\scripts\openai_key.ps1 push     # dua key vao AWS Secrets Manager (chay SAU khi cdk deploy)
param([Parameter(Mandatory = $true)][ValidateSet("models", "test", "push")][string]$Action,
      [string]$Model)

$ErrorActionPreference = "Stop"
$keyFile = Join-Path $PSScriptRoot "..\.venv\openai.key"
if (-not (Test-Path $keyFile)) { throw "Khong thay $keyFile" }
$key = (Get-Content -Raw $keyFile).Trim().Trim('"', "'").Trim()   # lo dan kem dau ngoac / dau cach / xuong dong
if (-not $key.StartsWith("sk-")) { throw "File $keyFile chua co key (phai bat dau bang sk-). Mo bang notepad va dan key vao." }

switch ($Action) {
  "models" {
    $resp = Invoke-RestMethod https://api.openai.com/v1/models -Headers @{ Authorization = "Bearer $key" }
    $resp.data.id | Sort-Object
  }
  "test" {
    if (-not $Model) { throw "Thieu ten model: .\scripts\openai_key.ps1 test <model>" }
    # Giong sample_app/chat_assistant.py: Responses API, max_output_tokens 800, store=false
    $body = @{ model = $Model; store = $false; max_output_tokens = 800
               instructions = "Tra loi bang tieng Viet, ngan gon."
               input = @(@{ role = "user"; content = "SQL injection la gi? Tra loi trong 2 cau." }) } | ConvertTo-Json -Depth 5
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
      $r = Invoke-RestMethod -Method Post https://api.openai.com/v1/responses -ContentType "application/json; charset=utf-8" `
        -Headers @{ Authorization = "Bearer $key" } -Body ([Text.Encoding]::UTF8.GetBytes($body))
    } catch {
      Write-Host "LOI: model '$Model' khong dung duoc: $($_.ErrorDetails.Message)" -ForegroundColor Red
      exit 1
    }
    $text = ($r.output | Where-Object type -eq "message" | ForEach-Object { $_.content } |
             Where-Object type -eq "output_text" | ForEach-Object { $_.text }) -join ""
    "Thoi gian : {0:N1} giay (chatbot cho toi da 25 giay)" -f $sw.Elapsed.TotalSeconds
    "Token     : vao $($r.usage.input_tokens), ra $($r.usage.output_tokens)"
    if ($text) { "Tra loi   : $text"; Write-Host "OK: dung duoc cho chatbot" -ForegroundColor Green }
    else { Write-Host "KHONG DUNG DUOC: tra loi rong (model ton het token vao suy nghi)" -ForegroundColor Red }
  }
  "push" {
    # Truyen key qua file tam (khong nam tren dong lenh, khong vao lich su PowerShell), xoa ngay sau do.
    $tmp = New-TemporaryFile
    try {
      Set-Content -NoNewline -Path $tmp -Value $key
      aws secretsmanager put-secret-value --region ap-southeast-1 `
        --secret-id logsentinel/openai_api_key --secret-string "file://$tmp" --query "Name" --output text
      if ($LASTEXITCODE -ne 0) { throw "aws secretsmanager loi (da cdk deploy voi -c chat_model=... chua?)" }
      Write-Host "Da dua key vao Secrets Manager. Tro ly AI dung key nay tu cau hoi ke tiep."
    } finally {
      Remove-Item -Force $tmp
    }
  }
}
