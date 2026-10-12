<#!
.SYNOPSIS
  Strix 실행 래퍼 (MVP) — allowlist 강제용.
.DESCRIPTION
  targets.allow에 없는 타겟, CIDR/서브넷 입력, 업데이트 옵션은 실행하지 않고 즉시 종료한다.
  로컬/소유·허가 대상(예: juice-shop:3000)에만 사용. 외부 서버 대상 사용 금지.
.EXAMPLE
  .\run.ps1 -TargetUrl "http://127.0.0.1:3000"
#>
[CmdletBinding()]
param(
  # 스캔 대상 URL (예: http://127.0.0.1:3000)
  [Parameter(Mandatory = $true)]
  [string]$TargetUrl,

  # Strix 추가 인자 (CLI 미확정으로 모두 거부)
  [string[]]$StrixArgs
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- 0. 경로 설정 ---
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AllowFile = Join-Path $ScriptDir 'targets.allow'

# --- 1. 금지 입력 검사 ---
function Stop-WithCode([string]$Message, [int]$Code) {
  [Console]::Error.WriteLine($Message)
  exit $Code
}

# CIDR/범위 지정은 TargetUrl과 개별 추가 인자에서 검사한다.
$JoinedArgs = "$TargetUrl $($StrixArgs -join ' ')"
$ForbiddenPatterns = @(
  '\d{1,3}(\.\d{1,3}){3}/\d{1,2}',  # IPv4 CIDR
  '(?i)--\s*(subnet|cidr|range)\b', # 범위 지정 옵션
  '(?i)\b(subnet|cidr)\s*='         # subnet=, cidr= 형태
)
foreach ($pat in $ForbiddenPatterns) {
  if ($JoinedArgs -match $pat) {
    Stop-WithCode "[거부] CIDR/서브넷 범위 입력은 허용되지 않습니다." 2
  }
}

# 자동 업데이트는 재현성을 깨므로 MVP에서 금지한다.
foreach ($arg in $StrixArgs) {
  if ($arg -match '(?i)^-u(?:=.*)?$|^--(update|self-update|selfupdate|upgrade|auto-update)(?:=.*)?$') {
    Stop-WithCode "[거부] 업데이트 옵션은 허용되지 않습니다." 3
  }
}

# Strix CLI/버전이 미확정이므로 옵션 전달은 모두 차단한다. 대상 덮어쓰기 등
# 확인되지 않은 CLI 인자를 전달하지 않는다.
if (@($StrixArgs).Count -gt 0) {
  Stop-WithCode "[거부] 확인되지 않은 Strix 추가 인자는 허용되지 않습니다." 7
}

# --- 2. allowlist 로드 및 형식 확인 ---
if (-not (Test-Path $AllowFile)) {
  Stop-WithCode "[오류] allowlist 파일을 찾을 수 없습니다: $AllowFile" 4
}
$Allowed = @(Get-Content $AllowFile |
  Where-Object { $_ -match '\S' -and -not $_.TrimStart().StartsWith('#') } |
  ForEach-Object { $_.Trim().ToLowerInvariant() })
$ExpectedAllowed = @('juice-shop:3000', '127.0.0.1:3000', 'localhost:3000')
if ($Allowed.Count -ne 3 -or ($Allowed | Select-Object -Unique).Count -ne 3 -or
    @($Allowed | Where-Object { $_ -notin $ExpectedAllowed }).Count -gt 0 -or
    @($ExpectedAllowed | Where-Object { $_ -notin $Allowed }).Count -gt 0) {
  Stop-WithCode "[오류] allowlist는 중복 없이 승인된 세 호스트:포트만 포함해야 합니다." 4
}

# --- 3. TargetUrl에서 호스트:포트 추출 ---
try {
  $Uri = [System.Uri]$TargetUrl
} catch {
  Stop-WithCode "[거부] URL 형식이 아닙니다." 5
}
if ($Uri.Scheme -notin @('http', 'https')) {
  Stop-WithCode "[거부] http/https 스킴만 허용됩니다." 5
}
$Port = if ($Uri.IsDefaultPort) { if ($Uri.Scheme -eq 'https') { 443 } else { 80 } } else { $Uri.Port }
$HostPort = ("{0}:{1}" -f $Uri.Host.ToLowerInvariant(), $Port)

# --- 4. allowlist 대조: 불일치 시 즉시 종료 ---
if ($Allowed -notcontains $HostPort) {
  Stop-WithCode "[거부] allowlist에 없는 타겟입니다: $HostPort." 6
}


# --- 5. 허용된 경우에도 dry-run만 표시 ---
# 실제 이미지는 사용자가 검증된 고정 버전으로 설정할 것. latest 금지.
Write-Host "[허용] 타겟 확인됨: $HostPort. dry-run이며 Strix는 실행하지 않았습니다."
Write-Host "실행 미구현: 검증된 Strix 고정 이미지/CLI가 필요합니다. 컨테이너 대상은 같은 targets-net의 juice-shop:3000입니다."
