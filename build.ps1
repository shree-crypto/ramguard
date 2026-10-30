# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param([switch]$Test,[switch]$M5Tools)
$ErrorActionPreference='Stop'
$cargo=Get-Command cargo.exe -ErrorAction Stop
$arguments=@($(if($Test){'test'}else{'build'}),'--manifest-path',(Join-Path $PSScriptRoot 'Cargo.toml'),'--locked')
if(!$Test){$arguments+='--release'}
if($M5Tools){$arguments+=@('--features','m5-tools')}
& $cargo.Source @arguments
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
