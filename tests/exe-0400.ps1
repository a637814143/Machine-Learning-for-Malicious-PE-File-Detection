param(
      [string]$Root = (Get-Location).Path,
      [string]$User = "$env:USERDOMAIN\$env:USERNAME"
  )

  function Set-Exe0400 {
      param(
          [string]$Path
      )

      Write-Host "Locking $Path"
      icacls $Path /inheritance:r          | Out-Null   # 取消继承，避免权限被父目录改写
      icacls $Path /grant:r "$User":R      | Out-Null   # 只给自己读权限
      icacls $Path /remove:g "Users" `
                             "Authenticated Users" `
                             "Everyone" `
                             "Administrators" `
                             "SYSTEM"                | Out-Null   # 去掉常见组
      icacls $Path /setowner "$User"       | Out-Null
  }

  Get-ChildItem -Path $Root -Recurse -Filter *.exe -File |
      ForEach-Object { Set-Exe0400 -Path $_.FullName }