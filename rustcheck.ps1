# Rust-Checker.ps1
# Проверка системы на наличие RUST-читов и подозрительной активности
# Автор для сообщества, 2025
# Запуск Right-click → Run with PowerShell (или от админа)

Clear-Host
Write-Host ════════════════════════════════════════════════ -ForegroundColor Cyan
Write-Host       RUST Speak  Rust Checker v1.3          -ForegroundColor Cyan
Write-Host ════════════════════════════════════════════════ -ForegroundColor Cyan
Write-Host 

$Found = 0

# 1. Проверка запущенных процессов на типичные имена и признаки Rust-майнеров
Write-Host [18] Проверка запущенных процессов... -ForegroundColor Yellow
$SuspiciousNames = @(
    xmrig, miner, kthreadd, kdevtmpfs, watchdog, pool, stratum, 
    cpu, taskhostw, svchostt, systemd, conhost, msedge, winlogin,
    sqlservr, ntos, kernel, crypt, wallet, nicehash, ethminer,
    lolminer, teamredminer, gminer, nanominer, tt-miner, phoenix
)

Get-Process  Where-Object { $_.Path }  ForEach-Object {
    $proc = $_
    $lowerName = $proc.ProcessName.ToLower()
    $path = $proc.Path.ToLower()

    # Проверка по имени
    if ($SuspiciousNames  Where-Object { $lowerName -like $_ }) {
        Write-Host   Подозрительный процесс $($proc.ProcessName) (PID $($proc.Id)) -ForegroundColor Red
        Write-Host     Путь $path -ForegroundColor DarkRed
        $Found++
    }

    # Проверка на большие бинарники без подписи + высокая загрузка CPU
    if ($proc.Path -and (Get-Item $proc.Path -ErrorAction SilentlyContinue).Length -gt 20MB) {
        if ($proc.CPU -gt 100) {  # 100 секунд CPU времени
            try {
                $sign = Get-AuthenticodeSignature $proc.Path -ErrorAction Stop
                if ($sign.Status -ne Valid) {
                    Write-Host   Большой неподписанный процесс $($proc.ProcessName) → $path -ForegroundColor Magenta
                    $Found++
                }
            } catch {}
        }
    }
}

# 2. Проверка типичных папок хранения раст-майнеров
Write-Host [28] Проверка известных папок... -ForegroundColor Yellow
$CheckFolders = @(
    $envAPPDATA,
    $envLOCALAPPDATA,
    $envTEMP,
    $envUSERPROFILEDownloads,
    CProgramData,
    CWindowsTemp,
    CIntel,
    CAMD,
    CPerfLogs,
    CUsersPublic
)

foreach ($folder in $CheckFolders) {
    Get-ChildItem $folder -Include .exe,.dll -Recurse -ErrorAction SilentlyContinue  Where-Object {
        $_.Length -gt 10MB -and $_.CreationTime -gt (Get-Date).AddDays(-90)
    }  ForEach-Object {
        try {
            $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction Stop
            if ($sig.Status -ne Valid) {
                Write-Host   Подозрительный большой EXE $($_.FullName) -ForegroundColor Red
                Write-Host     Размер $([math]Round($_.Length1MB,2)) MB  Создан $($_.CreationTime) -ForegroundColor DarkRed
                $Found++
            }
        } catch {}
    }
}

# 3. Проверка автозагрузки (реестр + планировщик)
Write-Host [38] Проверка автозагрузки... -ForegroundColor Yellow
$AutoRuns = @(
    HKLMSOFTWAREMicrosoftWindowsCurrentVersionRun,
    HKCUSOFTWAREMicrosoftWindowsCurrentVersionRun,
    HKLMSOFTWAREWow6432NodeMicrosoftWindowsCurrentVersionRun
)

foreach ($key in $AutoRuns) {
    Get-ItemProperty $key -ErrorAction SilentlyContinue  
      Select-Object -Property PSChildName,  -ExcludeProperty PS  
      ForEach-Object {
          $_.PSObject.Properties  Where-Object Name -notin PSPath,PSParentPath,PSChildName,PSDrive,PSProvider  ForEach-Object {
              $val = $_.Value
              if ($val -match .exe) {
                  Write-Host   Автозапуск $($_.Name) → $val -ForegroundColor Magenta
                  $Found++
              }
          }
      }
}

# 4. Проверка задач в планировщике
Write-Host [48] Проверка задач планировщика... -ForegroundColor Yellow
Get-ScheduledTask  Where-Object {$_.Actions -match .exe}  ForEach-Object {
    Write-Host   Подозрительная задача $($_.TaskName) в $($_.TaskPath) -ForegroundColor Magenta
    $_.Actions.Execute  Where-Object { Test-Path $_ -ErrorAction SilentlyContinue }  ForEach-Object {
        Write-Host     Выполняет $_ -ForegroundColor DarkRed
    }
    $Found++
}

# 5. Проверка драйверов (часто используют раст-руткиты)
Write-Host [58] Проверка подозрительных драйверов... -ForegroundColor Yellow
Get-CimInstance Win32_SystemDriver  Where-Object {$_.PathName -notlike CWindowssystem32drivers}  ForEach-Object {
    Write-Host   Нестандартный драйвер $($_.Name) → $($_.PathName) -ForegroundColor Red
    $Found++
}

# 6. Проверка открытых портов 3333, 4444, 5555, 6666, 7777, 14444 и т.д. (stratum)
Write-Host [68] Проверка подозрительных сетевых подключений... -ForegroundColor Yellow
Get-NetTCPConnection  Where-Object {$_.RemotePort -in 3333,4444,5555,6666,7777,14444,55555}  ForEach-Object {
    Write-Host   Подключение к майнинг-пулу $($_.LocalAddress)$($_.LocalPort) → $($_.RemoteAddress)$($_.RemotePort) -ForegroundColor Red
    $Found++
}

# 7. Проверка наличия типичных строк в процессах (stratum+tcp, xmrig, etc.)
Write-Host [78] Поиск строк в памяти процессов... -ForegroundColor Yellow
# Это тяжёлая операция, делаем только для подозрительных процессов
Get-Process  Where-Object {$_.CPU -gt 50}  ForEach-Object {
    try {
        $handle = $_.Handle
        # Простая проверка через strings (если установлен Sysinternals)
        if (Get-Command strings -ErrorAction SilentlyContinue) {
            $out = strings -n 8 $($_.Path) 2$null  Select-String -Pattern stratum+tcp,xmr.,pool.,wallet,donate.vip -SimpleMatch
            if ($out) {
                Write-Host   Найдены майнерские строки в $($_.Name) ($($_.Id)) -ForegroundColor Red
                $Found++
            }
        }
    } catch {}
}

# 8. Итог
Write-Host 
Write-Host ════════════════════════════════════════════════ -ForegroundColor Cyan
if ($Found -eq 0) {
    Write-Host      СИСТЕМА ЧИСТАЯ! Признаков RUST-майнеров не найдено. -ForegroundColor Green
} else {
    Write-Host      ОБНАРУЖЕНО $Found подозрительных объектов! -ForegroundColor Red
    Write-Host      Рекомендуется полная проверка антивирусом (Kaspersky, Dr.Web, Malwarebytes) -ForegroundColor Yellow
    Write-Host      и удаление найденных файлов вручную. -ForegroundColor Yellow
}
Write-Host ════════════════════════════════════════════════ -ForegroundColor Cyan

Pause