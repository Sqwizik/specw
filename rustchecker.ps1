Rust Cheat Detector v1.3
Write-Host "Запуск проверки на популярные читы Rust..." -ForegroundColor Cyan
Write-Host "Требуются права администратора!" -ForegroundColor Yellow

$Detected = $false

# 1. Проверка запущенных подозрительных процессов
$SuspiciousProcesses = @(
    "cheatengine-x86_64", "cheatengine-i386", "CE70", "Cheat Engine",
    "rustcheat", "rusthack", "rustaim", "rustesp", "evolve", "quantumcheats",
    "battleeye_bypass", "eac_bypass", "injector", "xenos64", "xenos32",
    "extreme injector", "cheatengine", "processhacker", "artmoney",
    "fiddler", "charles", "wireshark", "ghidra", "ida", "ollydbg",
    "x64dbg", "scyllahide", "vmware", "vbox", "hyperv", "sandboxie"
)

Write-Host "`nПроверка запущенных процессов..." -ForegroundColor Green
foreach ($procName in $SuspiciousProcesses) {
    if (Get-Process -Name $procName -ErrorAction SilentlyContinue) {
        Write-Host "[ОБНАРУЖЕНО] Процесс: $procName" -ForegroundColor Red
        $Detected = $true
    }
}

# 2. Проверка Rust процесса + подозрительных DLL
Write-Host "`nПроверка процесса RustClient.exe..." -ForegroundColor Green
$RustProcess = Get-Process -Name "RustClient" -ErrorAction SilentlyContinue
if ($RustProcess) {
    Write-Host "RustClient найден (PID: $($RustProcess.Id))" -ForegroundColor Yellow
    
    # Список известных читерских DLL (обновляется)
    $BadDLLs = @(
        "Rebirth.dll", "RustHack.dll", "Quantum.dll", "Evolve.dll",
        "Lunar.dll", "Neverlose.dll", "Osiris.dll", "AimStar.dll",
        "Interium.dll", "Onyx.dll", "Gamesense.dll", "LuckyCharms.dll"
    )
    
    try {
        $modules = $RustProcess.Modules
        foreach ($module in $modules) {
            $name = $module.ModuleName.ToLower()
            foreach ($bad in $BadDLLs) {
                if ($name -like "*$($bad.ToLower())*") {
                    Write-Host "[ОБНАРУЖЕНА ЧИТ-ДЛЛ] $name (PID: $($RustProcess.Id))" -ForegroundColor Red
                    $Detected = $true
                }
            }
        }
    } catch { Write-Host "Не удалось прочитать модули Rust (возможно, античит блокирует)" -ForegroundColor Gray }
} else {
    Write-Host "RustClient не запущен." -ForegroundColor Gray
}

# 3. Проверка известных папок читов
Write-Host "`nПроверка известных папок читов..." -ForegroundColor Green
$CheatPaths = @(
    "$env:APPDATA\RustCheat",
    "$env:APPDATA\Quantum",
    "$env:APPDATA\Evolve",
    "$env:APPDATA\Rebirth",
    "$env:TEMP\Lunar",
    "$env:TEMP\RustHack",
    "C:\RustCheat",
    "C:\Cheat",
    "C:\ProgramData\Injector"
)

foreach ($path in $CheatPaths) {
    if (Test-Path $path) {
        Write-Host "[ОБНАРУЖЕНА ПАПКА ЧИТА] $path" -ForegroundColor Red
        $Detected = $true
    }
}

# 4. Проверка реестра (автозапуск инжекторов)
Write-Host "`nПроверка автозапуска в реестре..." -ForegroundColor Green
$RegPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($reg in $RegPaths) {
    $items = Get-ItemProperty $reg -ErrorAction SilentlyContinue
    if ($items) {
        foreach ($prop in $items.PSObject.Properties) {
            if ($prop.Value -match "injector|cheat|rusthack|quantum|evolve|rebirth|dll") {
                Write-Host "[ПОДОЗРИТЕЛЬНЫЙ АВТОЗАПУСК] $($prop.Name) = $($prop.Value)" -ForegroundColor Red
                $Detected = $true
            }
        }
    }
}

# 5. Проверка подписи EasyAntiCheat и BattleEye (если повреждены — часто признак обхода)
Write-Host "`nПроверка целостности EAC и BE..." -ForegroundColor Green
$EACPath = "${env:ProgramFiles(x86)}\EasyAntiCheat\EasyAntiCheat.exe"
$BEPath  = "${env:ProgramFiles(x86)}\Common Files\BattlEye\BEService.exe"

if (Test-Path $EACPath) {
    $cert = Get-AuthenticodeSignature $EACPath
    if ($cert.Status -ne "Valid") {
        Write-Host "[ПОВРЕЖДЕНА ПОДПИСЬ EAC] $EACPath" -ForegroundColor Red
        $Detected = $true
    }
}

# Итог
Write-Host "`n" + "="*60 -ForegroundColor Cyan
if ($Detected) {
    Write-Host "ВНИМАНИЕ: ОБНАРУЖЕНЫ ПРИЗНАКИ ИСПОЛЬЗОВАНИЯ ЧИТОВ!" -ForegroundColor Red
    Write-Host "Рекомендуется полный бан аккаунта." -ForegroundColor Red
} else {
    Write-Host "Признаки читов НЕ обнаружены." -ForegroundColor Green
}
Write-Host "="*60 -ForegroundColor Cyan

pause