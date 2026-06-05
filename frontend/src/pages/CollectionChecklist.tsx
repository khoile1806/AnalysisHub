import { useEffect, useRef, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  CheckSquare, Square, ChevronDown, ChevronRight, Play,
  RotateCcw, Download, AlertTriangle, Terminal, Loader2,
  CheckCircle2, XCircle, Clock, Trash2, Wrench, BrainCircuit,
} from 'lucide-react'
import { agentsApi, Agent } from '@/api/agents'
import { checklistApi, ChecklistBatch } from '@/api/checklist'
import { toolsApi, Tool } from '@/api/tools'
import { jobsApi } from '@/api/jobs'

// ─── Types ────────────────────────────────────────────────────────────────────

type Priority = 'critical' | 'high' | 'medium'


interface ChecklistItem {
  id: string
  subsection: string
  subsectionLabel: string
  label: string
  commands: string[]
  priority: Priority
  executable: boolean
}

interface ChecklistSection {
  id: string
  phase: string
  label: string
  optional?: boolean
  items: { win: ChecklistItem[]; linux: ChecklistItem[] }
}

import { useChecklistStore, type Platform, type ItemStatus, type ToolResult } from '@/store/checklist'


// ─── Checklist Data ───────────────────────────────────────────────────────────

const PHASE1_WIN: ChecklistItem[] = [
  // 1.1 System Information
  { id:'p1w-1.1-1', subsection:'1.1', subsectionLabel:'System Information', priority:'critical', executable:true,
    label:'Thu thập thông tin hệ thống (OS version, patch level, hostname)',
    commands:['systeminfo > systeminfo.txt','hostname >> systeminfo.txt','whoami /all >> systeminfo.txt'] },
  { id:'p1w-1.1-2', subsection:'1.1', subsectionLabel:'System Information', priority:'critical', executable:true,
    label:'Ghi lại system time + tính time offset so với UTC',
    commands:['date /t && time /t','powershell -c "Get-Date -Format \'yyyy-MM-dd HH:mm:ss zzz\'"','w32tm /query /status 2>NUL','w32tm /query /configuration 2>NUL'] },
  { id:'p1w-1.1-3', subsection:'1.1', subsectionLabel:'System Information', priority:'medium', executable:true,
    label:'Ghi lại uptime hệ thống',
    commands:['net statistics workstation | findstr "since"'] },
  { id:'p1w-1.1-4', subsection:'1.1', subsectionLabel:'System Information', priority:'medium', executable:true,
    label:'Thu thập environment variables',
    commands:['set > env_vars.txt'] },

  // 1.2 Network State
  { id:'p1w-1.2-1', subsection:'1.2', subsectionLabel:'Network State', priority:'critical', executable:true,
    label:'Tất cả kết nối mạng đang hoạt động (kèm PID + executable)',
    commands:['netstat -anob > netstat.txt'] },
  { id:'p1w-1.2-2', subsection:'1.2', subsectionLabel:'Network State', priority:'high', executable:true,
    label:'ARP cache (phát hiện lateral movement nội bộ)',
    commands:['arp -a > arp_cache.txt'] },
  { id:'p1w-1.2-3', subsection:'1.2', subsectionLabel:'Network State', priority:'high', executable:true,
    label:'Cấu hình network interfaces',
    commands:['ipconfig /all > ipconfig.txt'] },
  { id:'p1w-1.2-4', subsection:'1.2', subsectionLabel:'Network State', priority:'medium', executable:true,
    label:'Routing table',
    commands:['route print > route.txt'] },
  { id:'p1w-1.2-5', subsection:'1.2', subsectionLabel:'Network State', priority:'high', executable:true,
    label:'DNS cache (phát hiện C2 domains đã resolve)',
    commands:['ipconfig /displaydns > dns_cache.txt'] },
  { id:'p1w-1.2-6', subsection:'1.2', subsectionLabel:'Network State', priority:'medium', executable:true,
    label:'Network shares đang mount',
    commands:['net use > net_shares.txt','net share >> net_shares.txt'] },
  { id:'p1w-1.2-7', subsection:'1.2', subsectionLabel:'Network State', priority:'medium', executable:true,
    label:'WiFi profiles đã lưu (có thể chứa credentials)',
    commands:['netsh wlan show profiles > wifi_profiles.txt'] },
  { id:'p1w-1.2-8', subsection:'1.2', subsectionLabel:'Network State', priority:'high', executable:true,
    label:'Windows Firewall logs',
    commands:['mkdir evidence 2>NUL','copy C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log evidence\\ 2>NUL','netsh advfirewall show allprofiles state'] },

  // 1.3 Running Processes
  { id:'p1w-1.3-1', subsection:'1.3', subsectionLabel:'Running Processes', priority:'critical', executable:true,
    label:'Danh sách processes kèm command line đầy đủ',
    commands:['tasklist /v /fo csv','powershell -c "Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath | ConvertTo-Csv -NoTypeInformation"'] },
  { id:'p1w-1.3-2', subsection:'1.3', subsectionLabel:'Running Processes', priority:'high', executable:true,
    label:'DLLs được load bởi từng process (tìm DLL injection)',
    commands:['tasklist /m > dlls_loaded.txt'] },
  { id:'p1w-1.3-3', subsection:'1.3', subsectionLabel:'Running Processes', priority:'high', executable:true,
    label:'Open file handles của mỗi process',
    commands:['handle.exe -a 2>NUL','powershell -c "Get-Process | Select-Object Id,Name,HandleCount,@{N=\'Path\';E={try{$_.MainModule.FileName}catch{\'\'}}} | Sort-Object HandleCount -Descending | Format-Table -AutoSize"'] },
  { id:'p1w-1.3-4', subsection:'1.3', subsectionLabel:'Running Processes', priority:'high', executable:true,
    label:'Loaded drivers (tìm rootkit kernel-mode)',
    commands:['driverquery /fo csv /v > drivers.csv'] },

  // 1.4 Users & Sessions
  { id:'p1w-1.4-1', subsection:'1.4', subsectionLabel:'Users & Sessions', priority:'critical', executable:true,
    label:'Users đang đăng nhập và active sessions',
    commands:['query user > sessions.txt','query session >> sessions.txt'] },
  { id:'p1w-1.4-2', subsection:'1.4', subsectionLabel:'Users & Sessions', priority:'high', executable:true,
    label:'Danh sách tất cả local accounts',
    commands:['net user','powershell -c "Get-LocalUser | Select-Object Name,SID,Enabled,LastLogon,Description | Format-Table -AutoSize"'] },
  { id:'p1w-1.4-3', subsection:'1.4', subsectionLabel:'Users & Sessions', priority:'high', executable:true,
    label:'Danh sách local groups (đặc biệt Administrators)',
    commands:['net localgroup Administrators > admins.txt','net localgroup > all_groups.txt'] },
  { id:'p1w-1.4-4', subsection:'1.4', subsectionLabel:'Users & Sessions', priority:'medium', executable:true,
    label:'Clipboard content (có thể chứa credentials)',
    commands:['powershell -c "Get-Clipboard" > clipboard.txt'] },

  // 1.5 Scheduled Tasks & Services
  { id:'p1w-1.5-1', subsection:'1.5', subsectionLabel:'Scheduled Tasks & Services', priority:'critical', executable:true,
    label:'Tất cả Scheduled Tasks (tìm persistence)',
    commands:['schtasks /query /fo csv /v > schtasks.csv'] },
  { id:'p1w-1.5-2', subsection:'1.5', subsectionLabel:'Scheduled Tasks & Services', priority:'critical', executable:true,
    label:'Tất cả services và trạng thái hiện tại',
    commands:['sc query type= all state= all','powershell -c "Get-Service | Select-Object Name,DisplayName,Status,StartType | Sort-Object Status | Format-Table -AutoSize"','powershell -c "Get-CimInstance Win32_Service | Select-Object Name,PathName,StartMode,State | ConvertTo-Csv -NoTypeInformation"'] },

  // 1.6 Persistence / Autorun
  { id:'p1w-1.6-1', subsection:'1.6', subsectionLabel:'Persistence / Autorun', priority:'critical', executable:true,
    label:'Registry Run keys (HKLM & HKCU)',
    commands:[
      'reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run > run_keys.txt',
      'reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run >> run_keys.txt',
      'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" >> run_keys.txt',
      'reg query HKLM\\SYSTEM\\CurrentControlSet\\Services >> run_keys.txt',
    ]},
  { id:'p1w-1.6-2', subsection:'1.6', subsectionLabel:'Persistence / Autorun', priority:'critical', executable:true,
    label:'Chạy Autoruns — tổng hợp tất cả persistence points',
    commands:['autorunsc.exe -a * -c -h -s > autoruns.csv'] },

  // 1.7 Windows Event Logs
  { id:'p1w-1.7-1', subsection:'1.7', subsectionLabel:'Windows Event Logs', priority:'critical', executable:true,
    label:'Security.evtx — logon, process creation, account management',
    commands:['mkdir evidence 2>NUL','wevtutil epl Security evidence\\Security.evtx'] },
  { id:'p1w-1.7-2', subsection:'1.7', subsectionLabel:'Windows Event Logs', priority:'critical', executable:true,
    label:'System.evtx — service install, boot/shutdown',
    commands:['mkdir evidence 2>NUL','wevtutil epl System evidence\\System.evtx'] },
  { id:'p1w-1.7-3', subsection:'1.7', subsectionLabel:'Windows Event Logs', priority:'critical', executable:true,
    label:'PowerShell/Operational.evtx — script block logging',
    commands:['mkdir evidence 2>NUL','wevtutil epl "Microsoft-Windows-PowerShell/Operational" evidence\\PS_Operational.evtx'] },
  { id:'p1w-1.7-4', subsection:'1.7', subsectionLabel:'Windows Event Logs', priority:'high', executable:true,
    label:'TaskScheduler/Operational.evtx',
    commands:['mkdir evidence 2>NUL','wevtutil epl "Microsoft-Windows-TaskScheduler/Operational" evidence\\TaskSched.evtx'] },
  { id:'p1w-1.7-5', subsection:'1.7', subsectionLabel:'Windows Event Logs', priority:'high', executable:true,
    label:'Sysmon/Operational.evtx (nếu Sysmon đang chạy)',
    commands:['mkdir evidence 2>NUL','wevtutil epl "Microsoft-Windows-Sysmon/Operational" evidence\\Sysmon.evtx 2>NUL || echo Sysmon not installed - skipping'] },
  { id:'p1w-1.7-6', subsection:'1.7', subsectionLabel:'Windows Event Logs', priority:'high', executable:true,
    label:'Application.evtx + copy toàn bộ thư mục logs',
    commands:['mkdir evidence 2>NUL','wevtutil epl Application evidence\\Application.evtx','xcopy /E /I /Y C:\\Windows\\System32\\winevt\\Logs\\ evidence\\evtx_all\\'] },

  // 1.8 User Artifacts & Activity
  { id:'p1w-1.8-1', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'critical', executable:true,
    label:'PowerShell command history',
    commands:['mkdir evidence 2>NUL','copy "%APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt" evidence\\ps_history.txt 2>NUL','powershell -c "Get-Content (Get-PSReadLineOption).HistorySavePath -ErrorAction SilentlyContinue | Select-Object -Last 200"'] },
  { id:'p1w-1.8-2', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'high', executable:true,
    label:'Prefetch files (chứng minh chương trình đã từng chạy)',
    commands:['mkdir evidence 2>NUL','mkdir evidence\\prefetch 2>NUL','xcopy /Y C:\\Windows\\Prefetch\\*.pf evidence\\prefetch\\ 2>NUL || echo Prefetch disabled or access denied'] },
  { id:'p1w-1.8-3', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'medium', executable:true,
    label:'Recent files & Jump Lists',
    commands:['mkdir evidence 2>NUL','mkdir evidence\\recent 2>NUL','xcopy /E /I /Y "C:\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\" evidence\\recent\\ 2>NUL'] },
  { id:'p1w-1.8-4', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'high', executable:true,
    label:'Browser history — Chrome',
    commands:['mkdir evidence 2>NUL','mkdir evidence\\chrome 2>NUL','xcopy /E /I /Y "C:\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\" evidence\\chrome\\ 2>NUL || echo Chrome not found'] },
  { id:'p1w-1.8-5', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'high', executable:true,
    label:'Browser history — Firefox',
    commands:['mkdir evidence 2>NUL','mkdir evidence\\firefox 2>NUL','xcopy /E /I /Y "C:\\Users\\*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\" evidence\\firefox\\ 2>NUL || echo Firefox not found'] },
  { id:'p1w-1.8-6', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'high', executable:true,
    label:'Tìm file mới tạo/modified trong khoảng thời gian sự cố',
    commands:['powershell -c "Get-ChildItem -Path C:\\Users -Recurse -ErrorAction SilentlyContinue | Where-Object {$_.LastWriteTime -gt (Get-Date).AddDays(-30)} | Select-Object FullName,LastWriteTime,Length | ConvertTo-Csv -NoTypeInformation"'] },
  { id:'p1w-1.8-7', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'critical', executable:true,
    label:'Kiểm tra thư mục temp/staging hay dùng bởi attacker',
    commands:['dir /a C:\\Windows\\Temp\\','dir /a C:\\Users\\Public\\','dir /a C:\\ProgramData\\','dir /a "%TEMP%"'] },
]

const PHASE1_LIN: ChecklistItem[] = [
  // 1.1
  { id:'p1l-1.1-1', subsection:'1.1', subsectionLabel:'System Information', priority:'critical', executable:true,
    label:'Thu thập thông tin hệ thống (kernel, distro, hostname)',
    commands:['uname -a > systeminfo.txt','cat /etc/os-release >> systeminfo.txt','hostname >> systeminfo.txt','id && whoami'] },
  { id:'p1l-1.1-2', subsection:'1.1', subsectionLabel:'System Information', priority:'critical', executable:true,
    label:'Ghi lại system time + timezone + time offset so với UTC',
    commands:['date > time_info.txt','timedatectl >> time_info.txt'] },
  { id:'p1l-1.1-3', subsection:'1.1', subsectionLabel:'System Information', priority:'medium', executable:true,
    label:'Ghi lại uptime hệ thống',
    commands:['uptime > uptime.txt'] },
  { id:'p1l-1.1-4', subsection:'1.1', subsectionLabel:'System Information', priority:'medium', executable:true,
    label:'Thu thập environment variables',
    commands:["env > env_vars.txt","cat /proc/1/environ | tr '\\0' '\\n' >> env_vars.txt"] },

  // 1.2
  { id:'p1l-1.2-1', subsection:'1.2', subsectionLabel:'Network State', priority:'critical', executable:true,
    label:'Tất cả kết nối mạng đang hoạt động (kèm PID + process)',
    commands:['ss -antp > netstat.txt','netstat -antp >> netstat.txt 2>/dev/null'] },
  { id:'p1l-1.2-2', subsection:'1.2', subsectionLabel:'Network State', priority:'high', executable:true,
    label:'ARP cache (phát hiện lateral movement nội bộ)',
    commands:['arp -n > arp_cache.txt','ip neigh >> arp_cache.txt'] },
  { id:'p1l-1.2-3', subsection:'1.2', subsectionLabel:'Network State', priority:'high', executable:true,
    label:'Cấu hình network interfaces',
    commands:['ip addr show > ip_config.txt','ifconfig -a >> ip_config.txt 2>/dev/null'] },
  { id:'p1l-1.2-4', subsection:'1.2', subsectionLabel:'Network State', priority:'medium', executable:true,
    label:'Routing table',
    commands:['ip route show > route.txt','route -n >> route.txt 2>/dev/null'] },
  { id:'p1l-1.2-5', subsection:'1.2', subsectionLabel:'Network State', priority:'high', executable:true,
    label:'DNS config + hosts file',
    commands:['cat /etc/resolv.conf > dns_config.txt','cat /etc/hosts >> dns_config.txt'] },
  { id:'p1l-1.2-6', subsection:'1.2', subsectionLabel:'Network State', priority:'medium', executable:true,
    label:'Network shares đang mount',
    commands:['mount > mounted.txt','cat /etc/fstab >> mounted.txt'] },
  { id:'p1l-1.2-7', subsection:'1.2', subsectionLabel:'Network State', priority:'high', executable:true,
    label:'Firewall rules hiện tại',
    commands:['iptables -L -n -v > firewall_rules.txt','ip6tables -L -n -v >> firewall_rules.txt 2>/dev/null','ufw status verbose >> firewall_rules.txt 2>/dev/null'] },

  // 1.3
  { id:'p1l-1.3-1', subsection:'1.3', subsectionLabel:'Running Processes', priority:'critical', executable:true,
    label:'Process tree đầy đủ kèm parent-child relationship',
    commands:['ps auxf > processes.txt','ps -eo pid,ppid,user,stat,cmd >> processes.txt'] },
  { id:'p1l-1.3-2', subsection:'1.3', subsectionLabel:'Running Processes', priority:'high', executable:true,
    label:'Symlinks của executables trong /proc (tìm fileless malware)',
    commands:['ls -la /proc/*/exe 2>/dev/null > proc_exe.txt'] },
  { id:'p1l-1.3-3', subsection:'1.3', subsectionLabel:'Running Processes', priority:'high', executable:true,
    label:'Open files & network connections của mỗi process',
    commands:['lsof -n > open_files.txt','lsof -i >> open_files.txt'] },
  { id:'p1l-1.3-4', subsection:'1.3', subsectionLabel:'Running Processes', priority:'high', executable:true,
    label:'Kernel modules đang load (tìm rootkit)',
    commands:['lsmod > lsmod.txt','cat /proc/modules >> lsmod.txt'] },

  // 1.4
  { id:'p1l-1.4-1', subsection:'1.4', subsectionLabel:'Users & Sessions', priority:'critical', executable:true,
    label:'Users đang đăng nhập và active sessions',
    commands:['who > sessions.txt','w >> sessions.txt'] },
  { id:'p1l-1.4-2', subsection:'1.4', subsectionLabel:'Users & Sessions', priority:'high', executable:true,
    label:'Lịch sử đăng nhập gần đây',
    commands:['last -50 > last_logins.txt','lastlog >> last_logins.txt'] },
  { id:'p1l-1.4-3', subsection:'1.4', subsectionLabel:'Users & Sessions', priority:'high', executable:true,
    label:'Danh sách tất cả user accounts',
    commands:['cat /etc/passwd > local_users.txt','getent passwd >> local_users.txt'] },
  { id:'p1l-1.4-4', subsection:'1.4', subsectionLabel:'Users & Sessions', priority:'high', executable:true,
    label:'Danh sách groups (đặc biệt sudo/wheel)',
    commands:["cat /etc/group > groups.txt","grep -E '^(sudo|wheel|adm)' /etc/group >> groups.txt"] },

  // 1.5
  { id:'p1l-1.5-1', subsection:'1.5', subsectionLabel:'Scheduled Tasks & Services', priority:'critical', executable:true,
    label:'Crontab của từng user và system-wide',
    commands:['crontab -l > crontabs.txt 2>/dev/null','cat /etc/crontab >> crontabs.txt','ls -la /etc/cron.* >> crontabs.txt','cat /var/spool/cron/crontabs/* >> crontabs.txt 2>/dev/null'] },
  { id:'p1l-1.5-2', subsection:'1.5', subsectionLabel:'Scheduled Tasks & Services', priority:'critical', executable:true,
    label:'Tất cả systemd services và trạng thái',
    commands:['systemctl list-units --type=service > services.txt','systemctl list-unit-files --type=service >> services.txt'] },

  // 1.6
  { id:'p1l-1.6-1', subsection:'1.6', subsectionLabel:'Persistence', priority:'critical', executable:true,
    label:'Startup scripts của users và hệ thống',
    commands:['cat ~/.bashrc ~/.bash_profile ~/.profile > startup_scripts.txt 2>/dev/null','cat /etc/rc.local >> startup_scripts.txt 2>/dev/null','ls /etc/profile.d/ >> startup_scripts.txt'] },
  { id:'p1l-1.6-2', subsection:'1.6', subsectionLabel:'Persistence', priority:'critical', executable:true,
    label:'SSH authorized_keys của tất cả users (backdoor phổ biến)',
    commands:['cat /root/.ssh/authorized_keys > ssh_keys.txt 2>/dev/null','find /home -name "authorized_keys" -exec cat {} \\; >> ssh_keys.txt 2>/dev/null'] },
  { id:'p1l-1.6-3', subsection:'1.6', subsectionLabel:'Persistence', priority:'high', executable:true,
    label:'LD_PRELOAD hijack check',
    commands:['cat /etc/ld.so.preload > ldpreload.txt 2>/dev/null','echo $LD_PRELOAD >> ldpreload.txt'] },
  { id:'p1l-1.6-4', subsection:'1.6', subsectionLabel:'Persistence', priority:'high', executable:true,
    label:'SUID/SGID binaries bất thường',
    commands:['find / -perm -4000 -o -perm -2000 2>/dev/null > suid_sgid.txt'] },

  // 1.7
  { id:'p1l-1.7-1', subsection:'1.7', subsectionLabel:'System Logs', priority:'critical', executable:true,
    label:'Auth log — SSH, sudo, PAM authentication',
    commands:['mkdir -p evidence/logs','cp /var/log/auth.log* evidence/logs/ 2>/dev/null','cp /var/log/secure* evidence/logs/ 2>/dev/null'] },
  { id:'p1l-1.7-2', subsection:'1.7', subsectionLabel:'System Logs', priority:'high', executable:true,
    label:'Syslog / messages — general system events',
    commands:['mkdir -p evidence/logs','cp /var/log/syslog* evidence/logs/ 2>/dev/null','cp /var/log/messages* evidence/logs/ 2>/dev/null'] },
  { id:'p1l-1.7-3', subsection:'1.7', subsectionLabel:'System Logs', priority:'high', executable:true,
    label:'Audit logs (nếu auditd đang chạy)',
    commands:['mkdir -p evidence/logs','cp /var/log/audit/audit.log* evidence/logs/ 2>/dev/null','ausearch -i 2>/dev/null'] },
  { id:'p1l-1.7-4', subsection:'1.7', subsectionLabel:'System Logs', priority:'high', executable:true,
    label:'Web server logs — Apache / Nginx',
    commands:['mkdir -p evidence/logs/web','cp /var/log/apache2/* evidence/logs/web/ 2>/dev/null','cp /var/log/nginx/* evidence/logs/web/ 2>/dev/null'] },
  { id:'p1l-1.7-5', subsection:'1.7', subsectionLabel:'System Logs', priority:'high', executable:true,
    label:'Firewall logs (ufw / iptables)',
    commands:['mkdir -p evidence/logs','cp /var/log/ufw.log* evidence/logs/ 2>/dev/null','cp /var/log/kern.log* evidence/logs/ 2>/dev/null'] },
  { id:'p1l-1.7-6', subsection:'1.7', subsectionLabel:'System Logs', priority:'high', executable:true,
    label:'Journald logs (systemd-based distros)',
    commands:['mkdir -p evidence/logs','journalctl --no-pager -n 5000 2>/dev/null','journalctl -u sshd --no-pager 2>/dev/null','journalctl -u apache2 -u nginx --no-pager 2>/dev/null'] },

  // 1.8
  { id:'p1l-1.8-1', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'critical', executable:true,
    label:'Bash history của tất cả users (flush buffer trước)',
    commands:['history -a','mkdir -p evidence','cp /root/.bash_history evidence/bash_history_root.txt 2>/dev/null','find /home -name ".bash_history" -exec cp {} evidence/ \\; 2>/dev/null','find /home /root -name ".*_history" 2>/dev/null'] },
  { id:'p1l-1.8-2', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'high', executable:true,
    label:'Browser profiles — Chrome / Firefox',
    commands:['mkdir -p evidence/chrome evidence/firefox','cp -r ~/.config/google-chrome/Default/ evidence/chrome/ 2>/dev/null','cp -r ~/.mozilla/firefox/*.default*/ evidence/firefox/ 2>/dev/null','find /home -name "places.sqlite" -o -name "History" 2>/dev/null'] },
  { id:'p1l-1.8-3', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'high', executable:true,
    label:'Tìm file mới tạo/modified trong khoảng thời gian sự cố',
    commands:['find /home /var /tmp /opt /root /usr/local /srv -mtime -7 -type f 2>/dev/null'] },
  { id:'p1l-1.8-4', subsection:'1.8', subsectionLabel:'User Artifacts & Activity', priority:'critical', executable:true,
    label:'Kiểm tra thư mục staging hay dùng bởi attacker',
    commands:['ls -la /tmp/ /var/tmp/ /dev/shm/ /root/ 2>/dev/null > staging_dirs.txt'] },
]

const PHASE2_WIN: ChecklistItem[] = [
  { id:'p2w-2.1-1', subsection:'2.1', subsectionLabel:'Memory (RAM) Dump', priority:'critical', executable:true,
    label:'Dump toàn bộ RAM (winpmem)',
    commands:['winpmem_mini.exe memdump.raw'] },
  { id:'p2w-2.1-2', subsection:'2.1', subsectionLabel:'Memory (RAM) Dump', priority:'critical', executable:true,
    label:'Verify hash RAM dump',
    commands:['certutil -hashfile memdump.raw SHA256 > memdump.sha256'] },
  { id:'p2w-2.1-3', subsection:'2.1', subsectionLabel:'Memory (RAM) Dump', priority:'high', executable:true,
    label:'Thu thập pagefile (RAM overflow ra disk)',
    commands:['mkdir evidence 2>NUL','esentutl /y C:\\pagefile.sys /vss /d evidence\\pagefile.sys 2>NUL || echo pagefile.sys is locked - requires VSS or FTK Imager'] },
  { id:'p2w-2.2-1', subsection:'2.2', subsectionLabel:'Disk Imaging', priority:'critical', executable:false,
    label:'Tạo full disk image bằng FTK Imager (.E01 với hash tự động)',
    commands:['FTK Imager → File → Create Disk Image → Source: Physical Drive → E01 format'] },
  { id:'p2w-2.2-2', subsection:'2.2', subsectionLabel:'Disk Imaging', priority:'critical', executable:true,
    label:'Verify MD5 + SHA256 sau khi imaging',
    commands:['certutil -hashfile disk.E01 MD5','certutil -hashfile disk.E01 SHA256'] },
  { id:'p2w-2.3-1', subsection:'2.3', subsectionLabel:'Registry Hives', priority:'critical', executable:true,
    label:'SAM hive (local accounts + password hashes)',
    commands:['mkdir evidence 2>NUL','reg save HKLM\\SAM evidence\\SAM.hiv /Y'] },
  { id:'p2w-2.3-2', subsection:'2.3', subsectionLabel:'Registry Hives', priority:'critical', executable:true,
    label:'SYSTEM hive (boot config, services, Shimcache)',
    commands:['mkdir evidence 2>NUL','reg save HKLM\\SYSTEM evidence\\SYSTEM.hiv /Y'] },
  { id:'p2w-2.3-3', subsection:'2.3', subsectionLabel:'Registry Hives', priority:'high', executable:true,
    label:'SOFTWARE hive (installed programs, OS config)',
    commands:['mkdir evidence 2>NUL','reg save HKLM\\SOFTWARE evidence\\SOFTWARE.hiv /Y'] },
  { id:'p2w-2.3-4', subsection:'2.3', subsectionLabel:'Registry Hives', priority:'high', executable:true,
    label:'NTUSER.DAT của từng user',
    commands:['mkdir evidence 2>NUL','mkdir evidence\\ntuser 2>NUL','copy "C:\\Users\\*\\NTUSER.DAT" evidence\\ntuser\\ 2>NUL','copy "C:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat" evidence\\ntuser\\ 2>NUL'] },
  { id:'p2w-2.4-1', subsection:'2.4', subsectionLabel:'NTFS Artifacts', priority:'high', executable:false,
    label:'$MFT — metadata của tất cả files kể cả đã xóa',
    commands:['FTK Imager → Add Evidence Item → Logical Drive → Export Files → chọn $MFT'] },
  { id:'p2w-2.4-2', subsection:'2.4', subsectionLabel:'NTFS Artifacts', priority:'high', executable:true,
    label:'$UsnJrnl — file system change journal',
    commands:['fsutil usn readjournal C: csv > evidence\\usnjrnl.csv'] },
  { id:'p2w-2.4-3', subsection:'2.4', subsectionLabel:'NTFS Artifacts', priority:'high', executable:true,
    label:'Amcache.hve — application execution history',
    commands:['mkdir evidence 2>NUL','copy C:\\Windows\\AppCompat\\Programs\\Amcache.hve evidence\\ 2>NUL'] },
]

const PHASE2_LIN: ChecklistItem[] = [
  { id:'p2l-2.1-1', subsection:'2.1', subsectionLabel:'Memory (RAM) Dump', priority:'critical', executable:true,
    label:'Dump RAM bằng LiME kernel module',
    commands:['sudo insmod lime.ko "path=/tmp/mem.lime format=lime"'] },
  { id:'p2l-2.1-2', subsection:'2.1', subsectionLabel:'Memory (RAM) Dump', priority:'critical', executable:true,
    label:'Verify hash RAM dump',
    commands:['sha256sum mem.lime > mem.lime.sha256'] },
  { id:'p2l-2.1-3', subsection:'2.1', subsectionLabel:'Memory (RAM) Dump', priority:'high', executable:true,
    label:'Thu thập swap partition',
    commands:['swapon -s','dd if=/dev/sda2 of=/tmp/swap.raw bs=4M conv=noerror,sync'] },
  { id:'p2l-2.2-1', subsection:'2.2', subsectionLabel:'Disk Imaging', priority:'critical', executable:true,
    label:'Full disk image với hash tích hợp (dcfldd)',
    commands:['sudo dcfldd if=/dev/sda of=/mnt/evidence/disk.img hash=sha256 hashlog=disk.img.sha256 bs=4M conv=noerror,sync'] },
  { id:'p2l-2.2-2', subsection:'2.2', subsectionLabel:'Disk Imaging', priority:'critical', executable:true,
    label:'Verify hash sau khi imaging',
    commands:['sha256sum /mnt/evidence/disk.img > /mnt/evidence/disk.img.sha256'] },
  { id:'p2l-2.3-1', subsection:'2.3', subsectionLabel:'Sensitive Files', priority:'critical', executable:true,
    label:'/etc/shadow — password hashes',
    commands:['cp /etc/shadow evidence/shadow.txt 2>/dev/null'] },
  { id:'p2l-2.3-2', subsection:'2.3', subsectionLabel:'Sensitive Files', priority:'high', executable:true,
    label:'SSH private keys của tất cả users',
    commands:['find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null > ssh_keys_found.txt'] },
  { id:'p2l-2.3-3', subsection:'2.3', subsectionLabel:'Sensitive Files', priority:'high', executable:true,
    label:'Web shells trong web root',
    commands:['find /var/www /srv/www /usr/share/nginx -name "*.php" -newer /etc/passwd 2>/dev/null > new_php_files.txt'] },
]

const PHASE3_ITEMS: ChecklistItem[] = [
  { id:'p3-1', subsection:'3.0', subsectionLabel:'Chain of Custody', priority:'critical', executable:false,
    label:'Hash SHA256 TẤT CẢ file evidence sau khi thu thập', commands:[] },
  { id:'p3-2', subsection:'3.0', subsectionLabel:'Chain of Custody', priority:'critical', executable:false,
    label:'Ghi nhận Chain of Custody đầy đủ cho từng item', commands:[] },
  { id:'p3-3', subsection:'3.0', subsectionLabel:'Chain of Custody', priority:'critical', executable:false,
    label:'KHÔNG làm việc trực tiếp trên evidence gốc — luôn dùng bản copy', commands:[] },
  { id:'p3-4', subsection:'3.0', subsectionLabel:'Chain of Custody', priority:'critical', executable:false,
    label:'Dùng write-blocker khi imaging disk vật lý', commands:[] },
  { id:'p3-5', subsection:'3.0', subsectionLabel:'Chain of Custody', priority:'high', executable:false,
    label:'Tạo ít nhất 2 bản backup của toàn bộ evidence (3-2-1 rule)', commands:[] },
  { id:'p3-6', subsection:'3.0', subsectionLabel:'Chain of Custody', priority:'critical', executable:false,
    label:'Verify hash sau khi chuyển evidence đến nơi lưu trữ', commands:[] },
  { id:'p3-7', subsection:'3.0', subsectionLabel:'Chain of Custody', priority:'critical', executable:false,
    label:'Lưu trữ evidence tại nơi an toàn, kiểm soát truy cập', commands:[] },
]

const SECTIONS: ChecklistSection[] = [
  {
    id: 'p1', phase: 'Phase 1', label: 'Initial Collection — Thu thập bắt buộc',
    items: { win: PHASE1_WIN, linux: PHASE1_LIN },
  },
  {
    id: 'p2', phase: 'Phase 2', label: 'Dump & Imaging — Thực hiện tuỳ trường hợp', optional: true,
    items: { win: PHASE2_WIN, linux: PHASE2_LIN },
  },
  {
    id: 'coc', phase: 'Phase 3', label: 'Chain of Custody & Integrity', optional: false,
    items: { win: PHASE3_ITEMS, linux: PHASE3_ITEMS },
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

// Strip file output redirections so stdout flows back through the agent pipe.
// Commands like "netstat -anob > netstat.txt" redirect stdout to a FILE on the
// agent, making our pipe capture empty. Stripping the redirect lets the output
// stream back to the Results panel in real-time.
// Preserved: 2>NUL / 2>/dev/null (stderr suppression), 2>&1, >&2, >& (stream dup).
function prepareCmd(raw: string, platform: Platform): string {
  if (platform === 'win') {
    return raw
      .replace(/\s*>>\s*(?!NUL\b|nul\b)[^\s|&<>]+/gi, '')       // >> file  (not NUL)
      .replace(/(?<!\d)\s*>\s*(?!NUL\b|nul\b|&)[^\s|&<>]+/gi, '') // > file   (not 2>NUL / >&)
      .trim()
  } else {
    return raw
      .replace(/\s*>>\s*(?!\/dev\/)[^\s|&;]+/g, '')               // >> file  (not /dev/null)
      .replace(/(?<!\d)\s*>\s*(?!\/dev\/|&)[^\s|&;]+/g, '')        // > file   (not 2>/dev/null / >&)
      .trim()
  }
}

function buildBatchCommand(items: ChecklistItem[], platform: Platform): string {
  const join = platform === 'win' ? ' & ' : ' ; '
  const parts = items
    .filter(it => it.executable && it.commands.length > 0)
    .map(it => it.commands
      .filter(c => c.trim() !== '')
      .map(c => prepareCmd(c, platform))
      .filter(c => c !== '')
      .join(join))
    .filter(p => p !== '')
  return parts.join(join)
}

function groupBySubsection(items: ChecklistItem[]): Map<string, { key: string; label: string; items: ChecklistItem[] }> {
  const map = new Map<string, { key: string; label: string; items: ChecklistItem[] }>()
  for (const item of items) {
    if (!map.has(item.subsection)) {
      map.set(item.subsection, { key: item.subsection, label: item.subsectionLabel, items: [] })
    }
    map.get(item.subsection)!.items.push(item)
  }
  return map
}

const PRIORITY_COLORS: Record<Priority, string> = {
  critical: 'bg-red-500/15 text-red-400 border border-red-500/30',
  high:     'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30',
  medium:   'bg-blue-500/15 text-blue-400 border border-blue-500/30',
}

const STATUS_ICON: Record<string, JSX.Element> = {
  pending: <Clock className="w-4 h-4 text-gray-500" />,
  running: <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />,
  done:    <CheckCircle2 className="w-4 h-4 text-green-400" />,
  failed:  <XCircle className="w-4 h-4 text-red-400" />,
  stopped: <XCircle className="w-4 h-4 text-yellow-400" />,
}

// ─── BatchResultCard ──────────────────────────────────────────────────────────

function BatchResultCard({ batch }: { batch: ChecklistBatch & { liveOutput?: string; liveStatus?: string } }) {
  const status = batch.liveStatus ?? batch.status
  const rawOutput = batch.liveOutput ?? batch.output ?? ''
  const isSavedToFile = rawOutput === '[Output saved to file]'
  const [expanded, setExpanded] = useState(true)
  const outputRef = useRef<HTMLPreElement>(null)
  const [fetchedOutput, setFetchedOutput] = useState<string | null>(null)

  const displayOutput = fetchedOutput !== null ? fetchedOutput : rawOutput
  const lineCount = displayOutput.split('\n').filter(Boolean).length

  useEffect(() => {
    if (status === 'running') setExpanded(true)
  }, [status])

  useEffect(() => {
    if (expanded && isSavedToFile && fetchedOutput === null) {
      setFetchedOutput('Loading output from file...\n')
      checklistApi.downloadBatchOutput(batch.id)
        .then(data => setFetchedOutput(data))
        .catch(err => setFetchedOutput(`Failed to load output: ${err.message}`))
    }
  }, [expanded, isSavedToFile, fetchedOutput, batch.id])

  useEffect(() => {
    if (status === 'running' && outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [displayOutput, status])

  const statusBar = {
    pending: 'bg-gray-500/20 border-gray-500/30 text-gray-400',
    running: 'bg-blue-500/15 border-blue-500/30 text-blue-300',
    done:    'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    failed:  'bg-red-500/10 border-red-500/30 text-red-400',
    stopped: 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400',
  }[status] ?? 'bg-gray-500/20 border-gray-500/30 text-gray-400'

  return (
    <div className={`rounded-lg overflow-hidden border ${statusBar} bg-[#0c0e18]`}>
      {/* Terminal-style title bar */}
      <div
        className="flex items-center gap-2 px-3 py-2 bg-[#171a2a] cursor-pointer select-none"
        onClick={() => setExpanded(e => !e)}
      >
        {/* Traffic-light dots */}
        <span className="flex gap-1.5 shrink-0">
          <span className="w-3 h-3 rounded-full bg-red-500/60" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/60" />
          <span className="w-3 h-3 rounded-full bg-green-500/60" />
        </span>
        <span className="text-[11px] font-mono text-[#5a6488]">
          {status === 'running' ? 'powershell.exe' : 'cmd.exe'} — [{batch.batch_key}]
        </span>
        <span className="flex-1 text-xs text-[#9ab] truncate">{batch.batch_label}</span>

        <div className="flex items-center gap-2 shrink-0">
          {STATUS_ICON[status] ?? STATUS_ICON.pending}
          {lineCount > 0 && (
            <span className="text-[10px] font-mono text-[#5a6488]">{lineCount} ln</span>
          )}
          {status === 'done' && batch.finished_at && (
            <span className="text-[10px] text-[#5a6488]">
              {new Date(batch.finished_at).toLocaleTimeString()}
            </span>
          )}
          {expanded
            ? <ChevronDown className="w-3.5 h-3.5 text-[#5a6488]" />
            : <ChevronRight className="w-3.5 h-3.5 text-[#5a6488]" />}
        </div>
      </div>

      {expanded && (
        <pre
          ref={outputRef}
          className="font-mono text-[11px] leading-relaxed text-[#a8c8a0] bg-[#060810] p-4 max-h-80 overflow-auto whitespace-pre-wrap break-all"
        >
          {displayOutput
            ? displayOutput
            : status === 'pending'
              ? <span className="text-[#5a6488]">Waiting for dispatch…</span>
              : status === 'running'
                ? <span className="text-blue-400 animate-pulse">▌ Streaming output…</span>
                : <span className="text-[#5a6488]">(no output captured)</span>
          }
          {status === 'running' && <span className="animate-pulse text-[#a8c8a0]">█</span>}
        </pre>
      )}
    </div>
  )
}

// ─── ItemRunButton ────────────────────────────────────────────────────────────


function ItemRunButton({ status, onClick, disabled }: {
  status: ItemStatus
  onClick: (e: React.MouseEvent) => void
  disabled: boolean
}) {
  const base = 'shrink-0 mt-0.5 flex items-center gap-1 px-2 py-1 rounded border text-[10px] font-semibold transition-all disabled:cursor-not-allowed disabled:opacity-40'
  const idle    = `${base} border-[#363d60] text-[#8fa8d0] hover:border-[#4f8ef7]/70 hover:bg-[#4f8ef7]/12 hover:text-[#4f8ef7]`
  const running = `${base} border-blue-500/40 text-blue-400 bg-blue-500/10`
  const done    = `${base} border-green-500/40 text-green-400 bg-green-500/10`
  const failed  = `${base} border-red-500/40 text-red-400 bg-red-500/10`

  const cls = status === 'running' ? running : status === 'done' ? done : status === 'failed' ? failed : idle

  return (
    <button
      onClick={onClick}
      disabled={disabled || status === 'running'}
      title={disabled ? 'Select an agent first' : status === 'running' ? 'Running…' : 'Run on agent'}
      className={cls}
    >
      {status === 'running' ? <Loader2 className="w-3 h-3 animate-spin" />
       : status === 'done'  ? <CheckCircle2 className="w-3 h-3" />
       : status === 'failed' ? <XCircle className="w-3 h-3" />
       : <Play className="w-3 h-3" />}
      <span>
        {status === 'running' ? 'Running' : status === 'done' ? 'Done' : status === 'failed' ? 'Failed' : 'Run'}
      </span>
    </button>
  )
}

// ─── ToolResultCard ───────────────────────────────────────────────────────────

function ToolResultCard({ result }: { result: ToolResult }) {
  const [expanded, setExpanded] = useState(true)
  const outputRef = useRef<HTMLPreElement>(null)

  useEffect(() => {
    if ((result.liveStatus === 'running' || result.liveStatus === 'downloading') && outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [result.liveOutput, result.liveStatus])

  const borderCls = {
    pending:     'border-gray-500/30',
    downloading: 'border-blue-500/30',
    running:     'border-purple-500/35',
    done:        'border-purple-500/40',
    failed:      'border-red-500/30',
  }[result.liveStatus] ?? 'border-gray-500/30'

  const statusIcon = {
    pending:     <Clock className="w-4 h-4 text-gray-500" />,
    downloading: <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />,
    running:     <Loader2 className="w-4 h-4 text-purple-400 animate-spin" />,
    done:        <CheckCircle2 className="w-4 h-4 text-purple-400" />,
    failed:      <XCircle className="w-4 h-4 text-red-400" />,
  }[result.liveStatus]

  const lineCount = result.liveOutput.split('\n').filter(Boolean).length

  return (
    <div className={`rounded-lg overflow-hidden border ${borderCls} bg-[#0c0e18]`}>
      <div
        className="flex items-center gap-2 px-3 py-2 bg-[#16122a] cursor-pointer select-none"
        onClick={() => setExpanded(e => !e)}
      >
        <span className="flex gap-1.5 shrink-0">
          <span className="w-3 h-3 rounded-full bg-red-500/60" />
          <span className="w-3 h-3 rounded-full bg-yellow-500/60" />
          <span className="w-3 h-3 rounded-full bg-purple-500/60" />
        </span>
        <Wrench className="w-3 h-3 text-purple-400 shrink-0" />
        <span className="flex-1 text-xs text-[#c8b0f0] truncate font-medium">{result.toolName}</span>
        <div className="flex items-center gap-2 shrink-0">
          {result.liveStatus === 'downloading' && (
            <span className="text-[10px] text-blue-400">Downloading…</span>
          )}
          {lineCount > 0 && (
            <span className="text-[10px] font-mono text-[#5a6488]">{lineCount} ln</span>
          )}
          {statusIcon}
          {expanded
            ? <ChevronDown className="w-3.5 h-3.5 text-[#5a6488]" />
            : <ChevronRight className="w-3.5 h-3.5 text-[#5a6488]" />}
        </div>
      </div>
      {expanded && (
        <pre
          ref={outputRef}
          className="font-mono text-[11px] leading-relaxed text-[#c8a8ff] bg-[#060810] p-4 max-h-80 overflow-auto whitespace-pre-wrap break-all"
        >
          {result.liveOutput
            ? result.liveOutput
            : result.liveStatus === 'downloading'
              ? <span className="text-blue-400 animate-pulse">⬇ Downloading tool to agent…</span>
              : <span className="text-[#5a6488]">Waiting…</span>
          }
          {(result.liveStatus === 'running') && <span className="animate-pulse text-[#c8a8ff]">█</span>}
        </pre>
      )}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function CollectionChecklist() {
  const navigate = useNavigate()
  const {
    platform, setPlatform,
    selectedAgent, setSelectedAgent,
    collapsed, setCollapsed,
    checked, setChecked,
    tab, setTab,
    running, setRunning,
    caseID, setCaseID,
    analyst, setAnalyst,
    itemStatus, setItemStatus,
    runIDs, setRunIDs,
    batchResults, setBatchResults,
    toolResults, setToolResults,
    openPickerFor, setOpenPickerFor,
    itemToolPick, setItemToolPick,
    itemToolRunning, setItemToolRunning,
    resetAgentState
  } = useChecklistStore()

  const [agents, setAgents] = useState<Agent[]>([])
  const queryClient = useQueryClient()
  const [tools, setTools] = useState<Tool[]>([])
  
  const pollTimersRef = useRef<Record<string, ReturnType<typeof setInterval>>>({})

  const esRefs = useRef<EventSource[]>([])

  useEffect(() => {
    agentsApi.list().then(setAgents).catch(() => {})
    toolsApi.list().then(setTools).catch(() => {})
  }, [])

  const { data: runs } = useQuery({
    queryKey: ['checklist-runs', selectedAgent],
    queryFn: () => checklistApi.listRuns(selectedAgent),
    enabled: !!selectedAgent,
  })

  // Auto-load latest run if batchResults is empty
  useEffect(() => {
    if (runs && runs.length > 0 && batchResults.length === 0 && !running && runIDs.length === 0) {
      const latest = runs[0]
      setRunIDs([latest.id])
      if (latest.batches) {
        setBatchResults(latest.batches.map((b: ChecklistBatch) => ({
          ...b,
          liveOutput: b.output,
          liveStatus: b.status
        })))
        
        // Restore itemStatus
        const newStatus: Record<string, ItemStatus> = {}
        latest.batches.forEach((b: ChecklistBatch) => {
          try {
            const ids: string[] = JSON.parse(b.item_ids || '[]')
            ids.forEach(id => {
              newStatus[id] = b.status === 'done' ? 'done' : b.status === 'failed' ? 'failed' : b.status === 'stopped' ? 'failed' : b.status === 'running' ? 'running' : 'idle'
            })
          } catch {}
        })
        setItemStatus(newStatus)
        setTab('results')
      }
    }
  }, [runs, batchResults.length, running, runIDs.length])

  // Track previous agent to reset state
  const prevAgentRef = useRef(selectedAgent)
  useEffect(() => {
    if (prevAgentRef.current !== selectedAgent) {
      resetAgentState(selectedAgent)
      prevAgentRef.current = selectedAgent
    }
  }, [selectedAgent, resetAgentState])

  useEffect(() => {
    if (!selectedAgent && agents.length > 0) {
      const online = agents.find(a => a.status === 'online')
      if (online) setSelectedAgent(online.id)
    }
  }, [agents, selectedAgent])

  useEffect(() => {
    return () => {
      esRefs.current.forEach(es => es.close())
      Object.values(pollTimersRef.current).forEach(t => clearInterval(t))
    }
  }, [])

  const allItems = (platform === 'win'
    ? [...PHASE1_WIN, ...PHASE2_WIN, ...PHASE3_ITEMS]
    : [...PHASE1_LIN, ...PHASE2_LIN, ...PHASE3_ITEMS])

  const checkedItems = allItems.filter(it => checked.has(it.id))
  const executableChecked = checkedItems.filter(it => it.executable)

  const batchGroups = (() => {
    const groups = new Map<string, { key: string; label: string; items: ChecklistItem[] }>()
    for (const item of executableChecked) {
      if (!groups.has(item.subsection)) {
        groups.set(item.subsection, { key: item.subsection, label: item.subsectionLabel, items: [] })
      }
      groups.get(item.subsection)!.items.push(item)
    }
    return Array.from(groups.values()).sort((a, b) => a.key.localeCompare(b.key, undefined, { numeric: true }))
  })()

  const activeCount = batchResults.filter(b => (b.liveStatus ?? b.status) === 'running').length

  // ── SSE subscription helper ──────────────────────────────────────────────

  function attachSSE(batches: ChecklistBatch[], affectedItemIds: string[]) {
    for (const batch of batches) {
      const es = checklistApi.streamBatchOutput(batch.id)
      esRefs.current.push(es)

      es.onmessage = (ev) => {
        const line: string = ev.data
        setBatchResults(prev => prev.map(b => {
          if (b.id !== batch.id) return b
          if (line === '__DONE__') {
            es.close()
            setItemStatus(prev2 => {
              const next = { ...prev2 }
              for (const id of affectedItemIds) next[id] = 'done'
              return next
            })
            return { ...b, liveStatus: 'done' }
          }
          return { ...b, liveOutput: (b.liveOutput ?? '') + line + '\n', liveStatus: 'running' }
        }))
      }

      es.onerror = () => {
        setBatchResults(prev => prev.map(b =>
          b.id === batch.id
            ? { ...b, liveStatus: (b.liveStatus ?? b.status) === 'done' ? 'done' : 'failed' }
            : b
        ))
        setItemStatus(prev => {
          const next = { ...prev }
          for (const id of affectedItemIds) {
            if (next[id] !== 'done') next[id] = 'failed'
          }
          return next
        })
        es.close()
      }
    }
  }

  // ── Run a single item ────────────────────────────────────────────────────

  async function handleRunSingle(item: ChecklistItem) {
    if (!selectedAgent || !item.executable) return
    const cmd = buildBatchCommand([item], platform)
    if (!cmd) return

    setItemStatus(prev => ({ ...prev, [item.id]: 'running' }))

    try {
      const result = await checklistApi.run({
        agent_id: selectedAgent,
        platform,
        label: item.label.slice(0, 60),
        case_id: caseID,
        analyst,
        batches: [{
          batch_key: item.subsection,
          batch_label: item.label.slice(0, 80),
          item_ids: [item.id],
          command: cmd,
        }],
      })

      setRunIDs(prev => [...prev, result.run_id])
      setBatchResults(prev => [
        ...prev,
        ...result.batches.map(b => ({ ...b, liveOutput: '', liveStatus: 'pending' as const })),
      ])

      queryClient.invalidateQueries({ queryKey: ['checklist-runs', selectedAgent] })
      attachSSE(result.batches, [item.id])
    } catch {
      setItemStatus(prev => ({ ...prev, [item.id]: 'failed' }))
    }
  }

  // ── Run all items in a subsection ────────────────────────────────────────

  async function handleRunGroup(groupKey: string, groupLabel: string, items: ChecklistItem[]) {
    if (!selectedAgent) return
    const execItems = items.filter(it => it.executable && it.commands.length > 0)
    if (execItems.length === 0) return

    const itemIds = execItems.map(it => it.id)
    setItemStatus(prev => {
      const next = { ...prev }
      for (const id of itemIds) next[id] = 'running'
      return next
    })

    try {
      const result = await checklistApi.run({
        agent_id: selectedAgent,
        platform,
        label: `Section ${groupKey}: ${groupLabel}`,
        case_id: caseID,
        analyst,
        batches: [{
          batch_key: groupKey,
          batch_label: groupLabel,
          item_ids: itemIds,
          command: buildBatchCommand(execItems, platform),
        }],
      })

      setRunIDs(prev => [...prev, result.run_id])
      setBatchResults(prev => [
        ...prev,
        ...result.batches.map(b => ({ ...b, liveOutput: '', liveStatus: 'pending' as const })),
      ])
      setTab('results')

      queryClient.invalidateQueries({ queryKey: ['checklist-runs', selectedAgent] })
      attachSSE(result.batches, itemIds)
    } catch {
      setItemStatus(prev => {
        const next = { ...prev }
        for (const id of itemIds) next[id] = 'failed'
        return next
      })
    }
  }

  // ── Run all selected (batch) ─────────────────────────────────────────────

  async function handleRun() {
    if (!selectedAgent || batchGroups.length === 0) return

    setRunning(true)
    const allItemIds = batchGroups.flatMap(g => g.items.filter(it => it.executable).map(it => it.id))
    setItemStatus(prev => {
      const next = { ...prev }
      for (const id of allItemIds) next[id] = 'running'
      return next
    })

    try {
      const result = await checklistApi.run({
        agent_id: selectedAgent,
        platform,
        label: `Evidence Collection ${new Date().toISOString().slice(0, 10)}`,
        case_id: caseID,
        analyst,
        batches: batchGroups.map(g => ({
          batch_key: g.key,
          batch_label: g.label,
          item_ids: g.items.map(it => it.id),
          command: buildBatchCommand(g.items, platform),
        })),
      })

      setRunIDs(prev => [...prev, result.run_id])
      setBatchResults(prev => [
        ...prev,
        ...result.batches.map(b => ({ ...b, liveOutput: '', liveStatus: 'pending' as const })),
      ])
      setTab('results')

      queryClient.invalidateQueries({ queryKey: ['checklist-runs', selectedAgent] })
      attachSSE(result.batches, allItemIds)
    } catch (err: any) {
      setItemStatus(prev => {
        const next = { ...prev }
        for (const id of allItemIds) next[id] = 'failed'
        return next
      })
      alert(err?.response?.data?.error ?? 'Failed to start checklist run')
    } finally {
      setRunning(false)
    }
  }

  // ── Run a tool for an item ───────────────────────────────────────────────

  async function handleRunTool(item: ChecklistItem) {
    const pick = itemToolPick[item.id]
    if (!pick?.toolId || !selectedAgent) return

    setItemToolRunning(prev => ({ ...prev, [item.id]: true }))
    setOpenPickerFor(null)

    try {
      const job = await jobsApi.create({ agent_id: selectedAgent, tool_id: pick.toolId, args: pick.args || '' })
      const toolName = job.tool?.name ?? tools.find(t => t.id === pick.toolId)?.name ?? 'Tool'

      const newResult: ToolResult = {
        jobId: job.id, itemId: item.id, toolName,
        liveOutput: '', liveStatus: 'downloading',
      }
      setToolResults(prev => [...prev, newResult])
      setTab('results')

      // Subscribe to output SSE — covers download progress then run output
      const es = jobsApi.streamOutput(job.id)
      esRefs.current.push(es)

      es.onmessage = (ev) => {
        const line: string = ev.data
        setToolResults(prev => prev.map(r => {
          if (r.jobId !== job.id) return r
          if (line === '__DONE__') {
            es.close()
            setItemToolRunning(prev2 => ({ ...prev2, [item.id]: false }))
            return { ...r, liveStatus: 'done' }
          }
          return { ...r, liveOutput: r.liveOutput + line + '\n', liveStatus: 'running' }
        }))
      }
      es.onerror = () => {
        setToolResults(prev => prev.map(r =>
          r.jobId === job.id && r.liveStatus !== 'done' ? { ...r, liveStatus: 'failed' } : r
        ))
        setItemToolRunning(prev => ({ ...prev, [item.id]: false }))
        es.close()
      }

      // Poll until ready → auto-run
      let attempts = 0
      const timer = setInterval(async () => {
        attempts++
        if (attempts > 30) {
          clearInterval(timer)
          delete pollTimersRef.current[job.id]
          setItemToolRunning(prev => ({ ...prev, [item.id]: false }))
          return
        }
        try {
          const current = await jobsApi.get(job.id)
          if (current.status === 'ready') {
            clearInterval(timer)
            delete pollTimersRef.current[job.id]
            setToolResults(prev => prev.map(r =>
              r.jobId === job.id ? { ...r, liveStatus: 'running' } : r
            ))
            await jobsApi.run(job.id)
          } else if (current.status === 'failed') {
            clearInterval(timer)
            delete pollTimersRef.current[job.id]
            setItemToolRunning(prev => ({ ...prev, [item.id]: false }))
          }
        } catch { /* ignore poll errors */ }
      }, 2000)
      pollTimersRef.current[job.id] = timer

    } catch (err: any) {
      setItemToolRunning(prev => ({ ...prev, [item.id]: false }))
      console.error('[handleRunTool]', err)
    }
  }

  function exportResults() {
    const lines: string[] = [
      `# DFIR Evidence Collection Report`,
      `Case ID : ${caseID || '(not set)'}`,
      `Analyst : ${analyst || '(not set)'}`,
      `Platform: ${platform === 'win' ? 'Windows' : 'Linux'}`,
      `Date    : ${new Date().toISOString()}`,
      `Run IDs : ${runIDs.join(', ') || '—'}`,
      '',
      `Total batches : ${batchResults.length}`,
      `Done          : ${batchResults.filter(b => (b.liveStatus ?? b.status) === 'done').length}`,
      `Failed        : ${batchResults.filter(b => (b.liveStatus ?? b.status) === 'failed').length}`,
      '',
      '─'.repeat(60),
      '',
    ]
    for (const b of batchResults) {
      lines.push(`## [${b.batch_key}] ${b.batch_label}`)
      lines.push(`Status : ${b.liveStatus ?? b.status}`)
      if (b.started_at)  lines.push(`Start  : ${new Date(b.started_at).toISOString()}`)
      if (b.finished_at) lines.push(`End    : ${new Date(b.finished_at).toISOString()}`)
      lines.push('')
      lines.push('```')
      lines.push(b.liveOutput ?? b.output ?? '(no output)')
      lines.push('```')
      lines.push('')
    }
    if (toolResults.length > 0) {
      lines.push('', '─'.repeat(60), '', '# TOOL RESULTS', '')
      for (const r of toolResults) {
        lines.push(`## Tool: ${r.toolName}`)
        lines.push(`Status: ${r.liveStatus}`)
        lines.push('```')
        lines.push(r.liveOutput || '(no output)')
        lines.push('```')
        lines.push('')
      }
    }
    const blob = new Blob([lines.join('\n')], { type: 'text/plain' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `dfir_report_${caseID || 'case'}_${Date.now()}.txt`
    a.click()
    URL.revokeObjectURL(a.href)
  }

  function clearResults() {
    esRefs.current.forEach(es => es.close())
    esRefs.current = []
    Object.values(pollTimersRef.current).forEach(t => clearInterval(t))
    pollTimersRef.current = {}
    setBatchResults([])
    setToolResults([])
    setRunIDs([])
    setItemStatus({})
    setItemToolRunning({})
  }

  function toggleItem(id: string) {
    setChecked(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id); else next.add(id)
      return next
    })
  }

  function selectCritical() { setChecked(new Set(allItems.filter(it => it.priority === 'critical').map(it => it.id))) }
  function selectAll()      { setChecked(new Set(allItems.map(it => it.id))) }
  function clearAll()        { setChecked(new Set()) }
  function toggleSection(id: string) { setCollapsed(prev => ({ ...prev, [id]: !prev[id] })) }

  const progressTotal = allItems.length
  const progressDone  = checked.size
  const progressPct   = progressTotal ? Math.round((progressDone / progressTotal) * 100) : 0

  return (
    <div className="flex flex-col h-full min-h-0 gap-0">

      {/* ── Header ── */}
      <div className="px-6 py-4 border-b border-[#2a2f4a] flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-bold text-[#4f8ef7]">DFIR — Evidence Collection Checklist</h1>
          <p className="text-xs text-[#5a6488] mt-0.5">Digital Forensics & Incident Response · Thu thập chứng cứ từ máy mục tiêu</p>
        </div>
        <div className="flex flex-wrap gap-3">
          {[
            { label: 'Case ID', value: caseID, set: setCaseID, placeholder: 'IR-2025-001' },
            { label: 'Analyst', value: analyst, set: setAnalyst, placeholder: 'Họ tên' },
          ].map(f => (
            <div key={f.label} className="flex flex-col gap-1">
              <label className="text-[10px] uppercase tracking-widest text-[#5a6488]">{f.label}</label>
              <input
                value={f.value}
                onChange={e => f.set(e.target.value)}
                placeholder={f.placeholder}
                className="bg-[#1c2030] border border-[#2a2f4a] rounded-md text-[#dde3f0] text-xs px-2 py-1 w-36 focus:outline-none focus:border-[#4f8ef7]"
              />
            </div>
          ))}
        </div>
      </div>

      {/* ── Controls bar ── */}
      <div className="px-6 py-3 border-b border-[#2a2f4a] flex items-center gap-4 flex-wrap bg-[#131620]">
        {/* Platform */}
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-widest text-[#5a6488]">Platform:</span>
          <div className="flex border border-[#2a2f4a] rounded-lg overflow-hidden">
            {(['win', 'linux'] as Platform[]).map(p => (
              <button
                key={p}
                onClick={() => setPlatform(p)}
                className={`px-4 py-1.5 text-xs font-semibold transition-colors ${
                  platform === p
                    ? p === 'win' ? 'bg-sky-500/15 text-sky-400' : 'bg-orange-500/15 text-orange-400'
                    : 'bg-[#1c2030] text-[#5a6488] hover:text-[#dde3f0]'
                }`}
              >
                {p === 'win' ? '⊞ Windows' : '🐧 Linux'}
              </button>
            ))}
          </div>
        </div>

        {/* Agent */}
        <div className="flex items-center gap-2">
          <span className="text-[10px] uppercase tracking-widest text-[#5a6488]">Agent:</span>
          <select
            value={selectedAgent}
            onChange={e => setSelectedAgent(e.target.value)}
            className="bg-[#1c2030] border border-[#2a2f4a] rounded-md text-xs text-[#dde3f0] px-2 py-1.5 focus:outline-none focus:border-[#4f8ef7]"
          >
            <option value="">— Select agent —</option>
            {agents.map(a => (
              <option key={a.id} value={a.id} disabled={a.status !== 'online'}>
                {a.name} ({a.hostname}) {a.status !== 'online' ? '— offline' : ''}
              </option>
            ))}
          </select>
        </div>

        {/* Quick select + Run All */}
        <div className="flex gap-1.5 ml-auto items-center flex-wrap">
          <button onClick={selectCritical} className="text-xs px-2 py-1 rounded border border-[#363d60] text-[#5a6488] hover:text-[#dde3f0] hover:border-[#4f8ef7] transition-colors">Critical only</button>
          <button onClick={selectAll}      className="text-xs px-2 py-1 rounded border border-[#363d60] text-[#5a6488] hover:text-[#dde3f0] hover:border-[#4f8ef7] transition-colors">Select all</button>
          <button onClick={clearAll}       className="text-xs px-2 py-1 rounded border border-[#363d60] text-[#5a6488] hover:text-[#dde3f0] transition-colors">Clear</button>

          {batchGroups.length > 0 && (
            <button
              onClick={handleRun}
              disabled={running || !selectedAgent}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-[#4f8ef7] hover:bg-[#3a7de6] disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold transition-colors ml-1"
            >
              {running
                ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                : <Play className="w-3.5 h-3.5" />
              }
              Run {batchGroups.length} batch{batchGroups.length > 1 ? 'es' : ''}
            </button>
          )}
        </div>
      </div>

      {/* ── Progress bar ── */}
      <div className="px-6 py-2 bg-[#0d0f18] border-b border-[#2a2f4a]">
        <div className="flex justify-between text-[11px] text-[#5a6488] mb-1">
          <span>Tiến độ checklist</span>
          <span className={platform === 'win' ? 'text-sky-400' : 'text-orange-400'}>
            {progressDone} / {progressTotal} ({progressPct}%)
          </span>
        </div>
        <div className="h-1.5 rounded-full bg-[#1c2030] overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-300 ${platform === 'win' ? 'bg-gradient-to-r from-sky-600 to-sky-400' : 'bg-gradient-to-r from-orange-600 to-orange-400'}`}
            style={{ width: `${progressPct}%` }}
          />
        </div>
      </div>

      {/* ── Tabs ── */}
      <div className="flex border-b border-[#2a2f4a] bg-[#131620] px-6">
        {(['checklist', 'results'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`relative text-sm px-4 py-2.5 border-b-2 transition-colors capitalize ${
              tab === t ? 'border-[#4f8ef7] text-[#4f8ef7]' : 'border-transparent text-[#5a6488] hover:text-[#dde3f0]'
            }`}
          >
            {t === 'checklist' ? 'Checklist' : `Results${batchResults.length > 0 ? ` (${batchResults.length})` : ''}`}
            {t === 'results' && activeCount > 0 && (
              <span className="absolute top-2 right-1 flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-blue-400" />
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── Content ── */}
      <div className="flex-1 overflow-y-auto">

        {/* ─── CHECKLIST TAB ─────────────────────────────────────────── */}
        {tab === 'checklist' && (
          <div className="p-6 flex flex-col gap-4 max-w-4xl">
            {SECTIONS.map(section => {
              const sectionItems = section.items[platform === 'win' ? 'win' : 'linux']
              const groups = groupBySubsection(sectionItems)
              const isCollapsed = collapsed[section.id]
              const sectionChecked = sectionItems.filter(it => checked.has(it.id)).length

              return (
                <div key={section.id} className="border border-[#2a2f4a] rounded-xl overflow-hidden">
                  {/* Section header */}
                  <button
                    onClick={() => toggleSection(section.id)}
                    className="w-full flex items-center gap-3 px-4 py-3 bg-[#1c2030] hover:bg-[#232840] transition-colors text-left"
                  >
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                      section.id === 'p1' ? 'bg-red-500/15 text-red-400' :
                      section.id === 'p2' ? 'bg-yellow-500/15 text-yellow-400' :
                      'bg-purple-500/15 text-purple-400'
                    }`}>
                      {section.phase}
                    </span>
                    <span className="text-sm font-semibold text-[#dde3f0] flex-1">{section.label}</span>
                    {section.optional && (
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-yellow-500/10 text-yellow-400 border border-yellow-500/30">Situational</span>
                    )}
                    <span className="text-xs text-[#5a6488]">{sectionChecked} / {sectionItems.length}</span>
                    {isCollapsed ? <ChevronRight className="w-4 h-4 text-[#5a6488]" /> : <ChevronDown className="w-4 h-4 text-[#5a6488]" />}
                  </button>

                  {!isCollapsed && (
                    <div>
                      {Array.from(groups.values()).map(group => {
                        const hasExec = group.items.some(it => it.executable && it.commands.length > 0)
                        return (
                          <div key={group.key}>
                            {/* Subsection header */}
                            <div className="flex items-center gap-2 px-4 pt-3 pb-1 border-t border-[#2a2f4a]">
                              <span className="text-[10px] uppercase tracking-widest text-[#5a6488] flex-1">
                                {group.key} · {group.label}
                              </span>

                              {/* Run section button */}
                              {hasExec && (
                                <button
                                  onClick={() => handleRunGroup(group.key, group.label, group.items)}
                                  disabled={!selectedAgent}
                                  title={!selectedAgent ? 'Select an agent first' : `Run all steps in ${group.label}`}
                                  className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border border-[#2a2f4a] text-[#5a6488] hover:text-[#4f8ef7] hover:border-[#4f8ef7]/50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                  <Play className="w-2.5 h-2.5" />
                                  Run section
                                </button>
                              )}

                              {group.items.some(it => checked.has(it.id) && it.executable) && (
                                <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#4f8ef7]/10 text-[#4f8ef7] border border-[#4f8ef7]/30 font-mono">
                                  Batch {group.key}
                                </span>
                              )}
                            </div>

                            {/* Items */}
                            {group.items.map(item => {
                              const isChecked = checked.has(item.id)
                              return (
                                <div
                                  key={item.id}
                                  className="flex items-start gap-3 px-4 py-2.5 transition-colors hover:bg-[#1c2030]"
                                >
                                  {/* Checkbox */}
                                  <button
                                    onClick={() => toggleItem(item.id)}
                                    className="mt-0.5 shrink-0"
                                  >
                                    {isChecked
                                      ? <CheckSquare className="w-4 h-4 text-green-400" />
                                      : <Square className="w-4 h-4 text-[#363d60]" />
                                    }
                                  </button>

                                  {/* Content — dim when checked, not the whole row */}
                                  <div className={`flex-1 min-w-0 transition-opacity ${isChecked ? 'opacity-50' : ''}`}>
                                    <div className={`text-sm ${isChecked ? 'line-through text-[#5a6488]' : 'text-[#dde3f0]'}`}>
                                      {item.label}
                                    </div>
                                    {item.commands.length > 0 && (
                                      <code className="mt-1.5 block text-[11px] font-mono text-[#8fa8d0] bg-[#0d0f18] border border-[#2a2f4a] rounded px-2.5 py-1.5 whitespace-pre-wrap break-all leading-relaxed">
                                        {item.commands.join('\n')}
                                      </code>
                                    )}
                                    {!item.executable && (
                                      <span className="mt-1 inline-flex items-center gap-1 text-[10px] text-yellow-400">
                                        <AlertTriangle className="w-3 h-3" /> Manual step only
                                      </span>
                                    )}
                                  </div>

                                  {/* Priority badge */}
                                  <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded-full shrink-0 mt-0.5 ${PRIORITY_COLORS[item.priority]}`}>
                                    {item.priority}
                                  </span>

                                  {/* Per-item cmd run button */}
                                  {item.executable && item.commands.length > 0 && (
                                    <ItemRunButton
                                      status={itemStatus[item.id] ?? 'idle'}
                                      disabled={!selectedAgent}
                                      onClick={(e) => { e.stopPropagation(); handleRunSingle(item) }}
                                    />
                                  )}

                                  {/* Tool picker toggle button */}
                                  {item.executable && (
                                    <button
                                      onClick={(e) => {
                                        e.stopPropagation()
                                        setOpenPickerFor(openPickerFor === item.id ? null : item.id)
                                      }}
                                      title="Add a tool to run alongside this step"
                                      className={`shrink-0 mt-0.5 flex items-center gap-1 px-2 py-1 rounded border text-[10px] font-semibold transition-all
                                        ${openPickerFor === item.id
                                          ? 'border-purple-500/60 bg-purple-500/15 text-purple-300'
                                          : 'border-[#363d60] text-[#5a6488] hover:border-purple-500/50 hover:text-purple-400'
                                        }`}
                                    >
                                      <Wrench className="w-3 h-3" />
                                      {itemToolPick[item.id]?.toolId
                                        ? <span className="max-w-[60px] truncate">{tools.find(t => t.id === itemToolPick[item.id].toolId)?.name ?? 'Tool'}</span>
                                        : <span>+ Tool</span>
                                      }
                                    </button>
                                  )}
                                </div>
                              )
                            })}

                            {/* Inline tool picker — appears below whichever item has it open */}
                            {group.items.map(item => openPickerFor === item.id && (
                              <div
                                key={`picker-${item.id}`}
                                onClick={e => e.stopPropagation()}
                                className="mx-4 mb-2 p-3 rounded-lg border border-purple-500/25 bg-purple-500/5 flex items-center gap-2 flex-wrap"
                              >
                                <Wrench className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                                <select
                                  value={itemToolPick[item.id]?.toolId ?? ''}
                                  onChange={e => {
                                    const toolId = e.target.value
                                    const defaultArgs = tools.find(t => t.id === toolId)?.args ?? ''
                                    setItemToolPick(prev => ({ ...prev, [item.id]: { toolId, args: defaultArgs } }))
                                  }}
                                  className="bg-[#1c2030] border border-[#2a2f4a] rounded text-xs text-[#dde3f0] px-2 py-1.5 focus:outline-none focus:border-purple-500/60 min-w-[160px]"
                                >
                                  <option value="">— Select tool —</option>
                                  {tools
                                    .filter(t =>
                                      platform === 'win'
                                        ? t.platform === 'windows' || t.platform === 'both'
                                        : t.platform === 'linux'  || t.platform === 'both'
                                    )
                                    .map(t => (
                                      <option key={t.id} value={t.id}>
                                        {t.name} v{t.version} · {t.category}
                                      </option>
                                    ))
                                  }
                                </select>

                                <input
                                  value={itemToolPick[item.id]?.args ?? ''}
                                  onChange={e => setItemToolPick(prev => ({
                                    ...prev,
                                    [item.id]: { ...prev[item.id], args: e.target.value },
                                  }))}
                                  placeholder="Args override (optional)"
                                  className="flex-1 min-w-[120px] bg-[#1c2030] border border-[#2a2f4a] rounded text-xs text-[#dde3f0] px-2 py-1.5 focus:outline-none focus:border-purple-500/60 font-mono"
                                />

                                <button
                                  onClick={() => handleRunTool(item)}
                                  disabled={!itemToolPick[item.id]?.toolId || itemToolRunning[item.id] || !selectedAgent}
                                  className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-purple-500/40 bg-purple-500/15 text-purple-300 hover:bg-purple-500/25 text-xs font-semibold transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                  {itemToolRunning[item.id]
                                    ? <Loader2 className="w-3 h-3 animate-spin" />
                                    : <Play className="w-3 h-3" />
                                  }
                                  {itemToolRunning[item.id] ? 'Running…' : 'Run Tool'}
                                </button>
                              </div>
                            ))}
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              )
            })}

            {/* Batch preview */}
            {batchGroups.length > 0 && (
              <div className="border border-[#4f8ef7]/30 bg-[#4f8ef7]/5 rounded-xl p-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <p className="text-sm font-semibold text-[#dde3f0]">
                      {executableChecked.length} commands in {batchGroups.length} parallel batch{batchGroups.length > 1 ? 'es' : ''}
                    </p>
                    <p className="text-xs text-[#5a6488] mt-0.5">
                      Each batch runs simultaneously — commands within a batch run sequentially
                    </p>
                  </div>
                  <button
                    onClick={handleRun}
                    disabled={running || !selectedAgent}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#4f8ef7] hover:bg-[#3a7de6] disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold transition-colors"
                  >
                    {running ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                    {running ? 'Dispatching…' : 'Start Collection'}
                  </button>
                </div>
                <div className="flex flex-wrap gap-2">
                  {batchGroups.map(g => (
                    <div key={g.key} className="flex items-center gap-1.5 text-xs bg-[#131620] border border-[#2a2f4a] rounded-lg px-2 py-1">
                      <Terminal className="w-3 h-3 text-[#4f8ef7]" />
                      <span className="text-[#5a6488] font-mono">{g.key}</span>
                      <span className="text-[#dde3f0]">{g.label}</span>
                      <span className="text-[#5a6488]">({g.items.filter(it => it.executable).length} cmd)</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ─── RESULTS TAB ───────────────────────────────────────────── */}
        {tab === 'results' && (
          <div className="p-6 flex flex-col gap-4">
            {batchResults.length === 0 && toolResults.length === 0 ? (
              <div className="text-center py-16 text-[#5a6488]">
                <Terminal className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p className="text-sm">No results yet.</p>
                <p className="text-xs mt-1 opacity-60">Click <Play className="w-3 h-3 inline" /> next to any step, or use "Run batches" to start collection.</p>
              </div>
            ) : (
              <>
                {/* Results header */}
                <div className="flex items-center justify-between flex-wrap gap-3">
                  <div>
                    <p className="text-sm text-[#dde3f0] font-semibold">
                      {batchResults.filter(b => (b.liveStatus ?? b.status) === 'done').length}/{batchResults.length} CMD
                      {toolResults.length > 0 && (
                        <span className="ml-2 text-purple-300">{toolResults.filter(r => r.liveStatus === 'done').length}/{toolResults.length} Tools</span>
                      )}
                      {activeCount > 0 && (
                        <span className="ml-2 text-xs text-blue-400 font-normal">{activeCount} running…</span>
                      )}
                    </p>
                    <p className="text-xs text-[#5a6488] mt-0.5 font-mono">
                      {runIDs.length} run{runIDs.length !== 1 ? 's' : ''}
                    </p>
                  </div>
                  <div className="flex gap-2 flex-wrap">
                    <button
                      onClick={() => { setBatchResults(prev => [...prev]); setToolResults(prev => [...prev]) }}
                      className="flex items-center gap-1 text-xs px-2 py-1 border border-[#363d60] rounded text-[#5a6488] hover:text-[#dde3f0] transition-colors"
                    >
                      <RotateCcw className="w-3 h-3" /> Refresh
                    </button>
                    <button
                      onClick={clearResults}
                      className="flex items-center gap-1 text-xs px-2 py-1 border border-[#363d60] rounded text-[#5a6488] hover:text-red-400 hover:border-red-500/40 transition-colors"
                    >
                      <Trash2 className="w-3 h-3" /> Clear
                    </button>
                    <button
                      onClick={exportResults}
                      disabled={batchResults.length === 0 && toolResults.length === 0}
                      className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-emerald-500/15 border border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/25 transition-colors font-medium disabled:opacity-40"
                    >
                      <Download className="w-3.5 h-3.5" /> Export Report
                    </button>
                    {runIDs.length > 0 && (
                      <button
                        onClick={() => navigate(`/ai-analysis?source=checklist_run&id=${runIDs[runIDs.length - 1]}`)}
                        className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg bg-violet-500/15 border border-violet-500/30 text-violet-300 hover:bg-violet-500/25 transition-colors font-medium"
                      >
                        <BrainCircuit className="w-3.5 h-3.5" /> Analyze with AI
                      </button>
                    )}
                  </div>
                </div>

                {/* 2-column when tool results exist, single column otherwise */}
                <div className={`grid gap-4 ${toolResults.length > 0 ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1 max-w-4xl'}`}>

                  {/* Left column: CMD output */}
                  <div className="flex flex-col gap-3 min-w-0">
                    {toolResults.length > 0 && (
                      <div className="flex items-center gap-2 pb-1 border-b border-[#2a2f4a]">
                        <Terminal className="w-3.5 h-3.5 text-[#4f8ef7]" />
                        <span className="text-xs text-[#5a6488] uppercase tracking-widest">CMD / Shell Output</span>
                        <span className="text-xs text-[#363d60]">({batchResults.length})</span>
                      </div>
                    )}
                    {batchResults.length > 0
                      ? batchResults.map((b, i) => <BatchResultCard key={`${b.id}-${i}`} batch={b} />)
                      : toolResults.length > 0 && (
                          <div className="text-center py-8 text-[#5a6488] text-xs">No CMD results yet</div>
                        )
                    }
                  </div>

                  {/* Right column: Tool output */}
                  {toolResults.length > 0 && (
                    <div className="flex flex-col gap-3 min-w-0">
                      <div className="flex items-center gap-2 pb-1 border-b border-[#2a2f4a]">
                        <Wrench className="w-3.5 h-3.5 text-purple-400" />
                        <span className="text-xs text-[#5a6488] uppercase tracking-widest">Tool Output</span>
                        <span className="text-xs text-[#363d60]">({toolResults.length})</span>
                      </div>
                      {toolResults.map(r => <ToolResultCard key={r.jobId} result={r} />)}
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
