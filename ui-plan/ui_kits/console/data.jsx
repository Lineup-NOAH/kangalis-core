/* Kangalis — mock data. Realistic CVEs, IPs, exploits, severities.
   Severity/status are stored as keys; labels resolve through i18n. */
(function () {
  const vulns = [
    { cve: 'CVE-2024-3094', title: 'XZ Utils backdoor in liblzma (SSH RCE)', cvss: 10.0, sev: 'critical', kev: true,  epss: 0.94, asset: '10.20.4.11', svc: 'sshd :22' },
    { cve: 'CVE-2021-44228', title: 'Apache Log4j2 JNDI remote code execution', cvss: 10.0, sev: 'critical', kev: true,  epss: 0.97, asset: '10.20.7.42', svc: 'tomcat :8080' },
    { cve: 'CVE-2023-23397', title: 'Microsoft Outlook privilege escalation',   cvss: 9.8,  sev: 'critical', kev: true,  epss: 0.89, asset: '10.20.2.8',  svc: 'smtp :25' },
    { cve: 'CVE-2024-21413', title: 'Outlook MonikerLink RCE',                   cvss: 9.8,  sev: 'critical', kev: false, epss: 0.61, asset: '10.20.2.31', svc: 'msrpc :135' },
    { cve: 'CVE-2023-34362', title: 'MOVEit Transfer SQL injection',             cvss: 9.8,  sev: 'critical', kev: true,  epss: 0.92, asset: '10.20.9.5',  svc: 'https :443' },
    { cve: 'CVE-2022-1388',  title: 'F5 BIG-IP iControl REST auth bypass',       cvss: 9.8,  sev: 'critical', kev: true,  epss: 0.90, asset: '10.20.1.2',  svc: 'https :443' },
    { cve: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset DoS',                    cvss: 7.5,  sev: 'high',     kev: true,  epss: 0.74, asset: '10.20.7.10', svc: 'nginx :443' },
    { cve: 'CVE-2024-1709',  title: 'ConnectWise ScreenConnect auth bypass',     cvss: 8.4,  sev: 'high',     kev: true,  epss: 0.88, asset: '10.20.5.19', svc: 'https :8040' },
    { cve: 'CVE-2023-4863',  title: 'libwebp heap buffer overflow',              cvss: 8.8,  sev: 'high',     kev: true,  epss: 0.55, asset: '10.20.6.77', svc: 'chrome' },
    { cve: 'CVE-2022-30190', title: 'MSDT "Follina" code execution',             cvss: 7.8,  sev: 'high',     kev: true,  epss: 0.71, asset: '10.20.2.44', svc: 'msdt' },
    { cve: 'CVE-2023-38545', title: 'curl SOCKS5 heap buffer overflow',          cvss: 7.5,  sev: 'high',     kev: false, epss: 0.18, asset: '10.20.4.61', svc: 'curl' },
    { cve: 'CVE-2021-34527', title: 'Windows Print Spooler "PrintNightmare"',    cvss: 8.8,  sev: 'high',     kev: true,  epss: 0.83, asset: '10.20.3.12', svc: 'spoolss :445' },
    { cve: 'CVE-2023-2868',  title: 'Barracuda ESG command injection',           cvss: 6.4,  sev: 'medium',   kev: true,  epss: 0.46, asset: '10.20.8.3',  svc: 'smtp :25' },
    { cve: 'CVE-2024-27198', title: 'TeamCity authentication bypass',            cvss: 6.5,  sev: 'medium',   kev: false, epss: 0.62, asset: '10.20.5.40', svc: 'https :8111' },
    { cve: 'CVE-2023-0386',  title: 'Linux OverlayFS local privilege esc.',      cvss: 5.5,  sev: 'medium',   kev: false, epss: 0.09, asset: '10.20.4.11', svc: 'kernel' },
    { cve: 'CVE-2022-40684', title: 'Fortinet FortiOS auth bypass',              cvss: 6.7,  sev: 'medium',   kev: true,  epss: 0.51, asset: '10.20.1.9',  svc: 'https :443' },
    { cve: 'CVE-2023-29059', title: '3CX desktop app supply-chain',              cvss: 4.3,  sev: 'low',      kev: false, epss: 0.07, asset: '10.20.2.55', svc: '3cx' },
    { cve: 'CVE-2024-0204',  title: 'GoAnywhere MFT auth bypass',                cvss: 3.7,  sev: 'low',      kev: false, epss: 0.12, asset: '10.20.9.21', svc: 'https :443' },
    { cve: 'CVE-2023-50164', title: 'Apache Struts path traversal',              cvss: 3.1,  sev: 'low',      kev: false, epss: 0.05, asset: '10.20.7.33', svc: 'tomcat :8080' },
    { cve: 'CVE-2023-39336', title: 'Ivanti EPM information disclosure',         cvss: 2.4,  sev: 'info',     kev: false, epss: 0.02, asset: '10.20.5.4',  svc: 'http :80' },
  ];

  const scans = [
    { id: 'SCN-2041', target: '10.20.4.0/24', type: 't_network', status: 'running',   pct: 62, started: '14:02', intensity: 'aggressive' },
    { id: 'SCN-2040', target: '10.20.7.42',   type: 't_web',     status: 'running',   pct: 31, started: '13:58', intensity: 'safe' },
    { id: 'SCN-2039', target: '10.20.2.0/25', type: 't_network', status: 'completed', pct: 100, started: '12:10', intensity: 'safe' },
    { id: 'SCN-2038', target: '10.20.9.5',    type: 't_web',     status: 'completed', pct: 100, started: '11:44', intensity: 'aggressive' },
    { id: 'SCN-2037', target: '10.20.1.0/24', type: 't_network', status: 'failed',    pct: 0,   started: '10:21', intensity: 'safe' },
    { id: 'SCN-2036', target: '10.20.5.0/24', type: 't_network', status: 'pending',   pct: 0,   started: '—',     intensity: 'safe' },
  ];

  const zones = [
    { name: 'DMZ',            cidrs: ['10.20.1.0/24', '10.20.2.0/24'], hosts: 96 },
    { name: 'Corp LAN',       cidrs: ['10.20.4.0/22'],                 hosts: 312 },
    { name: 'Server Farm',    cidrs: ['10.20.7.0/24', '10.20.8.0/24'], hosts: 144 },
    { name: 'OT / SCADA',     cidrs: ['10.30.0.0/24'],                 hosts: 38 },
    { name: 'Guest Wi-Fi',    cidrs: ['10.40.0.0/22'],                 hosts: 60 },
    { name: 'Management',     cidrs: ['10.20.0.0/28'],                 hosts: 12 },
  ];

  const creds = [
    { user: 'svc_scanner', type: 'SSH',   port: ':22',   zone: 'Server Farm' },
    { user: 'administrator', type: 'WinRM', port: ':5985', zone: 'Corp LAN' },
    { user: 'rdp_audit',   type: 'RDP',   port: ':3389', zone: 'DMZ' },
    { user: 'root',        type: 'SSH',   port: ':22',   zone: 'OT / SCADA' },
    { user: 'backup_ro',   type: 'SSH',   port: ':22',   zone: 'Management' },
    { user: 'helpdesk',    type: 'RDP',   port: ':3389', zone: 'Corp LAN' },
  ];

  const exploits = [
    { id: 'EDB-51987',           src: 'Exploit-DB',  title: 'XZ liblzma backdoor — SSH auth bypass PoC',        cves: ['CVE-2024-3094'] },
    { id: 'exploit/multi/log4j', src: 'Metasploit',  title: 'Log4Shell HTTP header JNDI injection',             cves: ['CVE-2021-44228'] },
    { id: 'CVE-2023-34362',      src: 'NVD',         title: 'MOVEit Transfer SQLi — record',                    cves: ['CVE-2023-34362'] },
    { id: 'EDB-51847',           src: 'Exploit-DB',  title: 'ScreenConnect 23.9.7 auth bypass + RCE',           cves: ['CVE-2024-1709','CVE-2024-1708'] },
    { id: 'exploit/windows/smb', src: 'Metasploit',  title: 'PrintNightmare RpcAddPrinterDriverEx',             cves: ['CVE-2021-34527'] },
    { id: 'CVE-2022-1388',       src: 'NVD',         title: 'F5 BIG-IP iControl REST unauth RCE — record',      cves: ['CVE-2022-1388'] },
    { id: 'EDB-50808',           src: 'Exploit-DB',  title: 'Follina MSDT ms-msdt:// document RCE',             cves: ['CVE-2022-30190'] },
    { id: 'exploit/linux/local', src: 'Metasploit',  title: 'OverlayFS local privilege escalation',            cves: ['CVE-2023-0386'] },
    { id: 'CVE-2024-27198',      src: 'NVD',         title: 'JetBrains TeamCity auth bypass — record',          cves: ['CVE-2024-27198'] },
  ];

  const audit = [
    { when: '2026-06-05 14:02', actor: 'm.demir',  role: 'role_admin',   action: 'Started aggressive scan SCN-2041 on 10.20.4.0/24' },
    { when: '2026-06-05 13:40', actor: 'a.yilmaz', role: 'role_analyst', action: 'Viewed credential vault (Server Farm)' },
    { when: '2026-06-05 13:12', actor: 'm.demir',  role: 'role_admin',   action: 'Updated exploit database (NVD, Exploit-DB, Metasploit)' },
    { when: '2026-06-05 11:44', actor: 's.kaya',   role: 'role_analyst', action: 'Exported report R-2026-22 (PDF)' },
    { when: '2026-06-05 10:21', actor: 'm.demir',  role: 'role_admin',   action: 'Scan SCN-2037 failed — host unreachable' },
    { when: '2026-06-05 09:05', actor: 'a.yilmaz', role: 'role_analyst', action: 'Created IP zone "OT / SCADA" (10.30.0.0/24)' },
    { when: '2026-06-04 17:55', actor: 'admin',    role: 'role_admin',   action: 'Added WinRM credential for Corp LAN' },
  ];

  const stats = { assets: 662, open: 148, scans: 6, exploit: 24180 };
  const sevCounts = { critical: 18, high: 41, medium: 53, low: 29, info: 7 };
  const exploitCounts = { total: 24180, NVD: 19420, 'Exploit-DB': 3160, Metasploit: 1600 };

  window.KDATA = { vulns, scans, zones, creds, exploits, audit, stats, sevCounts, exploitCounts };
})();
