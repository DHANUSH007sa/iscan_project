import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { CheckCircle, XCircle, AlertTriangle, Shield, Activity, Lock, Globe, Server } from 'lucide-react';

interface ScanResultsSummaryProps {
  report: any;
}

export function ScanResultsSummary({ report }: ScanResultsSummaryProps) {
  if (!report) return null;

  const summary = report.summary || {};
  const openPorts = summary.open_ports || [];
  const vulnerabilities = report.windows_vulnerabilities || [];
  
  // Extract key information from scanner results
  const crackmapexecResult = report.results?.crackmapexec;
  const enum4linuxResult = report.results?.enum4linux;
  
  // Parse system information
  const getSystemInfo = () => {
    let hostname = 'Unknown';
    let os = 'Unknown';
    let workgroup = 'Unknown';
    
    // Try to get hostname from enum4linux
    if (enum4linuxResult?.stdout) {
      const hostnameMatch = enum4linuxResult.stdout.match(/DESKTOP-[A-Z0-9]+|[A-Z0-9]+-[A-Z0-9]+/);
      if (hostnameMatch) hostname = hostnameMatch[0];
      
      const workgroupMatch = enum4linuxResult.stdout.match(/Got domain\/workgroup name:\s*(\S+)/);
      if (workgroupMatch) workgroup = workgroupMatch[1];
    }
    
    // Try to get OS from crackmapexec
    if (crackmapexecResult?.stdout) {
      const osMatch = crackmapexecResult.stdout.match(/Windows [0-9.]+ Build \d+/);
      if (osMatch) os = osMatch[0];
    }
    
    return { hostname, os, workgroup };
  };
  
  const systemInfo = getSystemInfo();
  
  // Get security findings
  const getSecurityFindings = () => {
    const findings = [];
    
    // Check SMB signing from crackmapexec
    if (crackmapexecResult?.stdout?.includes('signing:False')) {
      findings.push({
        type: 'SMB Signing Disabled',
        severity: 'High',
        icon: AlertTriangle,
        color: 'text-red-600'
      });
    }
    
    // Check SMBv1
    if (crackmapexecResult?.stdout?.includes('SMBv1:True')) {
      findings.push({
        type: 'SMBv1 Enabled (EternalBlue)',
        severity: 'Critical',
        icon: XCircle,
        color: 'text-red-700'
      });
    } else if (crackmapexecResult?.stdout?.includes('SMBv1:False')) {
      findings.push({
        type: 'SMBv1 Disabled',
        severity: 'Good',
        icon: CheckCircle,
        color: 'text-green-600'
      });
    }
    
    return findings;
  };
  
  const securityFindings = getSecurityFindings();
  
  return (
    <div className="space-y-4">
      {/* System Information Card */}
      <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Server className="h-5 w-5 text-purple-400" />
            System Information
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <div className="text-sm text-purple-200/70">Target IP</div>
              <div className="font-mono font-semibold text-white">{report.target}</div>
            </div>
            <div>
              <div className="text-sm text-purple-200/70">Hostname</div>
              <div className="font-semibold text-white">{systemInfo.hostname}</div>
            </div>
            <div>
              <div className="text-sm text-purple-200/70">Operating System</div>
              <div className="font-semibold text-white">{systemInfo.os}</div>
            </div>
            <div>
              <div className="text-sm text-purple-200/70">Workgroup/Domain</div>
              <div className="font-semibold text-white">{systemInfo.workgroup}</div>
            </div>
            <div>
              <div className="text-sm text-purple-200/70">Scan Date</div>
              <div className="font-semibold text-white">{report.scan_date}</div>
            </div>
            <div>
              <div className="text-sm text-purple-200/70">Scan Profile</div>
              <Badge variant="outline" className="border-purple-500/30 text-purple-300">{report.profile || 'Unknown'}</Badge>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Security Summary Card */}
      <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Shield className="h-5 w-5 text-purple-400" />
            Security Summary
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 border border-purple-500/20 rounded-lg bg-slate-800/50">
              <div className="text-3xl font-bold text-blue-400">{summary.total_scanners || 0}</div>
              <div className="text-sm text-purple-200/70">Total Scanners</div>
            </div>
            <div className="text-center p-4 border border-purple-500/20 rounded-lg bg-slate-800/50">
              <div className="text-3xl font-bold text-green-400">{summary.successful_scans || 0}</div>
              <div className="text-sm text-purple-200/70">Successful</div>
            </div>
            <div className="text-center p-4 border border-purple-500/20 rounded-lg bg-slate-800/50">
              <div className="text-3xl font-bold text-yellow-400">{summary.vulnerabilities_found || 0}</div>
              <div className="text-sm text-purple-200/70">Vulnerabilities</div>
            </div>
            <div className="text-center p-4 border border-purple-500/20 rounded-lg bg-slate-800/50">
              <div className="text-3xl font-bold text-red-400">{summary.critical_issues || 0}</div>
              <div className="text-sm text-purple-200/70">Critical Issues</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Open Ports Card */}
      {openPorts.length > 0 && (
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Globe className="h-5 w-5 text-blue-400" />
              Open Ports ({openPorts.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {openPorts.map((port: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between p-3 border border-purple-500/20 rounded-lg bg-slate-800/50 hover:bg-purple-500/10 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="font-mono font-bold text-lg text-purple-300">{port.port}</div>
                    <div>
                      <div className="font-medium text-sm text-white">{port.service}</div>
                      {port.product && (
                        <div className="text-xs text-purple-200/70">{port.product}</div>
                      )}
                    </div>
                  </div>
                  <Badge variant={port.state === 'open' ? 'destructive' : 'secondary'} className={port.state === 'open' ? 'bg-red-500/20 text-red-300 border-red-500/30' : 'bg-slate-700/50 text-slate-300 border-slate-600/30'}>
                    {port.state}
                  </Badge>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Security Findings Card */}
      {securityFindings.length > 0 && (
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Lock className="h-5 w-5 text-indigo-400" />
              Security Findings
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {securityFindings.map((finding, idx) => {
                const Icon = finding.icon;
                return (
                  <div key={idx} className="flex items-center justify-between p-3 border border-purple-500/20 rounded-lg bg-slate-800/50 hover:bg-purple-500/10 transition-colors">
                    <div className="flex items-center gap-3">
                      <Icon className={`h-5 w-5 ${finding.color}`} />
                      <div>
                        <div className="font-medium text-white">{finding.type}</div>
                      </div>
                    </div>
                    <Badge variant={
                      finding.severity === 'Critical' ? 'destructive' :
                      finding.severity === 'High' ? 'destructive' :
                      finding.severity === 'Good' ? 'outline' :
                      'secondary'
                    } className={
                      finding.severity === 'Critical' || finding.severity === 'High' 
                        ? 'bg-red-500/20 text-red-300 border-red-500/30' 
                        : finding.severity === 'Good'
                          ? 'bg-green-500/20 text-green-300 border-green-500/30'
                          : 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30'
                    }>
                      {finding.severity}
                    </Badge>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Vulnerabilities Card */}
      {vulnerabilities.length > 0 && (
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <AlertTriangle className="h-5 w-5 text-yellow-400" />
              Detected Vulnerabilities ({vulnerabilities.length})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {vulnerabilities.map((vuln: any, idx: number) => (
                <div key={idx} className="p-4 border border-purple-500/20 rounded-lg bg-slate-800/50">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-semibold text-white">{vuln.type || vuln.cve}</div>
                    <Badge variant={
                      vuln.severity === 'Critical' || vuln.severity === 'High' ? 'destructive' :
                      vuln.severity === 'Medium' ? 'secondary' :
                      'outline'
                    } className={
                      vuln.severity === 'Critical' || vuln.severity === 'High' 
                        ? 'bg-red-500/20 text-red-300 border-red-500/30' 
                        : vuln.severity === 'Medium'
                          ? 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30'
                          : 'bg-slate-700/50 text-slate-300 border-slate-600/30'
                    }>
                      {vuln.severity}
                    </Badge>
                  </div>
                  <p className="text-sm text-purple-200/70 mb-2">{vuln.description}</p>
                  {vuln.recommendation && (
                    <div className="mt-2 p-2 bg-purple-500/10 border border-purple-500/20 rounded text-sm">
                      <span className="font-medium text-purple-300">Recommendation:</span> <span className="text-purple-200/70">{vuln.recommendation}</span>
                    </div>
                  )}
                  {vuln.cve && vuln.cvss && (
                    <div className="mt-2 flex gap-2">
                      <Badge variant="outline" className="border-purple-500/30 text-purple-300">{vuln.cve}</Badge>
                      <Badge variant="outline" className="border-purple-500/30 text-purple-300">CVSS: {vuln.cvss}</Badge>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Scanner Execution Summary */}
      <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-white">
            <Activity className="h-5 w-5 text-purple-400" />
            Scanner Execution Summary
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {Object.entries(report.results || {}).map(([scanner, result]: [string, any]) => {
              // Format scanner name for display
              const displayName = scanner
                .split('_')
                .map(word => word.charAt(0).toUpperCase() + word.slice(1))
                .join(' ');
              
              // Determine status icon and color
              const isSuccess = result.status === 'success';
              const isSkipped = result.message?.includes('Skipped') || result.status === 'skipped';
              const hasError = result.status === 'error' || result.status === 'timeout';
              
              return (
                <div key={scanner} className="flex items-center justify-between p-3 border border-purple-500/20 rounded-lg bg-slate-800/50 hover:bg-purple-500/10 transition-colors">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      {isSuccess ? (
                        <CheckCircle className="h-4 w-4 text-green-400" />
                      ) : isSkipped ? (
                        <AlertTriangle className="h-4 w-4 text-slate-400" />
                      ) : hasError ? (
                        <XCircle className="h-4 w-4 text-red-400" />
                      ) : (
                        <AlertTriangle className="h-4 w-4 text-yellow-400" />
                      )}
                      <span className="text-sm font-medium text-white">{displayName}</span>
                    </div>
                    <div className="text-xs text-purple-200/70">
                      {isSkipped ? 'Skipped' : 
                       result.duration ? `${result.duration.toFixed(1)}s` : 
                       result.status === 'timeout' ? 'Timeout' :
                       result.status === 'error' ? 'Error' :
                       'Completed'}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
