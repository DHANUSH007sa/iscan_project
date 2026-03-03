import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, CheckCircle, XCircle, AlertTriangle, Clock, Shield, Activity, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import Logo from '@/components/Logo';

interface ScanReport {
  target: string;
  scan_timestamp: number;
  scan_date: string;
  scanners_used: string[];
  summary: {
    total_scanners: number;
    successful_scans: number;
    failed_scans: number;
    vulnerabilities_found: number;
    critical_issues: number;
    open_ports: any[];
  };
  results: Record<string, any>;
  profile?: string;
  windows_vulnerabilities?: any[];
  open_ports?: any[];
}

const Reports = () => {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [latestReport, setLatestReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchLatestReport();
  }, []);

  async function fetchLatestReport() {
    setLoading(true);
    try {
      const res = await fetch('/api/reports/list');
      
      if (res.ok) {
        const data = await res.json();
        const rawReports: any[] = Array.isArray(data?.reports) ? data.reports : [];
        
        if (rawReports.length === 0) {
          setLatestReport(null);
          return;
        }

        const latest = rawReports[0];
        
        const normalizedReport: ScanReport = {
          target: latest.target || latest.ip_directory?.replace(/_/g, '.') || 'Unknown',
          scan_timestamp: latest.scan_timestamp || latest.timestamp || Date.now(),
          scan_date: latest.scan_date || latest.date || new Date().toLocaleString(),
          scanners_used: Array.isArray(latest.scanners_used) ? latest.scanners_used : Object.keys(latest.results || {}),
          summary: {
            total_scanners: latest.summary?.total_scanners || Object.keys(latest.results || {}).length,
            successful_scans: latest.summary?.successful_scans || 0,
            failed_scans: latest.summary?.failed_scans || 0,
            vulnerabilities_found: latest.summary?.vulnerabilities_found || 0,
            critical_issues: latest.summary?.critical_issues || 0,
            open_ports: Array.isArray(latest.summary?.open_ports) ? latest.summary.open_ports : []
          },
          results: latest.results || {},
          profile: latest.profile,
          windows_vulnerabilities: latest.windows_vulnerabilities || [],
          open_ports: latest.open_ports || latest.summary?.open_ports || []
        };

        setLatestReport(normalizedReport);
      } else {
        toast({ title: 'Error', description: 'Failed to load scan report', variant: 'destructive' });
      }
    } catch (error) {
      console.error('Failed to fetch report:', error);
      toast({ title: 'Error', description: 'Failed to load scan report', variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }

  const handleDownloadPDF = async () => {
    if (!latestReport) {
      toast({ title: 'No report available', description: 'No scan report to download', variant: 'destructive' });
      return;
    }

    try {
      const response = await fetch(`/api/report/download/${latestReport.target}`);
      
      if (!response.ok) {
        throw new Error('Failed to generate PDF report');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `security-report-${latestReport.target}-${new Date().toISOString().split('T')[0]}.pdf`;
      
      document.body.appendChild(link);
      link.click();
      
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      toast({ title: 'Report Downloaded', description: `PDF report for ${latestReport.target} has been downloaded` });
    } catch (error) {
      console.error('Error downloading report:', error);
      toast({ title: 'Download Failed', description: 'Failed to download PDF report. Please try again.', variant: 'destructive' });
    }
  };

  const calculateRiskScore = (report: ScanReport): number => {
    const summary = report.summary;
    const critical = summary.critical_issues || 0;
    const vulnerabilities = summary.vulnerabilities_found || 0;
    
    let riskScore = 0;
    riskScore += critical * 25;
    riskScore += vulnerabilities * 10;
    
    return Math.min(100, Math.round(riskScore));
  };

  const getRiskColor = (score: number) => {
    if (score >= 70) return 'text-red-600';
    if (score >= 40) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getRiskLevel = (score: number) => {
    if (score >= 70) return 'Critical Risk';
    if (score >= 40) return 'Medium Risk';
    return 'Low Risk';
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-indigo-950 via-purple-950 to-slate-950 relative overflow-hidden">
        <div className="absolute inset-0">
          <div className="absolute top-0 left-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
        </div>
        <header className="border-b border-purple-500/20 bg-slate-900/60 backdrop-blur-xl relative z-10">
          <div className="flex items-center px-6 py-4">
            <Button variant="ghost" size="sm" onClick={() => navigate('/dashboard')} className="text-purple-300 hover:text-white hover:bg-purple-500/10">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Dashboard
            </Button>
            <div className="ml-4">
              <Logo size="sm" showText={true} variant="light" />
            </div>
          </div>
        </header>
        <div className="flex items-center justify-center min-h-[400px] relative z-10">
          <div className="text-center">
            <Activity className="h-12 w-12 text-purple-400 mx-auto mb-4 animate-spin" />
            <p className="text-lg font-medium text-white">Loading scan report...</p>
          </div>
        </div>
      </div>
    );
  }

  if (!latestReport) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-indigo-950 via-purple-950 to-slate-950 relative overflow-hidden">
        <div className="absolute inset-0">
          <div className="absolute top-0 left-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
          <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
        </div>
        <header className="border-b border-purple-500/20 bg-slate-900/60 backdrop-blur-xl relative z-10">
          <div className="flex items-center px-6 py-4">
            <Button variant="ghost" size="sm" onClick={() => navigate('/dashboard')} className="text-purple-300 hover:text-white hover:bg-purple-500/10">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Dashboard
            </Button>
            <div className="ml-4">
              <Logo size="sm" showText={true} variant="light" />
            </div>
          </div>
        </header>
        <div className="flex items-center justify-center min-h-[400px] relative z-10">
          <div className="text-center">
            <Shield className="h-12 w-12 text-purple-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium mb-2 text-white">No scan reports available</h3>
            <p className="text-purple-200 mb-4">Run a vulnerability scan to generate your first report.</p>
            <Button onClick={() => navigate('/dashboard')} className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700">
              Go to Dashboard
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-950 via-purple-950 to-slate-950 relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl animate-pulse delay-500"></div>
      </div>

      {/* Header */}
      <header className="border-b border-purple-500/20 bg-slate-900/60 backdrop-blur-xl relative z-10">
        <div className="flex items-center justify-between px-6 py-4">
          <div className="flex items-center space-x-4">
            <Button variant="ghost" size="sm" onClick={() => navigate('/dashboard')} className="text-purple-300 hover:text-white hover:bg-purple-500/10">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Dashboard
            </Button>
            <Logo size="sm" showText={true} variant="light" />
          </div>
          <Button variant="default" size="sm" onClick={handleDownloadPDF} className="bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700">
            <Download className="h-4 w-4 mr-2" />
            Download PDF
          </Button>
        </div>
      </header>

      <div className="p-6 space-y-6 max-w-7xl mx-auto relative z-10">
        {/* Target Information */}
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="flex items-center justify-between text-white">
              <div className="flex items-center space-x-2">
                <Shield className="h-6 w-6 text-purple-400" />
                <span>Target: {latestReport.target}</span>
              </div>
              <Badge variant="outline" className="text-sm border-purple-500/30 text-purple-300">
                {latestReport.profile || 'Standard'} Scan
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-purple-500/20">
                <p className="text-sm text-purple-300">Scan Date</p>
                <p className="text-lg font-semibold text-white">{latestReport.scan_date}</p>
              </div>
              <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-purple-500/20">
                <p className="text-sm text-purple-300">Scanners Used</p>
                <p className="text-lg font-semibold text-white">{latestReport.summary.total_scanners}</p>
              </div>
              <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-purple-500/20">
                <p className="text-sm text-purple-300">Open Ports</p>
                <p className="text-lg font-semibold text-white">{latestReport.open_ports?.length || 0}</p>
              </div>
              <div className="text-center p-4 bg-slate-800/50 rounded-lg border border-purple-500/20">
                <p className="text-sm text-purple-300">Vulnerabilities</p>
                <p className="text-lg font-semibold text-orange-400">{latestReport.summary.vulnerabilities_found}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Summary Statistics */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-purple-300">Risk Score</p>
                  <p className={`text-2xl font-bold ${getRiskColor(calculateRiskScore(latestReport))}`}>
                    {calculateRiskScore(latestReport)}%
                  </p>
                  <p className="text-xs text-slate-400">{getRiskLevel(calculateRiskScore(latestReport))}</p>
                </div>
                <Shield className={`h-8 w-8 ${getRiskColor(calculateRiskScore(latestReport))}`} />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-purple-300">Total Scanners</p>
                  <p className="text-2xl font-bold text-white">{latestReport.summary.total_scanners}</p>
                </div>
                <Activity className="h-8 w-8 text-blue-400" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-purple-300">Successful</p>
                  <p className="text-2xl font-bold text-green-400">{latestReport.summary.successful_scans}</p>
                </div>
                <CheckCircle className="h-8 w-8 text-green-400" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-purple-300">Failed</p>
                  <p className="text-2xl font-bold text-red-400">{latestReport.summary.failed_scans}</p>
                </div>
                <XCircle className="h-8 w-8 text-red-400" />
              </div>
            </CardContent>
          </Card>
          
          <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
            <CardContent className="p-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-purple-300">Critical Issues</p>
                  <p className="text-2xl font-bold text-red-400">{latestReport.summary.critical_issues}</p>
                </div>
                <AlertTriangle className="h-8 w-8 text-red-400" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Vulnerabilities Section */}
        {latestReport.windows_vulnerabilities && latestReport.windows_vulnerabilities.length > 0 && (
          <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-white">
                <AlertTriangle className="h-5 w-5 text-yellow-400" />
                <span>Detected Vulnerabilities ({latestReport.windows_vulnerabilities.length})</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {latestReport.windows_vulnerabilities.map((vuln: any, idx: number) => (
                  <div key={idx} className="p-4 rounded-lg border border-purple-500/20 bg-slate-800/50">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2 mb-1">
                          <h4 className="font-bold text-lg text-white">{vuln.type || vuln.title || 'Security Issue'}</h4>
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
                            {vuln.severity || 'Medium'}
                          </Badge>
                        </div>
                        <p className="text-sm mt-2 font-medium text-purple-200/70">{vuln.description || 'No description available'}</p>
                        {vuln.recommendation && (
                          <div className="mt-3 p-3 bg-purple-500/10 border border-purple-500/20 rounded">
                            <p className="text-xs font-bold mb-1 text-purple-300">Recommendation:</p>
                            <p className="text-xs text-purple-200/70">{vuln.recommendation}</p>
                          </div>
                        )}
                      </div>
                    </div>
                    {vuln.port && (
                      <div className="mt-2 text-sm font-medium text-purple-200/70">
                        <span className="font-bold text-white">Affected Port:</span> {vuln.port}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Open Ports */}
        {latestReport.open_ports && latestReport.open_ports.length > 0 && (
          <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
            <CardHeader>
              <CardTitle className="text-white">Open Ports ({latestReport.open_ports.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {latestReport.open_ports.map((port: any, idx: number) => (
                  <div key={idx} className="p-4 border border-purple-500/20 rounded-lg bg-slate-800/50 hover:bg-purple-500/10 transition-colors">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-bold text-xl text-purple-300">Port {port.port}</span>
                      <Badge variant={port.state === 'open' ? 'destructive' : 'secondary'} className={port.state === 'open' ? 'bg-red-500/20 text-red-300 border-red-500/30' : 'bg-slate-700/50 text-slate-300 border-slate-600/30'}>
                        {port.state || 'unknown'}
                      </Badge>
                    </div>
                    <div className="space-y-1 text-sm">
                      <div className="flex justify-between">
                        <span className="text-purple-200/70">Service:</span>
                        <span className="font-medium text-white">{port.service || 'unknown'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-purple-200/70">Protocol:</span>
                        <span className="font-medium text-white">{port.protocol || 'tcp'}</span>
                      </div>
                      {port.product && (
                        <div className="flex justify-between">
                          <span className="text-purple-200/70">Product:</span>
                          <span className="font-medium text-xs text-white">{port.product}</span>
                        </div>
                      )}
                      {port.version && (
                        <div className="flex justify-between">
                          <span className="text-purple-200/70">Version:</span>
                          <span className="font-medium text-white">{port.version}</span>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Scanner Status Summary */}
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="text-white">Scanner Execution Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {Object.entries(latestReport.results).map(([scanner, result]: [string, any]) => (
                <div key={scanner} className="p-3 border border-purple-500/20 rounded-lg bg-slate-800/50 hover:bg-purple-500/10 transition-colors">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm font-medium capitalize text-white">{scanner.replace(/_/g, ' ')}</span>
                    {result.status === 'success' ? (
                      <CheckCircle className="h-4 w-4 text-green-400" />
                    ) : result.status === 'timeout' ? (
                      <Clock className="h-4 w-4 text-yellow-400" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-400" />
                    )}
                  </div>
                  <div className="text-xs text-purple-200/70">
                    {result.duration ? `${result.duration.toFixed(1)}s` : 'N/A'}
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Security Recommendations */}
        {latestReport.summary.vulnerabilities_found > 0 && (
          <Card className="bg-slate-900/60 backdrop-blur-xl border-yellow-500/30">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-white">
                <AlertTriangle className="h-5 w-5 text-yellow-400" />
                <span>Security Recommendations</span>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start space-x-2">
                  <span className="text-yellow-400 mt-1">•</span>
                  <span className="text-purple-200/70">Review and address all detected vulnerabilities based on their severity</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-yellow-400 mt-1">•</span>
                  <span className="text-purple-200/70">Ensure all services are running the latest security patches</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-yellow-400 mt-1">•</span>
                  <span className="text-purple-200/70">Consider implementing a firewall to restrict access to sensitive ports</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-yellow-400 mt-1">•</span>
                  <span className="text-purple-200/70">Disable unnecessary services to reduce attack surface</span>
                </li>
                <li className="flex items-start space-x-2">
                  <span className="text-yellow-400 mt-1">•</span>
                  <span className="text-purple-200/70">Schedule regular security scans to monitor for new vulnerabilities</span>
                </li>
              </ul>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default Reports;
