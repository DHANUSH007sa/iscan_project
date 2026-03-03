// ~/iscan_project/src/pages/Dashboard.tsx
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  MoreHorizontal,
  Plus,
  Shield,
  Activity,
  FileText,
  Wifi,
  AlertTriangle,
  CheckCircle,
  XCircle,
  RefreshCcw
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import Logo from "@/components/Logo";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useAuth } from "@/contexts/auth-context";
import { useToast } from "@/hooks/use-toast";
import { ScanResultsSummary } from "@/components/ScanResultsSummary";

// Wrapper component to fetch and display scan results
const ScanResultsSummaryWrapper = ({ deviceIp }: { deviceIp: string }) => {
  const [report, setReport] = React.useState<any>(null);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    async function fetchReport() {
      try {
        const res = await fetch('/api/reports/list');
        if (res.ok) {
          const data = await res.json();
          const reports = data.reports || [];
          const deviceReport = reports.find((r: any) => 
            r.target === deviceIp || r.ip_directory?.replace(/_/g, '.') === deviceIp
          );
          setReport(deviceReport);
        }
      } catch (error) {
        console.error('Failed to fetch report:', error);
      } finally {
        setLoading(false);
      }
    }
    fetchReport();
  }, [deviceIp]);

  if (loading) {
    return <div className="text-center py-8">Loading scan results...</div>;
  }

  if (!report) {
    return <div className="text-center py-8 text-muted-foreground">No scan results available for this device.</div>;
  }

  return <ScanResultsSummary report={report} />;
};

interface ScannedDevice {
  id: string;       // we'll use ip as id
  name: string;     // hostname or ip
  ip: string;
  os?: string;      // Operating System: Android, Windows, Linux, etc.
  mac?: string;     // MAC address
  riskScore?: number;
  lastScan?: string;
  vulnerabilities?: number;
  status?: "secure" | "warning" | "critical";
}

const Dashboard: React.FC = () => {
  const navigate = useNavigate();
  const { logout, user } = useAuth();
  const { toast } = useToast();

  // State
  const [devices, setDevices] = useState<ScannedDevice[]>(() => {
    // Restore devices from localStorage if available
    const savedDevices = localStorage.getItem('discoveredDevices');
    return savedDevices ? JSON.parse(savedDevices) : [];
  });
  const [selectedSystem, setSelectedSystem] = useState<string | null>(() => {
    // Restore selected system from localStorage if available
    return localStorage.getItem('selectedSystem');
  });
  const [availableScanners, setAvailableScanners] = useState<any[]>([]);
  const [selectedScanners, setSelectedScanners] = useState<string[]>([
    "nmap",
    "nmap_vuln",
    "nikto"
  ]);
  const [scanProfile, setScanProfile] = useState("medium");
  const [loadingDiscover, setLoadingDiscover] = useState(false);
  const [startingScan, setStartingScan] = useState(false);
  const [showScannerDialog, setShowScannerDialog] = useState(false);
  const [showAddDeviceDialog, setShowAddDeviceDialog] = useState(false);
  const [newDeviceIp, setNewDeviceIp] = useState("");
  const [selectedDevice, setSelectedDevice] = useState<ScannedDevice | null>(null);
  const [showDeviceDetails, setShowDeviceDetails] = useState(false);
  
  // New state for network range and tabs
  const [networkRange, setNetworkRange] = useState("10.151.244.0/24");
  const [activeTab, setActiveTab] = useState("local");
  const [knownDevices, setKnownDevices] = useState<ScannedDevice[]>([]);

  // Scan progress tracking
  const [isScanning, setIsScanning] = useState(false);
  const [scanJobId, setScanJobId] = useState<string | null>(null);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentScanner, setCurrentScanner] = useState<string | null>(null);
  const [scanStartTime, setScanStartTime] = useState<number | null>(null);
  const [scanTimer, setScanTimer] = useState(0);

  // Wrapper function for onClick handler
  const handleRefreshDevices = () => {
    fetchDevices(false); // Don't use cache for manual refresh
  };

  // Handle PDF report download
  const handleDownloadReport = async () => {
    if (!selectedSystem) {
      toast({ title: "No target selected", description: "Please select a system to download its report", variant: "destructive" });
      return;
    }

    try {
      const response = await fetch(`/api/report/download/${selectedSystem}`);
      
      if (!response.ok) {
        throw new Error('Failed to generate PDF report');
      }

      // Create blob from response
      const blob = await response.blob();
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `security-report-${selectedSystem}-${new Date().toISOString().split('T')[0]}.pdf`;
      
      // Trigger download
      document.body.appendChild(link);
      link.click();
      
      // Cleanup
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      toast({ title: "Report Downloaded", description: `PDF report for ${selectedSystem} has been downloaded` });
    } catch (error) {
      console.error('Error downloading report:', error);
      toast({ title: "Download Failed", description: "Failed to download PDF report. Please try again.", variant: "destructive" });
    }
  };

  // Save selectedSystem to localStorage whenever it changes
  useEffect(() => {
    if (selectedSystem) {
      localStorage.setItem('selectedSystem', selectedSystem);
    }
  }, [selectedSystem]);

  useEffect(() => {
    fetchDevices(true); // Use cache if available
    fetchAvailableScanners();
    loadKnownDevices();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleLogout = () => {
    logout();
    navigate("/");
    toast({ title: "Logged out", description: "You have been successfully logged out" });
  };

  const getRiskColor = (score?: number) => {
    const s = score ?? 0;
    if (s >= 70) return "text-destructive";
    if (s >= 40) return "text-warning";
    return "text-success";
  };

  const getStatusIcon = (status?: string) => {
    switch (status) {
      case "secure":
        return <CheckCircle className="h-4 w-4 text-success" />;
      case "warning":
        return <AlertTriangle className="h-4 w-4 text-warning" />;
      case "critical":
        return <XCircle className="h-4 w-4 text-destructive" />;
      default:
        return <Shield className="h-4 w-4" />;
    }
  };

  async function fetchAvailableScanners() {
    try {
      const res = await fetch("/api/scanners");
      if (res.ok) {
        const data = await res.json();
        setAvailableScanners(data.scanners || []);
      }
    } catch (err) {
      console.error("Failed to fetch scanners", err);
    }
  }

  async function fetchDevices(useCache: boolean = false) {
    // If useCache is true, try to restore from localStorage first
    if (useCache) {
      const savedDevices = localStorage.getItem('discoveredDevices');
      if (savedDevices) {
        try {
          const parsedDevices = JSON.parse(savedDevices);
          if (Array.isArray(parsedDevices) && parsedDevices.length > 0) {
            setDevices(parsedDevices);
            
            // Restore selected system if not already set
            if (!selectedSystem) {
              const savedSelectedSystem = localStorage.getItem('selectedSystem');
              if (savedSelectedSystem) {
                setSelectedSystem(savedSelectedSystem);
              } else if (parsedDevices.length > 0) {
                // If no selected system, select the first one
                setSelectedSystem(parsedDevices[0].id);
              }
            }
            return;
          }
        } catch (e) {
          console.error("Failed to parse saved devices from localStorage", e);
        }
      }
    }
    
    setLoadingDiscover(true);
    try {
      // Use the network range from state (user can customize it)
      const res = await fetch(`/api/discover?net=${networkRange}`);
      if (!res.ok) {
        const txt = await res.text();
        throw new Error(`discover failed: ${res.status} ${txt}`);
      }
      const body = await res.json();
      const backendDevices: any[] = Array.isArray(body?.devices) ? body.devices : [];

      // Normalize backend devices to ScannedDevice
      const normalized: ScannedDevice[] = backendDevices.map((d: any, idx: number) => {
        const ip = d.ip ?? d.address ?? d.host ?? `unknown-${idx}`;
        const name = d.name ?? d.hostname ?? ip;
        const os = d.os ?? "Unknown";
        const mac = d.mac ?? "N/A";
        return {
          id: ip,
          ip,
          name,
          os,
          mac,
          riskScore: d.riskScore ?? Math.floor(Math.random() * 60),
          lastScan: d.lastScan ?? "",
          vulnerabilities: d.vulnerabilities ?? 0,
          status: d.status ?? (d.vulnerabilities && d.vulnerabilities > 2 ? "critical" : d.vulnerabilities && d.vulnerabilities > 0 ? "warning" : "secure")
        } as ScannedDevice;
      });

      setDevices(normalized);
      // Save to localStorage
      localStorage.setItem('discoveredDevices', JSON.stringify(normalized));
      
      // If no device is currently selected, select the first one
      if (!selectedSystem && normalized.length > 0) {
        setSelectedSystem(normalized[0].id);
      }
      toast({ title: "Discovery", description: `Found ${normalized.length} device(s)` });
    } catch (err: any) {
      console.error("discover error", err);
      toast({ title: "Discover failed", description: err?.message ?? String(err) });
    } finally {
      setLoadingDiscover(false);
    }
  }

  async function loadKnownDevices() {
    try {
      const res = await fetch("/api/reports/list");
      if (res.ok) {
        const data = await res.json();
        const reports = data.reports || [];
        
        // Convert reports to known devices
        const known: ScannedDevice[] = reports.map((report: any) => ({
          id: report.target || report.ip_directory?.replace(/_/g, '.'),
          ip: report.target || report.ip_directory?.replace(/_/g, '.'),
          name: report.target || report.ip_directory?.replace(/_/g, '.'),
          os: "Unknown",
          riskScore: report.summary?.critical_issues > 0 ? 85 : report.summary?.vulnerabilities_found > 0 ? 45 : 20,
          lastScan: report.scan_date || new Date(report.scan_timestamp * 1000).toLocaleDateString(),
          vulnerabilities: report.summary?.vulnerabilities_found || 0,
          status: report.summary?.critical_issues > 0 ? "critical" : report.summary?.vulnerabilities_found > 0 ? "warning" : "secure"
        }));
        
        setKnownDevices(known);
      }
    } catch (err) {
      console.error("Failed to load known devices", err);
    }
  }

  async function quickScanDevice(ip: string) {
    setLoadingDiscover(true);
    try {
      const res = await fetch(`/api/discover?net=${ip}`);
      if (!res.ok) {
        throw new Error("Quick scan failed");
      }
      const body = await res.json();
      const backendDevices: any[] = Array.isArray(body?.devices) ? body.devices : [];
      
      if (backendDevices.length > 0) {
        const device = backendDevices[0];
        const normalized: ScannedDevice = {
          id: device.ip,
          ip: device.ip,
          name: device.name || device.ip,
          os: device.os || "Unknown",
          riskScore: Math.floor(Math.random() * 60),
          lastScan: "",
          vulnerabilities: 0,
          status: "secure"
        };
        
        setDevices([normalized]);
        setSelectedSystem(normalized.id);
        toast({ title: "Quick Scan", description: `Found device: ${normalized.ip}` });
      } else {
        // If discovery fails, allow manual addition
        addManualDevice(ip);
      }
    } catch (err: any) {
      // If discovery fails, allow manual addition
      addManualDevice(ip);
    } finally {
      setLoadingDiscover(false);
    }
  }

  function addManualDevice(ip: string) {
    const manualDevice: ScannedDevice = {
      id: ip,
      ip: ip,
      name: `Device-${ip}`,
      os: "Unknown",
      riskScore: 0,
      lastScan: "",
      vulnerabilities: 0,
      status: "secure"
    };
    
    setDevices([manualDevice]);
    setSelectedSystem(manualDevice.id);
    toast({ 
      title: "Device Added", 
      description: `Manually added ${ip} - you can now scan it`,
      variant: "default"
    });
  }

  function openScanDialog() {
    if (!selectedSystem) {
      toast({ title: "Select a system", description: "Choose a target first" });
      return;
    }
    
    // Start scan immediately based on selected profile
    startScan();
  }

  // Get recommended scanners based on OS type
  function getRecommendedScanners(os: string): string[] {
    const baseScanners = ["nmap", "nmap_vuln"];
    
    switch (os.toLowerCase()) {
      case "android":
        return [...baseScanners, "android"];
      case "windows":
        return [...baseScanners, "windows", "nikto"];
      case "linux":
        return [...baseScanners, "linux", "lynis", "nikto"];
      case "macos":
      case "ios":
        return [...baseScanners, "nikto"];
      default:
        // Unknown OS - use general scanners
        return [...baseScanners, "nikto"];
    }
  }
  
  // Poll for scan status updates
  const pollScanStatus = async (jobId: string, timer: NodeJS.Timeout) => {
    try {
      const res = await fetch(`/api/scan/jobs/${jobId}`);
      const job = await res.json();
      
      if (job.status === "completed") {
        setIsScanning(false);
        clearInterval(timer);
        setScanProgress(100);
        setCurrentScanner(null);
        
        toast({ 
          title: "Scan completed", 
          description: `Scan finished for ${job.target_ip}` 
        });
        
        // Refresh device list to show updated scan data
        fetchDevices(false); // Don't use cache after scan completion
        return;
      }
      
      if (job.status === "failed" || job.status === "error") {
        setIsScanning(false);
        clearInterval(timer);
        
        toast({ 
          title: "Scan failed", 
          description: job.error || "Scan encountered an error",
          variant: "destructive"
        });
        return;
      }
      
      // Update progress
      setScanProgress(job.progress || 0);
      setCurrentScanner(job.current_scanner || null);
      
      // Continue polling
      setTimeout(() => pollScanStatus(jobId, timer), 2000);
    } catch (err) {
      console.error("Error polling scan status:", err);
      clearInterval(timer);
      setIsScanning(false);
    }
  };

  async function startScan() {
    if (!selectedSystem) {
      toast({ title: "Select a system", description: "Choose a target first" });
      return;
    }
    
    setStartingScan(true);
    try {
      // Get scanner count based on profile
      const scannerCount = scanProfile === "small" ? 2 : scanProfile === "medium" ? 5 : 11;
      const profileName = scanProfile.charAt(0).toUpperCase() + scanProfile.slice(1);
      
      const res = await fetch("/api/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          ip: selectedSystem,
          profile: scanProfile
        })
      });
      
      const body = await res.json();
      if (!res.ok) throw new Error(body?.error ?? "scan error");
      
      // Start scan tracking
      const jobId = body.job_id;
      if (jobId) {
        setIsScanning(true);
        setScanJobId(jobId);
        setScanProgress(0);
        setCurrentScanner(null);
        setScanStartTime(Date.now());
        setScanTimer(0);
        
        // Start timer
        const timer = setInterval(() => {
          setScanTimer(prev => prev + 1);
        }, 1000);
        
        // Start polling for job status
        pollScanStatus(jobId, timer);
      }
      
      toast({ 
        title: "Scan started", 
        description: `${profileName} scan with ${scannerCount} tools on ${selectedSystem}` 
      });
    } catch (err: any) {
      console.error("Scan start error:", err);
      toast({ title: "Scan failed", description: err?.message ?? String(err), variant: "destructive" });
    } finally {
      setStartingScan(false);
    }
  }

  const toggleScanner = (scannerId: string) => {
    setSelectedScanners(prev => 
      prev.includes(scannerId) 
        ? prev.filter(s => s !== scannerId)
        : [...prev, scannerId]
    );
  };

  // Derived data
  const selectedDeviceData = devices.find((d) => d.id === selectedSystem) ?? null;
  const currentRiskScore = selectedDeviceData?.riskScore ?? 0;

  return (
    <div className="min-h-screen bg-gradient-to-br from-indigo-950 via-purple-950 to-slate-950 relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl animate-pulse delay-500"></div>
      </div>

      <header className="border-b border-purple-500/20 bg-slate-900/60 backdrop-blur-xl relative z-10">
        <div className="flex items-center justify-between px-6 py-4">
          <div className="flex items-center space-x-4">
            <Button variant="ghost" size="sm" onClick={() => navigate("/")} className="text-purple-300 hover:text-white hover:bg-purple-500/10">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back
            </Button>
            <Logo size="sm" showText={true} variant="light" />
          </div>

          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="sm" className="text-purple-300 hover:text-white hover:bg-purple-500/10">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="bg-slate-900 border-purple-500/30">
              <DropdownMenuItem onClick={() => navigate("/about")} className="text-slate-200 hover:bg-purple-500/10 focus:bg-purple-500/10">About</DropdownMenuItem>
              <DropdownMenuItem onClick={() => navigate("/settings")} className="text-slate-200 hover:bg-purple-500/10 focus:bg-purple-500/10">Settings</DropdownMenuItem>
              <DropdownMenuItem onClick={handleLogout} className="text-slate-200 hover:bg-purple-500/10 focus:bg-purple-500/10">Logout</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      <div className="p-6 space-y-6 relative z-10">
        <div className="flex items-center justify-between">
          <h2 className="text-3xl font-bold text-white">Welcome back, {user?.firstName}</h2>
          <div className="text-sm text-purple-300">Vulnerability Scanner - Raspberry Pi 5</div>
        </div>

        {/* System Selector */}
        <div className="grid grid-cols-1 gap-6">
          <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
            <CardHeader>
              <CardTitle className="flex items-center space-x-2 text-white">
                <Wifi className="h-5 w-5 text-purple-400" />
                <span>System Selection</span>
              </CardTitle>
              <CardDescription className="text-purple-200">Select a system to scan for vulnerabilities</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Tabs value={activeTab} onValueChange={setActiveTab}>
                <TabsList className="grid w-full grid-cols-3 bg-slate-800/50 border border-purple-500/20">
                  <TabsTrigger value="local" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-purple-600 data-[state=active]:to-blue-600 data-[state=active]:text-white">Local Network</TabsTrigger>
                  <TabsTrigger value="quick" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-purple-600 data-[state=active]:to-blue-600 data-[state=active]:text-white">Quick Scan</TabsTrigger>
                  <TabsTrigger value="known" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-purple-600 data-[state=active]:to-blue-600 data-[state=active]:text-white">Known Devices</TabsTrigger>
                </TabsList>

                {/* Local Network Tab */}
                <TabsContent value="local" className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="network-range" className="text-slate-200 font-medium">Network Range</Label>
                    <div className="flex space-x-2">
                      <Input
                        id="network-range"
                        type="text"
                        placeholder="10.151.244.0/24"
                        value={networkRange}
                        onChange={(e) => setNetworkRange(e.target.value)}
                        className="flex-1 bg-slate-800/50 border-slate-600/50 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20"
                      />
                      <Button 
                        size="icon" 
                        variant="outline" 
                        onClick={handleRefreshDevices}
                        disabled={loadingDiscover}
                        title="Discover devices"
                        className="border-purple-500/30 hover:bg-purple-500/10 text-purple-300"
                      >
                        <RefreshCcw className={`h-4 w-4 ${loadingDiscover ? 'animate-spin' : ''}`} />
                      </Button>
                    </div>
                    <p className="text-xs text-purple-300/70">
                      Enter CIDR notation (e.g., 192.168.1.0/24), single IP, or comma-separated IPs
                    </p>
                  </div>

                  <div className="flex space-x-2">
                    <Select value={selectedSystem || ""} onValueChange={(v) => setSelectedSystem(v)}>
                      <SelectTrigger className="flex-1">
                        <SelectValue placeholder={devices.length ? "Select system to scan..." : "No devices found"} />
                      </SelectTrigger>
                      <SelectContent>
                        {devices.map((device) => (
                          <SelectItem key={device.id} value={device.id}>
                            {device.ip} - {device.name} {device.os && device.os !== "Unknown" ? `(${device.os})` : ""} {device.mac && device.mac !== "N/A" ? `[${device.mac}]` : ""}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  {selectedDeviceData && (
                    <div className="p-4 border rounded-lg bg-muted/50">
                      <div className="flex items-center justify-between">
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <h4 className="font-medium">{selectedDeviceData.name}</h4>
                            {selectedDeviceData.os && selectedDeviceData.os !== "Unknown" && (
                              <Badge variant="secondary">{selectedDeviceData.os}</Badge>
                            )}
                          </div>
                          <p className="text-sm text-muted-foreground">IP: {selectedDeviceData.ip}</p>
                          {selectedDeviceData.mac && selectedDeviceData.mac !== "N/A" && (
                            <p className="text-sm text-muted-foreground">MAC: {selectedDeviceData.mac}</p>
                          )}
                        </div>
                        <Badge variant={selectedDeviceData.status === "critical" ? "destructive" : selectedDeviceData.status === "warning" ? "secondary" : "outline"}>
                          {selectedDeviceData.status}
                        </Badge>
                      </div>
                    </div>
                  )}
                </TabsContent>

                {/* Quick Scan Tab */}
                <TabsContent value="quick" className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="quick-ip">IP Address</Label>
                    <div className="flex space-x-2">
                      <Input
                        id="quick-ip"
                        type="text"
                        placeholder="192.168.1.100"
                        value={newDeviceIp}
                        onChange={(e) => setNewDeviceIp(e.target.value)}
                        className="flex-1"
                      />
                      <Button 
                        onClick={() => {
                          if (newDeviceIp) {
                            quickScanDevice(newDeviceIp);
                          }
                        }}
                        disabled={loadingDiscover || !newDeviceIp}
                      >
                        Scan
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Enter a single IP address for quick discovery
                    </p>
                  </div>

                  {devices.length > 0 && (
                    <div className="space-y-2">
                      <Select value={selectedSystem || ""} onValueChange={(v) => setSelectedSystem(v)}>
                        <SelectTrigger className="flex-1">
                          <SelectValue placeholder="Select discovered device..." />
                        </SelectTrigger>
                        <SelectContent>
                          {devices.map((device) => (
                            <SelectItem key={device.id} value={device.id}>
                              {device.name} ({device.ip}) {device.os && device.os !== "Unknown" ? `- ${device.os}` : ""}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  )}
                </TabsContent>

                {/* Known Devices Tab */}
                <TabsContent value="known" className="space-y-4">
                  <div className="space-y-2">
                    <Label>Previously Scanned Devices</Label>
                    {knownDevices.length > 0 ? (
                      <Select value={selectedSystem || ""} onValueChange={(v) => setSelectedSystem(v)}>
                        <SelectTrigger className="flex-1">
                          <SelectValue placeholder="Select from known devices..." />
                        </SelectTrigger>
                        <SelectContent>
                          {knownDevices.map((device) => (
                            <SelectItem key={device.id} value={device.id}>
                              {device.ip} - Last scan: {device.lastScan} ({device.vulnerabilities} issues)
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    ) : (
                      <p className="text-sm text-muted-foreground p-4 border rounded-lg text-center">
                        No previously scanned devices found. Run a scan to populate this list.
                      </p>
                    )}
                  </div>

                  {selectedDeviceData && (
                    <div className="p-4 border rounded-lg bg-muted/50">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="flex items-center gap-2">
                            <h4 className="font-medium">{selectedDeviceData.name}</h4>
                            {selectedDeviceData.os && selectedDeviceData.os !== "Unknown" && (
                              <Badge variant="secondary">{selectedDeviceData.os}</Badge>
                            )}
                          </div>
                          <p className="text-sm text-muted-foreground">{selectedDeviceData.ip}</p>
                          <p className="text-xs text-muted-foreground">Last scan: {selectedDeviceData.lastScan || "Never"}</p>
                        </div>
                        <Badge variant={selectedDeviceData.status === "critical" ? "destructive" : selectedDeviceData.status === "warning" ? "secondary" : "outline"}>
                          {selectedDeviceData.status}
                        </Badge>
                      </div>
                    </div>
                  )}
                </TabsContent>
              </Tabs>

              {/* Scan Profile - Choose Scan Type */}
              <div className="space-y-3 pt-4 border-t border-purple-500/20">
                <Label className="text-base font-semibold text-white">Choose Scan Type</Label>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {/* Small Scan */}
                  <div
                    className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                      scanProfile === "small"
                        ? "border-purple-500 bg-purple-500/20 shadow-lg shadow-purple-500/20"
                        : "border-slate-600/50 hover:border-purple-500/50 bg-slate-800/30"
                    }`}
                    onClick={() => setScanProfile("small")}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-semibold text-white">Small Scan</h4>
                      <Badge variant={scanProfile === "small" ? "default" : "outline"} className={scanProfile === "small" ? "bg-purple-600" : "border-purple-500/30 text-purple-300"}>Fast</Badge>
                    </div>
                    <p className="text-sm text-purple-200/70 mb-2">Quick network discovery</p>
                    <div className="text-xs space-y-1 text-slate-300">
                      <p>• Basic security check</p>
                      <p>• 4 security tools</p>
                      <p>• Time: ~1 minute</p>
                    </div>
                  </div>

                  {/* Medium Scan */}
                  <div
                    className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                      scanProfile === "medium"
                        ? "border-purple-500 bg-purple-500/20 shadow-lg shadow-purple-500/20"
                        : "border-slate-600/50 hover:border-purple-500/50 bg-slate-800/30"
                    }`}
                    onClick={() => setScanProfile("medium")}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-semibold text-white">Medium Scan</h4>
                      <Badge variant={scanProfile === "medium" ? "default" : "outline"} className={scanProfile === "medium" ? "bg-purple-600" : "border-purple-500/30 text-purple-300"}>Balanced</Badge>
                    </div>
                    <p className="text-sm text-purple-200/70 mb-2">Comprehensive security assessment</p>
                    <div className="text-xs space-y-1 text-slate-300">
                      <p>• Vulnerability detection</p>
                      <p>• 7 security tools</p>
                      <p>• Time: ~3 minutes</p>
                    </div>
                  </div>

                  {/* Deep Scan */}
                  <div
                    className={`p-4 border-2 rounded-lg cursor-pointer transition-all ${
                      scanProfile === "deep"
                        ? "border-purple-500 bg-purple-500/20 shadow-lg shadow-purple-500/20"
                        : "border-slate-600/50 hover:border-purple-500/50 bg-slate-800/30"
                    }`}
                    onClick={() => setScanProfile("deep")}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-semibold text-white">Deep Scan</h4>
                      <Badge variant={scanProfile === "deep" ? "default" : "outline"} className={scanProfile === "deep" ? "bg-purple-600" : "border-purple-500/30 text-purple-300"}>Thorough</Badge>
                    </div>
                    <p className="text-sm text-purple-200/70 mb-2">Complete security audit</p>
                    <div className="text-xs space-y-1 text-slate-300">
                      <p>• Full vulnerability scan</p>
                      <p>• 11 security tools</p>
                      <p>• Time: ~6 minutes</p>
                    </div>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Scan Progress Bar */}
          {isScanning && (
            <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="font-medium flex items-center text-white">
                    <Activity className="h-4 w-4 mr-2 animate-pulse text-purple-400" />
                    Scanning in Progress
                  </h3>
                  <div className="text-sm">
                    <span className="font-mono text-purple-300">
                      {Math.floor(scanTimer / 60)}:{String(scanTimer % 60).padStart(2, '0')}
                    </span>
                  </div>
                </div>
                
                <div className="mb-3">
                  <div className="flex justify-between text-sm mb-2 text-slate-200">
                    <span>Progress: {scanProgress}%</span>
                    <span>{currentScanner ? `Running: ${currentScanner}` : 'Initializing...'}</span>
                  </div>
                  <div className="w-full bg-slate-700/50 rounded-full h-2">
                    <div 
                      className="h-2 rounded-full bg-gradient-to-r from-purple-600 to-blue-600 transition-all duration-300 ease-out"
                      style={{ width: `${scanProgress}%` }}
                    />
                  </div>
                </div>
                
                <p className="text-sm text-purple-200/70">
                  Please wait while the vulnerability scan completes. Do not close this page.
                </p>
              </CardContent>
            </Card>
          )}

        </div>

        {/* Action Buttons */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Button 
            className="h-16 text-left justify-start bg-slate-900/60 backdrop-blur-xl border-purple-500/20 hover:bg-purple-500/10 hover:border-purple-500/40" 
            variant="outline" 
            onClick={openScanDialog} 
            disabled={!selectedSystem || isScanning}
          >
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-purple-500/20 rounded-lg">
                <Shield className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <div className="font-medium text-white">
                  {isScanning ? "Scanning..." : `Start ${scanProfile.charAt(0).toUpperCase() + scanProfile.slice(1)} Scan`}
                </div>
                <div className="text-sm text-purple-200/70">
                  {isScanning 
                    ? `${scanProgress}% complete` 
                    : scanProfile === "small" 
                      ? "2 tools • 2-5 min" 
                      : scanProfile === "medium" 
                        ? "5 tools • 5-10 min" 
                        : "11 tools • 15-30 min"
                  }
                </div>
              </div>
            </div>
          </Button>

          <Button className="h-16 text-left justify-start bg-slate-900/60 backdrop-blur-xl border-purple-500/20 hover:bg-purple-500/10 hover:border-purple-500/40" variant="outline" onClick={() => navigate("/reports")}>
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-500/20 rounded-lg">
                <Activity className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <div className="font-medium text-white">View Reports</div>
                <div className="text-sm text-purple-200/70">Access scan history</div>
              </div>
            </div>
          </Button>

          <Button className="h-16 text-left justify-start bg-slate-900/60 backdrop-blur-xl border-purple-500/20 hover:bg-purple-500/10 hover:border-purple-500/40" variant="outline" onClick={handleDownloadReport}>
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-indigo-500/20 rounded-lg">
                <FileText className="h-5 w-5 text-indigo-400" />
              </div>
              <div>
                <div className="font-medium text-white">Download Report</div>
                <div className="text-sm text-purple-200/70">Download PDF report</div>
              </div>
            </div>
          </Button>
        </div>

        {/* Recently Scanned Devices (cards) */}
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="text-white">Recently Scanned Devices</CardTitle>
            <CardDescription className="text-purple-200">Click on a device to view detailed scan results</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {devices.map((device) => (
                <Card key={device.id} className="cursor-pointer bg-slate-800/50 border-purple-500/20 hover:bg-purple-500/10 hover:border-purple-500/40 transition-colors" onClick={() => { setSelectedDevice(device); setShowDeviceDetails(true); }}>
                  <CardContent className="p-4">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <h4 className="font-medium text-sm text-white">{device.name}</h4>
                        {device.os && device.os !== "Unknown" && (
                          <Badge variant="outline" className="text-xs border-purple-500/30 text-purple-300">{device.os}</Badge>
                        )}
                      </div>
                      {getStatusIcon(device.status)}
                    </div>
                    <p className="text-xs text-purple-200/70 mb-1">{device.ip}</p>
                    <p className="text-xs text-purple-200/70 mb-2">Last scan: {device.lastScan ?? "—"}</p>
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-purple-200/70">Last Scan</span>
                      <span className="text-xs text-purple-200/70">{device.vulnerabilities ?? 0} issues</span>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Device Details Dialog - Now shows consolidated summary */}
      <Dialog open={showDeviceDetails} onOpenChange={setShowDeviceDetails}>
        <DialogContent className="max-w-6xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center space-x-2">
              {selectedDevice && getStatusIcon(selectedDevice.status)}
              <span>{selectedDevice?.name} - Scan Results</span>
            </DialogTitle>
            <DialogDescription>Comprehensive security assessment for {selectedDevice?.ip}</DialogDescription>
          </DialogHeader>

          {selectedDevice && (
            <ScanResultsSummaryWrapper deviceIp={selectedDevice.ip} />
          )}

          <div className="flex justify-end space-x-2 mt-4">
            <Button variant="outline" onClick={() => setShowDeviceDetails(false)}>Close</Button>
            <Button onClick={handleDownloadReport}>Download PDF Report</Button>
          </div>
        </DialogContent>
      </Dialog>

      {/* Scanner Selection Dialog */}
      <Dialog open={showScannerDialog} onOpenChange={setShowScannerDialog}>
        <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Start Vulnerability Scan</DialogTitle>
            <DialogDescription>
              Starting {scanProfile} scan for {selectedSystem}
              {selectedDeviceData?.os && selectedDeviceData.os !== "Unknown" && (
                <span className="block mt-1">Detected OS: <strong>{selectedDeviceData.os}</strong></span>
              )}
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-6 py-4">
            {/* Scan Summary */}
            <div className="p-4 border rounded-lg bg-muted/50">
              <h4 className="font-medium mb-2">Scan Configuration</h4>
              <div className="space-y-1 text-sm">
                <p><strong>Target:</strong> {selectedSystem}</p>
                <p><strong>Profile:</strong> {scanProfile.charAt(0).toUpperCase() + scanProfile.slice(1)}</p>
                <p><strong>Scanners:</strong> {
                  scanProfile === "small" ? "2 scanners (nmap, nikto)" :
                  scanProfile === "medium" ? "5 scanners (nmap, nikto, nmap_vuln, wappalyzer, sslyze)" :
                  "11 scanners (all available tools)"
                }</p>
                <p><strong>Estimated Time:</strong> {
                  scanProfile === "small" ? "2-5 minutes" :
                  scanProfile === "medium" ? "5-10 minutes" :
                  "15-30 minutes"
                }</p>
              </div>
            </div>

            {/* Optional: Advanced Scanner Selection */}
            <div className="space-y-3">
              <Label className="text-base font-semibold">Advanced: Custom Scanner Selection (Optional)</Label>
              <p className="text-sm text-muted-foreground">
                By default, scanners are auto-selected based on your profile. You can customize the selection below.
              </p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-60 overflow-y-auto">
                {availableScanners.map((scanner) => (
                  <div
                    key={scanner.id}
                    className="flex items-start space-x-3 p-3 border rounded-lg hover:bg-muted/50 cursor-pointer"
                    onClick={() => toggleScanner(scanner.id)}
                  >
                    <Checkbox
                      checked={selectedScanners.includes(scanner.id)}
                      onCheckedChange={() => toggleScanner(scanner.id)}
                    />
                    <div className="flex-1">
                      <div className="font-medium text-sm">{scanner.name}</div>
                      <div className="text-xs text-muted-foreground">
                        Timeout: {Math.floor(scanner.timeout / 60)}min
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowScannerDialog(false)}>
              Cancel
            </Button>
            <Button 
              onClick={startScan} 
              disabled={startingScan}
            >
              {startingScan ? "Starting..." : "Start Scan"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
};

export default Dashboard;

// UI_RESTORE_MARKER_1763522277
