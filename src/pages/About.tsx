import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Shield, Cpu, Network, Mail } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';

const About = () => {
  const navigate = useNavigate();

  const features = [
    {
      icon: <Shield className="h-6 w-6" />,
      title: "Agentless Scanning",
      description: "Non-intrusive vulnerability detection without installing agents on target systems"
    },
    {
      icon: <Cpu className="h-6 w-6" />,
      title: "Raspberry Pi 5 Powered",
      description: "Efficient scanning powered by ARM64 architecture for optimal performance"
    },
    {
      icon: <Network className="h-6 w-6" />,
      title: "Network Discovery",
      description: "Automatic detection and mapping of Windows systems on your network"
    },
    {
      icon: <Mail className="h-6 w-6" />,
      title: "Comprehensive Reports",
      description: "Detailed analysis with actionable insights and PDF export capabilities"
    }
  ];

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
        <div className="flex items-center px-6 py-4">
          <Button variant="ghost" size="sm" onClick={() => navigate('/dashboard')} className="text-purple-300 hover:text-white hover:bg-purple-500/10">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>
        </div>
      </header>

      <div className="p-6 max-w-4xl mx-auto space-y-8 relative z-10">
        {/* Hero Section */}
        <div className="text-center space-y-4">
          <div className="flex justify-center">
            <div className="p-4 rounded-full bg-purple-500/20 border border-purple-500/30">
              <Shield className="h-12 w-12 text-purple-400" />
            </div>
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-purple-400 to-blue-400 bg-clip-text text-transparent">
            PiScan Security
          </h1>
          <p className="text-xl text-purple-200/70 max-w-2xl mx-auto">
            Agentless Windows System Vulnerability and Network Scanner using Raspberry Pi 5
          </p>
          <div className="flex justify-center space-x-2">
            <Badge variant="outline" className="bg-purple-500/20 border-purple-500/30 text-purple-300">
              <Cpu className="h-3 w-3 mr-1" />
              Raspberry Pi 5
            </Badge>
            <Badge variant="outline" className="bg-blue-500/20 border-blue-500/30 text-blue-300">
              <Shield className="h-3 w-3 mr-1" />
              Agentless
            </Badge>
            <Badge variant="outline" className="bg-indigo-500/20 border-indigo-500/30 text-indigo-300">
              <Network className="h-3 w-3 mr-1" />
              Network Scanner
            </Badge>
          </div>
        </div>

        {/* Project Description */}
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="text-white">Project Overview</CardTitle>
          </CardHeader>
          <CardContent className="prose prose-sm max-w-none text-purple-200/70">
            <p className="mb-4">
              PiScan Security is a cutting-edge cybersecurity solution that leverages the power of Raspberry Pi 5 
              to perform comprehensive vulnerability assessments on Windows systems across your network. Our agentless 
              approach ensures minimal disruption to your infrastructure while providing maximum security insights.
            </p>
            <p className="mb-4">
              The system automatically discovers Windows machines on your network, performs thorough security scans, 
              and presents actionable intelligence through this modern web dashboard. With real-time risk scoring 
              and detailed vulnerability reports, security teams can prioritize remediation efforts effectively.
            </p>
            <p>
              Built with modern web technologies and cybersecurity best practices, PiScan Security offers 
              an intuitive interface for managing network security at scale, from small offices to enterprise environments.
            </p>
          </CardContent>
        </Card>

        {/* Key Features */}
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="text-white">Key Features</CardTitle>
            <CardDescription className="text-purple-200/70">
              Advanced capabilities powered by Raspberry Pi 5 technology
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {features.map((feature, index) => (
                <div key={index} className="flex space-x-3">
                  <div className="flex-shrink-0 p-2 bg-purple-500/20 rounded-lg text-purple-400">
                    {feature.icon}
                  </div>
                  <div>
                    <h3 className="font-medium mb-1 text-white">{feature.title}</h3>
                    <p className="text-sm text-purple-200/70">{feature.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Technical Specifications */}
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="text-white">Technical Specifications</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h3 className="font-medium mb-3 text-white">Hardware Requirements</h3>
                <ul className="space-y-2 text-sm text-purple-200/70">
                  <li>• Raspberry Pi 5 (8GB RAM recommended)</li>
                  <li>• MicroSD Card (32GB minimum, Class 10)</li>
                  <li>• Ethernet connection for reliable scanning</li>
                  <li>• Power supply (5V, 5A USB-C)</li>
                </ul>
              </div>
              <div>
                <h3 className="font-medium mb-3 text-white">Software Stack</h3>
                <ul className="space-y-2 text-sm text-purple-200/70">
                  <li>• React 18 with TypeScript</li>
                  <li>• Tailwind CSS for styling</li>
                  <li>• Custom vulnerability scanning engine</li>
                  <li>• Network discovery protocols</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Contact Information */}
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardHeader>
            <CardTitle className="text-white">Get In Touch</CardTitle>
            <CardDescription className="text-purple-200/70">
              Contact us for support and collaboration
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex justify-center">
              <Button 
                variant="outline" 
                className="h-20 px-8 flex-col space-y-2 bg-slate-800/50 border-purple-500/20 hover:bg-purple-500/10 text-white"
                onClick={() => window.location.href = 'mailto:pi.scan.advr@gmail.com'}
              >
                <Mail className="h-6 w-6 text-blue-400" />
                <span className="text-sm font-medium">Email Support</span>
                <span className="text-xs text-purple-200/70">pi.scan.advr@gmail.com</span>
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Version Information */}
        <Card className="bg-slate-900/60 backdrop-blur-xl border-purple-500/20">
          <CardContent className="text-center py-6">
            <div className="space-y-2">
              <p className="text-sm text-purple-200/70">
                PiScan Security v1.0.0 • Built with ❤️ by Team 7
              </p>
              <p className="text-xs text-purple-200/70">
                © 2025 Team 7. Agentless Windows System Vulnerability and Network Scanner using Raspberry Pi 5.
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
};

export default About;