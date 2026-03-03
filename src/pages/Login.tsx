import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import { Shield, Eye, EyeOff, Loader2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { useAuth } from '@/contexts/auth-context';
import { useToast } from '@/hooks/use-toast';
import Logo from '@/components/Logo';

interface LoginFormData {
  email: string;
  password: string;
}

interface RegisterFormData {
  firstName: string;
  lastName: string;
  dateOfBirth: string;
  email: string;
  password: string;
  confirmPassword: string;
}

const Login = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const { login, register } = useAuth();
  const navigate = useNavigate();
  const { toast } = useToast();

  const loginForm = useForm<LoginFormData>();
  const registerForm = useForm<RegisterFormData>();

  const onLoginSubmit = async (data: LoginFormData) => {
    setIsLoading(true);
    try {
      const success = await login(data.email, data.password);
      if (success) {
        toast({ title: "Welcome to PiShield Dashboard!", description: "Authentication successful" });
        navigate('/dashboard');
      }
    } catch (error: any) {
      const errorMessage = error.message || "Authentication failed. Please try again.";
      toast({ 
        title: "Authentication Failed", 
        description: errorMessage, 
        variant: "destructive" 
      });
    }
    setIsLoading(false);
  };

  const onRegisterSubmit = async (data: RegisterFormData) => {
    if (data.password !== data.confirmPassword) {
      toast({ title: "Error", description: "Passwords don't match", variant: "destructive" });
      return;
    }

    setIsLoading(true);
    try {
      const success = await register(data);
      if (success) {
        toast({ title: "Registration Successful!", description: "Welcome to PiShield Dashboard" });
        navigate('/dashboard');
      }
    } catch (error: any) {
      const errorMessage = error.message || "Registration failed. Please try again.";
      toast({ 
        title: "Registration Failed", 
        description: errorMessage, 
        variant: "destructive" 
      });
    }
    setIsLoading(false);
  };

  return (
    <div className="min-h-screen flex bg-gradient-to-br from-indigo-950 via-purple-950 to-slate-950 relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-0 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute bottom-0 right-0 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl animate-pulse delay-1000"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl animate-pulse delay-500"></div>
      </div>

      {/* Left side - Branding */}
      <div className="hidden lg:flex lg:w-1/2 items-center justify-center p-12 relative z-10">
        <div className="max-w-md">
          <div className="mb-8">
            <Logo size="xl" showText={false} />
          </div>
          <h1 className="text-5xl font-bold text-white mb-4">
            PiScan Security
          </h1>
          <p className="text-xl text-purple-200 mb-8">
            Advanced Vulnerability Scanner for Network Security
          </p>
          <div className="space-y-4">
            <div className="flex items-start gap-3">
              <div className="mt-1 p-2 rounded-lg bg-purple-500/20">
                <Shield className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <h3 className="text-white font-semibold mb-1">Real-time Scanning</h3>
                <p className="text-purple-200/70 text-sm">Detect vulnerabilities instantly across your network</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="mt-1 p-2 rounded-lg bg-blue-500/20">
                <Shield className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <h3 className="text-white font-semibold mb-1">Comprehensive Reports</h3>
                <p className="text-purple-200/70 text-sm">Detailed analysis with actionable insights</p>
              </div>
            </div>
            <div className="flex items-start gap-3">
              <div className="mt-1 p-2 rounded-lg bg-indigo-500/20">
                <Shield className="h-5 w-5 text-indigo-400" />
              </div>
              <div>
                <h3 className="text-white font-semibold mb-1">Multi-Scanner Support</h3>
                <p className="text-purple-200/70 text-sm">11+ security tools in one platform</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Right side - Login Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-8 relative z-10">
        <div className="w-full max-w-md">
          {/* Mobile logo */}
          <div className="lg:hidden text-center mb-8">
            <div className="flex justify-center mb-4">
              <Logo size="lg" showText={false} />
            </div>
            <h2 className="text-2xl font-bold text-white">PiScan Security</h2>
          </div>

          <Card className="bg-slate-900/60 backdrop-blur-xl border-slate-700/50 shadow-2xl">
            <CardHeader className="space-y-1 pb-6">
              <CardTitle className="text-2xl font-bold text-white">
                {isLogin ? 'Welcome Back' : 'Create Account'}
              </CardTitle>
              <CardDescription className="text-slate-400">
                {isLogin ? 'Enter your credentials to access your account' : 'Fill in your details to get started'}
              </CardDescription>
            </CardHeader>

        <CardContent className="space-y-4">
          {isLogin ? (
            <form onSubmit={loginForm.handleSubmit(onLoginSubmit)} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email" className="text-slate-200 font-medium">Email Address</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="you@example.com"
                  {...loginForm.register('email', { required: true })}
                  className="bg-slate-800/50 border-slate-600/50 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20 h-12 transition-all"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password" className="text-slate-200 font-medium">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••"
                    {...loginForm.register('password', { required: true })}
                    className="bg-slate-800/50 border-slate-600/50 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20 h-12 pr-10 transition-all"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent text-slate-400 hover:text-purple-400 transition-colors"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
              <Button 
                type="submit" 
                className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white h-12 font-semibold shadow-lg shadow-purple-500/20 transition-all"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                    Signing in...
                  </>
                ) : (
                  'Sign In'
                )}
              </Button>
            </form>
          ) : (
            <form onSubmit={registerForm.handleSubmit(onRegisterSubmit)} className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label htmlFor="firstName" className="text-slate-200 font-medium">First Name</Label>
                  <Input
                    id="firstName"
                    placeholder="John"
                    {...registerForm.register('firstName', { required: true })}
                    className="bg-slate-800/50 border-slate-600/50 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20 h-11"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="lastName" className="text-slate-200 font-medium">Last Name</Label>
                  <Input
                    id="lastName"
                    placeholder="Doe"
                    {...registerForm.register('lastName', { required: true })}
                    className="bg-slate-800/50 border-slate-600/50 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20 h-11"
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="dateOfBirth" className="text-slate-200 font-medium">Date of Birth</Label>
                <Input
                  id="dateOfBirth"
                  type="date"
                  {...registerForm.register('dateOfBirth', { required: true })}
                  className="bg-slate-800/50 border-slate-600/50 text-white focus:border-purple-500 focus:ring-purple-500/20 h-11"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email" className="text-slate-200 font-medium">Email Address</Label>
                <Input
                  id="email"
                  type="email"
                  placeholder="you@example.com"
                  {...registerForm.register('email', { required: true })}
                  className="bg-slate-800/50 border-slate-600/50 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20 h-11"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password" className="text-slate-200 font-medium">Password</Label>
                <div className="relative">
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••"
                    {...registerForm.register('password', { required: true })}
                    className="bg-slate-800/50 border-slate-600/50 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20 h-11 pr-10"
                  />
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent text-slate-400 hover:text-purple-400"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirmPassword" className="text-slate-200 font-medium">Confirm Password</Label>
                <Input
                  id="confirmPassword"
                  type="password"
                  placeholder="••••••••"
                  {...registerForm.register('confirmPassword', { required: true })}
                  className="bg-slate-800/50 border-slate-600/50 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20 h-11"
                />
              </div>
              <Button 
                type="submit" 
                className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white h-12 font-semibold shadow-lg shadow-purple-500/20"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-5 w-5 animate-spin" />
                    Creating Account...
                  </>
                ) : (
                  'Create Account'
                )}
              </Button>
            </form>
          )}
        </CardContent>

        <CardFooter className="flex flex-col space-y-4 pt-4">
          <div className="text-center">
            <Button
              variant="link"
              onClick={() => setIsLogin(!isLogin)}
              className="text-sm text-purple-400 hover:text-purple-300"
            >
              {isLogin ? "Don't have an account? Create one" : "Already have an account? Sign in"}
            </Button>
          </div>
          
          <div className="relative w-full">
            <div className="absolute inset-0 flex items-center">
              <span className="w-full border-t border-slate-700/50"></span>
            </div>
            <div className="relative flex justify-center text-xs">
              <span className="bg-slate-900 px-3 text-slate-500 uppercase tracking-wider">Admin Access</span>
            </div>
          </div>

          <Button
            variant="outline"
            onClick={() => navigate('/admin')}
            className="w-full bg-transparent border-purple-500/30 text-purple-300 hover:bg-purple-500/10 hover:border-purple-500/50 h-11 transition-all"
          >
            <Shield className="h-4 w-4 mr-2" />
            Administrator Portal
          </Button>
          
          <div className="text-xs text-slate-600 text-center pt-2 flex items-center justify-center gap-2">
            <span>Powered by PiScan</span>
            <span>•</span>
            <span>Team 7</span>
          </div>
        </CardFooter>
      </Card>
        </div>
      </div>
    </div>
  );
};

export default Login;