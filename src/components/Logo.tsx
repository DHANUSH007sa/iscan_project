import React from 'react';
import { Shield } from 'lucide-react';

interface LogoProps {
  size?: 'sm' | 'md' | 'lg' | 'xl';
  showText?: boolean;
  variant?: 'default' | 'light';
}

const Logo: React.FC<LogoProps> = ({ size = 'md', showText = true, variant = 'default' }) => {
  const sizeClasses = {
    sm: { icon: 'h-6 w-6', container: 'p-2', text: 'text-lg' },
    md: { icon: 'h-8 w-8', container: 'p-3', text: 'text-xl' },
    lg: { icon: 'h-12 w-12', container: 'p-4', text: 'text-2xl' },
    xl: { icon: 'h-16 w-16', container: 'p-4', text: 'text-3xl' },
  };

  const colors = variant === 'light' 
    ? 'from-purple-400 to-blue-400 text-purple-400'
    : 'from-purple-500/20 to-blue-500/20 text-purple-400 border-purple-500/30';

  return (
    <div className="flex items-center gap-3">
      <div className={`${sizeClasses[size].container} rounded-2xl bg-gradient-to-br ${colors} backdrop-blur-sm border inline-flex`}>
        <Shield className={`${sizeClasses[size].icon} ${variant === 'light' ? 'text-white' : 'text-purple-400'}`} />
      </div>
      {showText && (
        <span className={`${sizeClasses[size].text} font-bold ${variant === 'light' ? 'text-white' : 'text-white'}`}>
          PiScan
        </span>
      )}
    </div>
  );
};

export default Logo;
