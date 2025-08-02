import React from 'react';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { EncryptionIcon } from '@/components/chat/icons';
import { 
  footerSocialLinks, 
  footerSecurityLinks,
  footerResourceLinks,
  footerFutureGoalLinks
} from '../../config/navigation.tsx';

const FooterSection: React.FC = () => {
  return (
    <footer className="bg-gradient-to-r from-gray-900 via-slate-900 to-gray-900 text-white py-16 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-r from-blue-900/10 to-purple-900/10" />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-12">
          <div className="animate-fade-in-up">
            <div className="flex items-center mb-6">
              <div className="p-3 rounded-xl bg-gradient-to-r from-blue-500 to-purple-500 mr-4">
                <EncryptionIcon className="h-8 w-8 text-white" />
              </div>
              <div>
                <span className="text-2xl font-bold">SecureChat</span>
                <div className="text-sm text-gray-400">End-to-End Encrypted</div>
              </div>
            </div>
            <p className="text-gray-400 leading-relaxed mb-6">
              Started creating this project in 2025.
            </p>
            <div className="flex space-x-4">
              {footerSocialLinks.map((social) => (
                <Button key={social} variant="ghost" size="sm" className="text-gray-400 hover:text-white">
                  {social}
                </Button>
              ))}
            </div>
          </div>
          
          <div className="animate-fade-in-up" style={{ animationDelay: '200ms' }}>
            <h3 className="font-bold text-lg mb-6">Security</h3>
            <ul className="space-y-3 text-gray-400">
              {footerSecurityLinks.map((item, index) => (
                <li 
                  key={item}
                  className="hover:text-white transition-colors duration-300 cursor-pointer"
                  style={{ animationDelay: `${300 + index * 100}ms` }}
                >
                  {item}
                </li>
              ))}
            </ul>
          </div>
          
          <div className="animate-fade-in-up" style={{ animationDelay: '400ms' }}>
            <h3 className="font-bold text-lg mb-6">Resources</h3>
            <ul className="space-y-3 text-gray-400">
              {footerResourceLinks.map((item, index) => (
                <li 
                  key={item}
                  className="hover:text-white transition-colors duration-300 cursor-pointer"
                  style={{ animationDelay: `${500 + index * 100}ms` }}
                >
                  {item}
                </li>
              ))}
            </ul>
          </div>
          
          <div className="animate-fade-in-up" style={{ animationDelay: '600ms' }}>
            <h3 className="font-bold text-lg mb-6">Future Goals</h3>
            <ul className="space-y-3 text-gray-400">
              {footerFutureGoalLinks.map((item, index) => (
                <li 
                  key={item}
                  className="hover:text-white transition-colors duration-300 cursor-pointer"
                  style={{ animationDelay: `${700 + index * 100}ms` }}
                >
                  {item}
                </li>
              ))}
            </ul>
          </div>
        </div>
        
        <div className="border-t border-gray-700 mt-12 pt-8 flex flex-col md:flex-row justify-between items-center animate-fade-in-up" style={{ animationDelay: '800ms' }}>
          <p className="text-gray-400 mb-4 md:mb-0">
            &copy; 2025 SecureChat. Open source under MIT License.
          </p>
          <div className="flex items-center space-x-6 text-gray-400">
            <span>Made with ❤️ for privacy</span>
            <Badge variant="outline" className="border-green-500 text-green-400">
              SOC 2 Compliant
            </Badge>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default FooterSection;