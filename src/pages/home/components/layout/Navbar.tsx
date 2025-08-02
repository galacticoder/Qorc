import React, { useState, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { 
  Cross1Icon,
  HamburgerMenuIcon,
  PlayIcon,
  MoonIcon,
  SunIcon,
  LockClosedIcon,
  LockOpen1Icon,
} from '@radix-ui/react-icons';
import { EncryptionIcon } from '@/components/chat/icons';
import { navItems, navBarButtons } from '../../config/navigation.tsx';

interface NavbarProps {
  onNavigate: (page: 'home' | 'server' | 'chat') => void;
}

const Navbar: React.FC<NavbarProps> = ({ onNavigate }) => {
  const [scrollY, setScrollY] = useState(0);
  const [lastScrollY, setLastScrollY] = useState(0);
  const [isScrolled, setIsScrolled] = useState(false);
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [darkMode, setDarkMode] = useState(false);


  useEffect(() => {
    // check sys preference and localstorage
    const savedMode = localStorage.getItem('darkMode');
    const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    if (savedMode === 'true' || (!savedMode && systemPrefersDark)) {
      setDarkMode(true);
      document.documentElement.classList.add('dark');
    }
  }, []);

  useEffect(() => {
    const handleScroll = () => {
      const currentScrollY = window.scrollY;
      setScrollY(currentScrollY);
      
      if (currentScrollY > 100) {
        if (currentScrollY > lastScrollY) {
          // scrolling down
          setIsScrolled(true);
        } else {
          // scrolling up
          setIsScrolled(false);
        }
      } else {
        // top of page
        setIsScrolled(false);
      }
      setLastScrollY(currentScrollY);
    };

    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, [lastScrollY]);

  const toggleDarkMode = () => {
    const newMode = !darkMode;
    setDarkMode(newMode);
    localStorage.setItem('darkMode', String(newMode));
    
    document.documentElement.classList.add('transition-colors', 'duration-500');
    if (newMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    
    setTimeout(() => {
      document.documentElement.classList.remove('transition-colors', 'duration-700');
    }, 500);
  };

  const smoothScrollTo = (elementId: string) => {
    const element = document.getElementById(elementId.replace('#', ''));
    if (element) {
      element.scrollIntoView({
        behavior: 'smooth',
        block: 'start',
      });
    }
  };

  return (
    <nav 
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-500 ${
        scrollY > 50 
          ? 'bg-white/50 backdrop-blur-xl shadow-xl dark:bg-gray-900/50 dark:shadow-gray-900/30' 
          : 'bg-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className={`flex justify-between items-center transition-all duration-500 ${
          isScrolled ? 'h-16' : 'h-20'
        }`}>
          {/* logo */}
          <div className={`flex items-center space-x-3 cursor-pointer transition-all duration-500 ease-in-out ${
            isScrolled ? 'transform translate-x-[-20px]' : ''
          }`}>
            <a 
              href="#" 
              onClick={(e) => {
                e.preventDefault();
                window.scrollTo({ top: 0, behavior: 'smooth' });
              }} 
              className="flex items-center space-x-3"
            >
              <div className={`relative transition-all duration-500 ease-in-out ${
                isScrolled ? 'w-8 h-8' : 'w-10 h-10'
              }`}>
                <div className="w-full h-full rounded-xl bg-gradient-to-r from-blue-600 to-red-600 flex items-center justify-center shadow-lg">
                  <EncryptionIcon className={`text-white transition-all duration-500 ease-in-out ${
                    isScrolled ? 'h-4 w-4' : 'h-6 w-6'
                  }`} />
                </div>
                <div className="absolute -top-1 -right-1 w-4 h-4 bg-green-500 rounded-full border-2 border-white animate-pulse"></div>
              </div>
              <div className={`overflow-hidden transition-all duration-500 ease-in-out ${
                isScrolled ? 'max-w-0 opacity-0' : 'max-w-[200px] opacity-100'
              }`}>
                <span className="text-2xl font-bold bg-gradient-to-r from-gray-900 to-gray-700 bg-clip-text text-transparent dark:from-gray-100 dark:to-gray-300 whitespace-nowrap">
                  SecureChat
                </span>
                <div className="text-xs text-gray-500 font-medium whitespace-nowrap dark:text-gray-400">
                  End-to-End Encrypted
                </div>
              </div>
            </a>
          </div>

          {/* desktop navigation */}
          <div className={`hidden md:flex items-center space-x-8 transition-all duration-500 ${
            isScrolled ? 'opacity-50' : 'opacity-100'
          }`}>
            {navItems.map((item) => (
              item.external ? (
                <a
                  key={item.name}
                  href={item.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="relative text-gray-700 hover:text-blue-600 transition-all duration-300 font-medium text-lg group dark:text-gray-300 dark:hover:text-blue-400"
                >
                  {item.name}
                  {/* <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-gradient-to-r from-blue-600 to-purple-600 group-hover:w-full transition-all duration-300 dark:from-blue-500 dark500"></span> */}
                </a>
              ) : (
                <button
                  key={item.name}
                  onClick={() => smoothScrollTo(item.href)}
                  className="relative text-gray-700 hover:text-blue-600 transition-all duration-300 font-medium text-lg group dark:text-gray-300 dark:hover:text-blue-400"
                >
                  {item.name}
                  {/* <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-gradient-to-r from-blue-600 to-purple-600 group-hover:w-full transition-all duration-300 dark:from-blue-500 dark:to-purple-500"></span> */}
                </button>
              )
            ))}
          </div>

          {/* desktop cta  */}
          <div className={`flex justify-between items-center transition-[height,opacity,transform] duration-900 ease-[cubic-bezier(0.4,0,0.2,1)] ${
            isScrolled ? 'h-16' : 'h-20'
          }`}>
            {/* dark mode toggle */}
            <Button
              variant="ghost"
              size="icon"
              onClick={toggleDarkMode}
              className={`rounded-full text-gray-700 hover:text-blue-600 dark:text-gray-300 dark:hover:text-blue-400 transition-all duration-500 ${
                isScrolled ? 'opacity-70' : 'opacity-100'
              }`}
              aria-label={darkMode ? "Switch to light mode" : "Switch to dark mode"}
            >
              {darkMode ? (
                <SunIcon className="h-5 w-5 transition-transform duration-500 hover:rotate-180" />
              ) : (
                <MoonIcon className="h-5 w-5 transition-transform duration-500 hover:rotate-12" />
              )}
            </Button>
            
           {/* desktop cta*/}
            <div className={`hidden md:flex items-center transition-all duration-500 ease-[cubic-bezier(0.4,0,0.2,1)] ${
              isScrolled ? 'space-x-0 translate-x-[-0px]' : 'translate-x-0'
            }`}>
              {navBarButtons.map((btn, idx) => (
                <Button
                  key={idx}
                  variant={'ghost'}
                  size="lg"
                  onClick={() => btn.action(onNavigate)}
                  className={`relative overflow-hidden transition-all duration-500 ease-[cubic-bezier(0.4,0,0.2,1)] ${
                    isScrolled 
                      ? 'w-10 h-10 !p-0' 
                      : 'px-6'
                  }`}
                >
                  <div className={`flex items-center justify-center w-full h-full transition-all duration-900 ${
                    isScrolled ? 'scale-90' : 'scale-100'
                  }`}>
                    <span className={`whitespace-nowrap transition-all duration-500 ${
                      isScrolled 
                        ? 'opacity-0 scale-75 translate-x-2' 
                        : 'opacity-100 scale-100 translate-x-0'
                    }`}>
                      {btn.label}
                    </span>
                    
                    <div className={`absolute inset-0 flex items-center justify-center transition-all duration-500 ${
                      isScrolled 
                        ? 'opacity-100 scale-100' 
                        : 'opacity-0 scale-75 -translate-x-2'
                    }`}>
                      {idx === 0 ? (
                        <LockClosedIcon className="h-5 w-5" />
                      ) : (
                        <PlayIcon className="h-5 w-5" />
                      )}
                    </div>
                  </div>
                </Button>
              ))}
            </div>
          </div>

          {/* mobile menu button */}
          <div className="md:hidden flex items-center">
            {/* dark mode toggle for mobile */}
            <Button
              variant="ghost"
              size="icon"
              onClick={toggleDarkMode}
              className="mr-2 text-gray-700 dark:text-gray-300"
              aria-label={darkMode ? "Switch to light mode" : "Switch to dark mode"}
            >
              {darkMode ? (
                <SunIcon className="h-5 w-5" />
              ) : (
                <MoonIcon className="h-5 w-5" />
              )}
            </Button>
            
            <Button
              variant="ghost"
              size="lg"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="text-gray-700 hover:text-blue-600 hover:bg-blue-50 dark:text-gray-300 dark:hover:text-blue-400 dark:hover:bg-gray-800"
            >
              {mobileMenuOpen ? (
                <Cross1Icon className="h-6 w-6" />
              ) : (
                <HamburgerMenuIcon className="h-6 w-6" />
              )}
            </Button>
          </div>
        </div>

        {/* mobile menu */}
        {mobileMenuOpen && (
          <div className="md:hidden absolute top-20 left-0 right-0 bg-white/95 backdrop-blur-xl shadow-2xl border-t border-gray-200/50 dark:bg-gray-900/95 dark:border-gray-800/50">
            <div className="px-6 py-8 space-y-6">
              {navItems.map((item) => (
                item.external ? (
                  <a
                    key={item.name}
                    href={item.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="block w-full text-left text-lg font-medium text-gray-700 hover:text-blue-600 transition-colors duration-300 py-2 dark:text-gray-300 dark:hover:text-blue-400"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    {item.name}
                  </a>
                ) : (
                  <button
                    key={item.name}
                    onClick={() => {
                      smoothScrollTo(item.href);
                      setMobileMenuOpen(false);
                    }}
                    className="block w-full text-left text-lg font-medium text-gray-700 hover:text-blue-600 transition-colors duration-300 py-2 dark:text-gray-300 dark:hover:text-blue-400"
                  >
                    {item.name}
                  </button>
                )
              ))}
              <div className="pt-6 space-y-4 border-t border-gray-200 dark:border-gray-800">
                <Button variant="outline" size="lg" className="w-full dark:border-gray-700 dark:text-gray-300">
                  Sign In
                </Button>
                <Button variant="outline" size="lg" className="w-full dark:border-gray-700 dark:text-gray-300">
                  Get started
                </Button>
              </div>
            </div>
          </div>
        )}
      </div>
    </nav>
  );
};

export default Navbar;