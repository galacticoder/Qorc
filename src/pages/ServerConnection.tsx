import React, { useEffect, useState, useRef } from 'react';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Separator } from '@/components/ui/separator';
import Navigation from './home/components/layout/Navbar.tsx';

import {
  LockClosedIcon,
  CheckIcon,
  ChatBubbleIcon,
  FileIcon,
  GlobeIcon,
  RocketIcon,
  LightningBoltIcon,
  PersonIcon,
  ArrowRightIcon,
  PlusIcon,
  Share1Icon,
  GearIcon,
  InfoCircledIcon,
  // ShieldIcon,
  ClockIcon,
  UpdateIcon,
} from '@radix-ui/react-icons';

import { EncryptionIcon } from '@/components/chat/icons';

interface ServerConnectionProps {
  onNavigate: (page: 'home' | 'server' | 'chat') => void;
}

const ServerConnection: React.FC<ServerConnectionProps> = ({ onNavigate }) => {
  const [isVisible, setIsVisible] = useState(false);
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 });
  const [activeTab, setActiveTab] = useState<'join' | 'host'>('join');
  const [serverIP, setServerIP] = useState('');
  const [serverPort, setServerPort] = useState('');
  const [serverPassword, setServerPassword] = useState('');
  const [hostPort, setHostPort] = useState('8080');
  const [hostPassword, setHostPassword] = useState('');
  const [serverName, setServerName] = useState('');
  const heroRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setIsVisible(true);
    
    const handleMouseMove = (e: MouseEvent) => {
      setMousePosition({ x: e.clientX, y: e.clientY });
    };

    window.addEventListener('mousemove', handleMouseMove);
    
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  const handleJoinServer = () => {
    if (!serverIP || !serverPort) {
      alert('Please enter both server IP and port');
      return;
    }
    // Here you would implement the actual server connection logic
    console.log('Joining server:', { serverIP, serverPort, serverPassword });
    // Navigate to chat after successful connection
    onNavigate('chat');
  };

  const handleHostServer = () => {
    if (!hostPort) {
      alert('Please enter a port number');
      return;
    }
    // Here you would implement the actual server hosting logic
    console.log('Hosting server:', { hostPort, hostPassword, serverName });
    // Navigate to chat after successful hosting
    onNavigate('chat');
  };

  const securityFeatures = [
    {
      icon: <LockClosedIcon className="h-6 w-6 text-blue-600" />,
      title: "End-to-End Encryption",
      description: "All communications are encrypted using RSA-4096 and AES-256 before transmission."
    },
    {
      icon: <RocketIcon className="h-6 w-6 text-green-600" />,
      title: "Zero-Knowledge Architecture",
      description: "Server never sees your plaintext messages or private keys."
    },
    {
      icon: <LightningBoltIcon className="h-6 w-6 text-yellow-600" />,
      title: "Real-time Messaging",
      description: "Instant message delivery with WebSocket technology and automatic reconnection."
    },
    {
      icon: <PersonIcon className="h-6 w-6 text-purple-600" />,
      title: "Secure Authentication",
      description: "Argon2 key derivation with unique salts for maximum security."
    }
  ];

  const hostingBenefits = [
    {
      icon: <RocketIcon className="h-6 w-6 text-purple-600" />,
      title: "Full Control",
      description: "Complete control over your server settings, user management, and data."
    },
    {
      icon: <GlobeIcon className="h-6 w-6 text-blue-600" />,
      title: "Network Flexibility",
      description: "Host on local network or configure for internet access as needed."
    },
    {
      icon: <GearIcon className="h-6 w-6 text-gray-600" />,
      title: "Customizable",
      description: "Set custom ports, passwords, server names, and security policies."
    },
    {
      icon: <ClockIcon className="h-6 w-6 text-green-600" />,
      title: "Always Available",
      description: "Your server runs continuously, available whenever you need it."
    }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50/30 to-indigo-50/50 relative overflow-hidden">
      <Navigation currentPage="server" onNavigate={onNavigate} />

      {/* Enhanced Animated Background */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div 
          className="absolute w-[600px] h-[600px] bg-gradient-to-r from-blue-400/20 to-purple-400/20 rounded-full blur-3xl animate-pulse"
          style={{
            left: mousePosition.x / 8,
            top: mousePosition.y / 8,
            transition: 'all 0.5s ease-out'
          }}
        />
        <div className="absolute top-1/4 right-1/4 w-96 h-96 bg-gradient-to-r from-cyan-400/15 to-blue-400/15 rounded-full blur-3xl animate-bounce" style={{ animationDuration: '4s' }} />
        <div className="absolute bottom-1/4 left-1/4 w-[500px] h-[500px] bg-gradient-to-r from-purple-400/15 to-pink-400/15 rounded-full blur-3xl animate-pulse" style={{ animationDuration: '6s' }} />
        
        {/* Floating particles */}
        <div className="absolute top-20 left-20 w-2 h-2 bg-blue-400 rounded-full animate-ping" style={{ animationDelay: '1s' }}></div>
        <div className="absolute top-40 right-32 w-1 h-1 bg-purple-400 rounded-full animate-ping" style={{ animationDelay: '2s' }}></div>
        <div className="absolute bottom-40 left-40 w-1.5 h-1.5 bg-cyan-400 rounded-full animate-ping" style={{ animationDelay: '3s' }}></div>
      </div>

      {/* Hero Section */}
      <div ref={heroRef} className="relative overflow-hidden pt-20">
        <div className="absolute inset-0 bg-gradient-to-br from-blue-600/10 via-purple-600/10 to-indigo-600/10" />
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
          <div className="text-center mb-16">
            {/* Enhanced floating icon */}
            <div 
              className={`mx-auto w-24 h-24 rounded-3xl bg-gradient-to-r from-blue-600 via-purple-600 to-blue-700 flex items-center justify-center mb-8 transform transition-all duration-1500 ${
                isVisible ? 'scale-100 rotate-0 opacity-100' : 'scale-0 rotate-180 opacity-0'
              }`}
              style={{ 
                boxShadow: '0 25px 80px rgba(59, 130, 246, 0.4), 0 0 0 1px rgba(255, 255, 255, 0.1)',
                animation: 'float 4s ease-in-out infinite'
              }}
            >
              <Share1Icon className="h-12 w-12 text-white" />
            </div>
            
            {/* Enhanced title */}
            <h1 
              className={`text-4xl md:text-6xl font-black mb-6 transform transition-all duration-1500 delay-300 ${
                isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'
              }`}
            >
              <span className="bg-gradient-to-r from-gray-900 via-blue-900 to-purple-900 bg-clip-text text-transparent">
                Server
              </span>
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 via-purple-600 to-blue-700 animate-pulse">
                Connection
              </span>
            </h1>
            
            {/* Enhanced subtitle */}
            <p 
              className={`text-xl md:text-2xl text-gray-700 mb-8 max-w-3xl mx-auto font-medium leading-relaxed transform transition-all duration-1500 delay-500 ${
                isVisible ? 'translate-y-0 opacity-100' : 'translate-y-10 opacity-0'
              }`}
            >
              Join an existing secure chat server or host your own encrypted communication hub.
            </p>
          </div>

          {/* Main Content Area */}
          <div className="max-w-6xl mx-auto">
            {/* Tab Navigation */}
            <div className="flex justify-center mb-8">
              <div className="bg-white/80 backdrop-blur-sm rounded-2xl p-2 shadow-xl border border-gray-200/50">
                <div className="flex space-x-2">
                  <Button
                    onClick={() => setActiveTab('join')}
                    variant={activeTab === 'join' ? 'default' : 'ghost'}
                    size="lg"
                    className={`px-8 py-4 rounded-xl transition-all duration-300 ${
                      activeTab === 'join' 
                        ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg' 
                        : 'text-gray-700 hover:text-blue-600 hover:bg-blue-50'
                    }`}
                  >
                    <Share1Icon className="mr-2 h-5 w-5" />
                    Join Server
                  </Button>
                  <Button
                    onClick={() => setActiveTab('host')}
                    variant={activeTab === 'host' ? 'default' : 'ghost'}
                    size="lg"
                    className={`px-8 py-4 rounded-xl transition-all duration-300 ${
                      activeTab === 'host' 
                        ? 'bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg' 
                        : 'text-gray-700 hover:text-blue-600 hover:bg-blue-50'
                    }`}
                  >
                    <PlusIcon className="mr-2 h-5 w-5" />
                    Host Server
                  </Button>
                </div>
              </div>
            </div>

            {/* Content Cards */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-12">
              {/* Main Action Card */}
              <Card className="bg-white/90 backdrop-blur-sm shadow-2xl border-t-4 border-blue-500 transform hover:scale-105 transition-all duration-300">
                <CardHeader>
                  <CardTitle className="text-2xl font-bold text-gray-800 flex items-center">
                    {activeTab === 'join' ? (
                      <>
                        <Share1Icon className="mr-3 h-6 w-6 text-blue-600" />
                        Join Existing Server
                      </>
                    ) : (
                      <>
                        <PlusIcon className="mr-3 h-6 w-6 text-purple-600" />
                        Host New Server
                      </>
                    )}
                  </CardTitle>
                  <CardDescription className="text-lg text-gray-600">
                    {activeTab === 'join' 
                      ? 'Connect to a secure chat server using its IP address and port.'
                      : 'Create your own secure chat server for others to join.'
                    }
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  {activeTab === 'join' ? (
                    <>
                      <div className="grid grid-cols-2 gap-4">
                        <div className="space-y-2">
                          <Label htmlFor="serverIP" className="text-sm font-medium text-gray-700">
                            Server IP Address
                          </Label>
                          <Input
                            id="serverIP"
                            type="text"
                            placeholder="192.168.1.100"
                            value={serverIP}
                            onChange={(e) => setServerIP(e.target.value)}
                            className="border-gray-300 focus:border-blue-500 focus:ring-blue-500"
                          />
                        </div>
                        <div className="space-y-2">
                          <Label htmlFor="serverPort" className="text-sm font-medium text-gray-700">
                            Port
                          </Label>
                          <Input
                            id="serverPort"
                            type="text"
                            placeholder="8080"
                            value={serverPort}
                            onChange={(e) => setServerPort(e.target.value)}
                            className="border-gray-300 focus:border-blue-500 focus:ring-blue-500"
                          />
                        </div>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="serverPassword" className="text-sm font-medium text-gray-700">
                          Server Password (Optional)
                        </Label>
                        <Input
                          id="serverPassword"
                          type="password"
                          placeholder="Enter server password"
                          value={serverPassword}
                          onChange={(e) => setServerPassword(e.target.value)}
                          className="border-gray-300 focus:border-blue-500 focus:ring-blue-500"
                        />
                      </div>
                      <Button 
                        onClick={handleJoinServer}
                        size="lg" 
                        className="w-full bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300"
                      >
                        <Share1Icon className="mr-2 h-5 w-5" />
                        Connect to Server
                        <ArrowRightIcon className="ml-2 h-5 w-5" />
                      </Button>
                    </>
                  ) : (
                    <>
                      <div className="space-y-2">
                        <Label htmlFor="hostPort" className="text-sm font-medium text-gray-700">
                          Server Port
                        </Label>
                        <Input
                          id="hostPort"
                          type="text"
                          placeholder="8080"
                          value={hostPort}
                          onChange={(e) => setHostPort(e.target.value)}
                          className="border-gray-300 focus:border-blue-500 focus:ring-blue-500"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="hostPassword" className="text-sm font-medium text-gray-700">
                          Server Password (Optional)
                        </Label>
                        <Input
                          id="hostPassword"
                          type="password"
                          placeholder="Set server password"
                          value={hostPassword}
                          onChange={(e) => setHostPassword(e.target.value)}
                          className="border-gray-300 focus:border-blue-500 focus:ring-blue-500"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="serverName" className="text-sm font-medium text-gray-700">
                          Server Name (Optional)
                        </Label>
                        <Input
                          id="serverName"
                          type="text"
                          placeholder="My Secure Chat Server"
                          value={serverName}
                          onChange={(e) => setServerName(e.target.value)}
                          className="border-gray-300 focus:border-blue-500 focus:ring-blue-500"
                        />
                      </div>
                      <Button 
                        onClick={handleHostServer}
                        size="lg" 
                        className="w-full bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 text-white shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300"
                      >
                        <PlusIcon className="mr-2 h-5 w-5" />
                        Start Server
                        <RocketIcon className="ml-2 h-5 w-5" />
                      </Button>
                    </>
                  )}
                </CardContent>
              </Card>

              {/* Information Card */}
              <Card className="bg-white/90 backdrop-blur-sm shadow-2xl border-t-4 border-purple-500">
                <CardHeader>
                  <CardTitle className="text-2xl font-bold text-gray-800 flex items-center">
                    <InfoCircledIcon className="mr-3 h-6 w-6 text-purple-600" />
                    {activeTab === 'join' ? 'Security Features' : 'Hosting Benefits'}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  {activeTab === 'join' ? (
                    <>
                      <div className="space-y-4">
                        {securityFeatures.map((feature, index) => (
                          <div key={index} className="flex items-start space-x-3">
                            {feature.icon}
                            <div>
                              <h3 className="font-semibold text-gray-800">{feature.title}</h3>
                              <p className="text-gray-600 text-sm">{feature.description}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                      <Separator />
                      <div className="bg-blue-50 p-4 rounded-lg">
                        <h4 className="font-semibold text-blue-800 mb-2 flex items-center">
                          <InfoCircledIcon className="mr-2 h-4 w-4" />
                          Connection Tips
                        </h4>
                        <ul className="text-blue-700 text-sm space-y-1">
                          <li>• Ask the server admin for the correct IP and port</li>
                          <li>• Ensure you're on the same network or have internet access</li>
                          <li>• Server password is case-sensitive if required</li>
                          <li>• Connection is automatically encrypted end-to-end</li>
                        </ul>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="space-y-4">
                        {hostingBenefits.map((benefit, index) => (
                          <div key={index} className="flex items-start space-x-3">
                            {benefit.icon}
                            <div>
                              <h3 className="font-semibold text-gray-800">{benefit.title}</h3>
                              <p className="text-gray-600 text-sm">{benefit.description}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                      <Separator />
                      <div className="bg-purple-50 p-4 rounded-lg">
                        <h4 className="font-semibold text-purple-800 mb-2 flex items-center">
                          <RocketIcon className="mr-2 h-4 w-4" />
                          Hosting Tips
                        </h4>
                        <ul className="text-purple-700 text-sm space-y-1">
                          <li>• Choose an available port (default: 8080)</li>
                          <li>• Share your IP address with users who want to join</li>
                          <li>• Consider setting a password for private servers</li>
                          <li>• Server automatically handles encryption and security</li>
                        </ul>
                      </div>
                    </>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* Enhanced Features Section */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
              <Card className="bg-white/90 backdrop-blur-sm shadow-xl border-l-4 border-blue-500 hover:shadow-2xl transition-all duration-300">
                <CardContent className="p-6 text-center">
                  <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <LockClosedIcon className="h-6 w-6 text-blue-600" />
                  </div>
                  <h3 className="font-bold text-gray-800 mb-2">Military-Grade Security</h3>
                  <p className="text-sm text-gray-600">RSA-4096 + AES-256 encryption for all communications</p>
                </CardContent>
              </Card>

              <Card className="bg-white/90 backdrop-blur-sm shadow-xl border-l-4 border-green-500 hover:shadow-2xl transition-all duration-300">
                <CardContent className="p-6 text-center">
                  <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <LightningBoltIcon className="h-6 w-6 text-green-600" />
                  </div>
                  <h3 className="font-bold text-gray-800 mb-2">Lightning Fast</h3>
                  <p className="text-sm text-gray-600">Real-time messaging with WebSocket technology</p>
                </CardContent>
              </Card>

              <Card className="bg-white/90 backdrop-blur-sm shadow-xl border-l-4 border-purple-500 hover:shadow-2xl transition-all duration-300">
                <CardContent className="p-6 text-center">
                  <div className="w-12 h-12 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <RocketIcon className="h-6 w-6 text-purple-600" />
                  </div>
                  <h3 className="font-bold text-gray-800 mb-2">Zero-Knowledge</h3>
                  <p className="text-sm text-gray-600">Server never sees your private messages or keys</p>
                </CardContent>
              </Card>

              <Card className="bg-white/90 backdrop-blur-sm shadow-xl border-l-4 border-orange-500 hover:shadow-2xl transition-all duration-300">
                <CardContent className="p-6 text-center">
                  <div className="w-12 h-12 bg-orange-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <UpdateIcon className="h-6 w-6 text-orange-600" />
                  </div>
                  <h3 className="font-bold text-gray-800 mb-2">Auto-Reconnect</h3>
                  <p className="text-sm text-gray-600">Seamless reconnection and message queuing</p>
                </CardContent>
              </Card>
            </div>

            {/* Server Status Card */}
            <Card className="bg-white/90 backdrop-blur-sm shadow-xl border-t-4 border-green-500">
              <CardHeader>
                <CardTitle className="text-xl font-bold text-gray-800 flex items-center">
                  <CheckIcon className="mr-3 h-5 w-5 text-green-600" />
                  Connection Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8">
                  <div className="w-16 h-16 bg-gray-200 rounded-full flex items-center justify-center mx-auto mb-4">
                    <GearIcon className="h-8 w-8 text-gray-500" />
                  </div>
                  <p className="text-gray-600 font-medium">Ready to Connect</p>
                  <p className="text-sm text-gray-500 mt-1">
                    {activeTab === 'join' 
                      ? 'Enter server details above to establish a secure connection'
                      : 'Configure your server settings above to start hosting'
                    }
                  </p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="py-12 bg-gray-900 text-gray-400 text-center">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row justify-between items-center space-y-6 md:space-y-0">
            <div className="text-lg font-semibold">
              SecureChat &copy; 2025
            </div>
            <div className="flex space-x-6">
              <a href="#" className="hover:text-white transition-colors duration-300">Privacy Policy</a>
              <a href="#" className="hover:text-white transition-colors duration-300">Terms of Service</a>
              <a href="#" className="hover:text-white transition-colors duration-300">Contact Us</a>
            </div>
            <div className="flex space-x-4">
              {/* Social Media Icons */}
              <a href="#" className="text-gray-400 hover:text-white"><svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path fillRule="evenodd" d="M22 12c0-5.523-4.477-10-10-10S2 6.477 2 12c0 4.991 3.657 9.128 8.438 9.878v-6.987h-2.54V12h2.54V9.797c0-2.506 1.492-3.89 3.777-3.89 1.094 0 2.238.195 2.238.195v2.46h-1.26c-1.243 0-1.63.771-1.63 1.562V12h2.773l-.443 2.89h-2.33V22C18.343 21.128 22 16.991 22 12z" clipRule="evenodd" /></svg></a>
              <a href="#" className="text-gray-400 hover:text-white"><svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path fillRule="evenodd" d="M12.488 1.277C10.638.26 8.53.059 6.437.045 3.314.045.54 1.28.54 5.912v12.982c0 4.633 2.774 5.868 5.897 5.868 2.103.014 4.21-.19 6.06-.997 1.85-.807 3.39-2.06 4.47-3.57 1.08-1.51 1.62-3.23 1.62-5.07 0-1.84-.54-3.56-1.62-5.07-1.08-1.51-2.62-2.763-4.47-3.57zM12 18.5c-3.59 0-6.5-2.91-6.5-6.5S8.41 5.5 12 5.5s6.5 2.91 6.5 6.5-2.91 6.5-6.5 6.5z" clipRule="evenodd" /></svg></a>
              <a href="#" className="text-gray-400 hover:text-white"><svg className="h-6 w-6" fill="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path fillRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.86 8.16 6.839 9.489.5.092.682-.217.682-.483 0-.237-.009-.868-.013-1.703-2.782.604-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.007.07 1.532 1.03 1.532 1.03.892 1.529 2.341 1.089 2.91.832.092-.647.35-1.089.636-1.338-2.22-.253-4.555-1.11-4.555-4.949 0-1.09.39-1.984 1.03-2.685-.103-.253-.448-1.27.097-2.659 0 0 .84-.27 2.75 1.025.798-.222 1.648-.333 2.498-.337.85.004 1.7.115 2.498.337 1.91-1.295 2.75-1.025 2.75-1.025.546 1.389.202 2.406.097 2.659.64.701 1.03 1.595 1.03 2.685 0 3.848-2.339 4.695-4.566 4.942.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.579.688.482C19.14 20.16 22 16.418 22 12c0-5.523-4.477-10-10-10z" clipRule="evenodd" /></svg></a>
            </div>
          </div>
        </div>
      </footer>

      {/* Keyframes for animations */}
      <style>{`
        @keyframes float {
          0% { transform: translateY(0px); }
          50% { transform: translateY(-10px); }
          100% { transform: translateY(0px); }
        }
        @keyframes blob {
          0% { transform: translate(0px, 0px) scale(1); }
          33% { transform: translate(30px, -50px) scale(1.1); }
          66% { transform: translate(-20px, 20px) scale(0.9); }
          100% { transform: translate(0px, 0px) scale(1); }
        }
        .animate-blob {
          animation: blob 7s infinite;
        }
        .animation-delay-2000 {
          animation-delay: 2s;
        }
        .animation-delay-4000 {
          animation-delay: 4s;
        }
      `}</style>
    </div>
  );
};

export default ServerConnection;

