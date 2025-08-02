import { ReactNode } from 'react';
import {
  LockClosedIcon,
  CheckIcon,
  ChatBubbleIcon,
  FileIcon,
  GlobeIcon,
  RocketIcon,
  LightningBoltIcon,
  PersonIcon,
  PlayIcon,
  ArrowRightIcon,
  StarIcon,
} from '@radix-ui/react-icons';

import { EncryptionIcon, KeyRing } from '@/components/chat/icons';

// navigation items
export const navItems = [
  { name: 'Features', href: '#features', external: false },
  { name: 'Security', href: '#security', external: false },
  { name: 'Technology', href: '#technology', external: false },
  { name: 'Documentation', href: '#docs', external: false },
  { name: 'GitHub', href: 'https://github.com/galacticoder/end2end-chat-site', external: true },
];

// hero section buttons
export const heroButtons = [
  {
    label: 'Start Secure Chat',
    iconLeft: <ChatBubbleIcon className="mr-3 h-6 w-6" />,
    iconRight: <ArrowRightIcon className="ml-3 h-6 w-6" />,
    action: (navigate: (page: 'home' | 'server' | 'chat') => void) => navigate('server'),
    variant: 'primary',
  },
  {
    label: 'Watch Demo',
    iconLeft: <PlayIcon className="mr-3 h-6 w-6" />,
    action: () => {
      const el = document.getElementById('features');
      if (el) el.scrollIntoView({ behavior: 'smooth' });
    },
    variant: 'outline',
  }
];

// cta buttons
export const callToActionButtons = [
  {
    label: 'Launch SecureChat',
    iconLeft: <KeyRing className="mr-3 h-6 w-6" />,
    iconRight: <ArrowRightIcon className="ml-3 h-6 w-6" />,
    action: (navigate: (page: 'home' | 'server' | 'chat') => void) => navigate('server'),
    variant: 'primary',
  },
  {
    label: 'View Documentation',
    iconLeft: <GlobeIcon className="mr-3 h-6 w-6" />,
    action: () => window.location.href = '#docs',
    variant: 'outline',
  }
];

// navbar buttons
export const navBarButtons = [
  {
    label: 'Sign In',
    variant: 'ghost',
    action: (navigate: (page: 'home' | 'server' | 'chat') => void) => navigate('home'),
  },
  {
    label: 'Get Started',
    iconLeft: <PlayIcon className="mr-2 h-5 w-5" />,
    variant: 'gradient',
    action: (navigate: (page: 'home' | 'server' | 'chat') => void) => navigate('server'),
  },
];

// hero section badges
export const heroBadges = [
  { text: 'Open Source', icon: <StarIcon className="h-4 w-4" /> },
  { text: 'MIT License', icon: <CheckIcon className="h-4 w-4" /> },
  { text: 'TypeScript', icon: <RocketIcon className="h-4 w-4" /> },
  { text: 'React', icon: <RocketIcon className="h-4 w-4" /> }
];

// security promise items
export const securityPromises = [
  'Messages encrypted on your device before transmission',
  'Server infrastructure never sees plaintext data',
  // 'Perfect forward secrecy for all conversations', soon
];

// footer social links
export const footerSocialLinks = ['GitHub'];

// footer security links
export const footerSecurityLinks = [
  'RSA-4096 Encryption',
  'AES-256 GCM',
  'Argon2 Key Derivation',
];

// footer resource links
export const footerResourceLinks = [
  'Documentation',
  'GitHub Repository',
];

// footer future links
export const footerFutureGoalLinks = [
  'Future plans list',
];