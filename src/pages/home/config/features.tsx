import { ReactNode } from 'react';
import {
  LockClosedIcon,
  FileIcon,
  GlobeIcon,
  CheckIcon,
  RocketIcon,
  LightningBoltIcon,
  PersonIcon,
} from '@radix-ui/react-icons';

export const features = [
  {
    icon: <LockClosedIcon className="h-8 w-8" />,
    title: "End-to-End Encryption",
    description: "Every message is encrypted using military-grade RSA-4096 and AES-256 GCM algorithms before leaving your device. Your private keys never touch our servers, ensuring complete privacy.",
    highlight: "RSA-4096 + AES-256",
    color: "from-blue-500 to-cyan-500",
    details: [
      "Client-side key generation",
      // "Perfect forward secrecy", //add back when done
      "Zero-knowledge architecture",
    ]
  },
  {
    icon: <LightningBoltIcon className="h-8 w-8" />,
    title: "Real-time Communication",
    description: "Experience lightning-fast message delivery through our optimized WebSocket infrastructure with automatic reconnection and message queuing for seamless conversations.",
    highlight: "WebSocket",
    color: "from-yellow-500 to-orange-500",
    details: [
      "Sub-second message delivery",
      "Automatic reconnection",
      // "Typing indicators & read receipts" // add when done
    ]
  },
  {
    icon: <FileIcon className="h-8 w-8" />,
    title: "Secure File Sharing",
    description: "Share documents, images, and files with any size with the same level of encryption as your messages. Files are encrypted in chunks for enhanced security and effeciency.",
    highlight: "Encrypted Files",
    color: "from-green-500 to-emerald-500",
    details: [
      "Chunked encryption",
    ]
  },
  {
    icon: <RocketIcon className="h-8 w-8" />,
    title: "Zero-Knowledge Architecture",
    description: "Our servers are designed to never see your plaintext messages. Even if compromised, your conversations remain completely private and secure.",
    highlight: "Zero-Knowledge",
    color: "from-purple-500 to-violet-500",
    details: [
      "Server-side encryption blind",
    ]
  },
  {
    icon: <PersonIcon className="h-8 w-8" />,
    title: "Secure Authentication",
    description: "Advanced Argon2 key derivation with unique salts and optional two-factor authentication ensures your account remains secure against all attack vectors.",
    highlight: "Argon2",
    color: "from-red-500 to-pink-500",
    details: [
      "Argon2id key derivation",
      "Hardware security keys",
      "Biometric authentication",
      "Session management"
    ]
  },
  {
    icon: <GlobeIcon className="h-8 w-8" />,
    title: "Cross-Platform Design",
    description: "Native applications for all major platforms with synchronized conversations, consistent user experience, and offline message support. (Soon)",
    highlight: "Cross-Platform",
    color: "from-indigo-500 to-blue-500",
    details: [
      "iOS, Android, Windows, macOS",
      "Progressive Web App",
      "Offline message sync",
    ]
  }
];

// security specs for security section
export const securitySpecs = [
  { 
    label: "Asymmetric Encryption", 
    value: "RSA-OAEP 4096-bit",
    description: "Industry-leading public key cryptography for secure key exchange"
  },
  { 
    label: "Symmetric Encryption", 
    value: "AES-GCM 256-bit",
    description: "Advanced encryption standard with authenticated encryption"
  },
  { 
    label: "Key Derivation", 
    value: "Argon2 with Salt",
    description: "Memory-hard function resistant to GPU and ASIC attacks"
  },
  { 
    label: "Hash Function", 
    value: "SHA-512",
    description: "Cryptographic hash function for data integrity verification"
  },
  { 
    label: "Transport Security", 
    value: "Secure WebSockets",
    description: "TLS 1.3 encrypted communication channels"
  },
  { 
    label: "Forward Secrecy", 
    value: "Per-message AES keys",
    description: "Unique encryption keys for each message exchange"
  }
];

export const frontendTechnologies = [
  { name: 'React 18', desc: 'Latest React with concurrent features and improved performance', version: 'v18.2.0' },
  { name: 'TypeScript', desc: 'Type-safe development with enhanced developer experience', version: 'v5.0+' },
  { name: 'Vite', desc: 'Lightning-fast build tool with hot module replacement', version: 'v4.0+' },
  { name: 'Tailwind CSS', desc: 'Utility-first CSS framework for rapid UI development', version: 'v3.3+' },
  { name: 'Radix UI', desc: 'Unstyled, accessible components for design systems', version: 'v1.0+' },
  { name: 'Framer Motion', desc: 'Production-ready motion library for React', version: 'v10.0+' }
];

export const backendTechnologies = [
  { name: 'Node.js', desc: 'High-performance JavaScript runtime for scalable applications', version: 'v18 LTS' },
  { name: 'WebSocket', desc: 'Real-time bidirectional communication with automatic reconnection', version: 'RFC 6455' },
  { name: 'Web Crypto API', desc: 'Native browser cryptography for client-side encryption', version: 'W3C Standard' },
  { name: 'Argon2', desc: 'Memory-hard password hashing resistant to GPU attacks', version: 'v1.3' },
  { name: 'Redis', desc: 'In-memory data structure store for session management', version: 'v7.0+' },
  // { name: 'PostgreSQL', desc: 'Advanced open-source relational database', version: 'v15+' } //use db soon
];

export const technologyHighlights = [
  {
    title: "Performance",
    icon: <RocketIcon className="h-8 w-8" />,
    color: "from-orange-500 to-red-500",
    stats: [
      { label: "Load Time", value: "<100ms" },
      { label: "Bundle Size", value: "<50KB" },
      { label: "Lighthouse Score", value: "100/100" }
    ]
  },
  {
    title: "Security",
    icon: <RocketIcon className="h-8 w-8" />,
    color: "from-green-500 to-emerald-500",
    stats: [
      { label: "Encryption", value: "AES-256" },
      { label: "Key Length", value: "4096-bit" },
      { label: "Audit Score", value: "A+" }
    ]
  },
  {
    title: "Reliability",
    icon: <CheckIcon className="h-8 w-8" />,
    color: "from-blue-500 to-cyan-500",
    stats: [
      { label: "Uptime", value: "99.99%" },
      { label: "Response Time", value: "<50ms" },
      { label: "Error Rate", value: "<0.01%" }
    ]
  }
];