import React from 'react';
import { motion } from 'framer-motion';
import { cn } from '@/lib/utils';

interface AuthLayoutProps {
    children: React.ReactNode;
    className?: string;
}

export const AuthLayout: React.FC<AuthLayoutProps> = ({ children, className }) => {
    return (
        <div className="min-h-screen w-full flex items-center justify-center bg-background relative overflow-hidden p-4 select-none">
            {/* Animated Background Gradients */}
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                <motion.div
                    className="absolute -top-[25%] -left-[10%] w-[70%] h-[70%] rounded-full bg-primary/5 blur-[100px]"
                    animate={{
                        x: [0, 20, 0],
                        y: [0, 15, 0],
                        scale: [1, 1.05, 1]
                    }}
                    transition={{
                        duration: 30,
                        repeat: Infinity,
                        ease: "easeInOut"
                    }}
                />
                <motion.div
                    className="absolute top-[20%] -right-[10%] w-[60%] h-[60%] rounded-full bg-accent/5 blur-[100px]"
                    animate={{
                        x: [0, -15, 0],
                        y: [0, 20, 0],
                        scale: [1, 1.1, 1]
                    }}
                    transition={{
                        duration: 35,
                        repeat: Infinity,
                        ease: "easeInOut",
                        delay: 2
                    }}
                />
                <motion.div
                    className="absolute -bottom-[20%] left-[20%] w-[50%] h-[50%] rounded-full bg-primary/5 blur-[100px]"
                    animate={{
                        x: [0, 20, 0],
                        y: [0, -20, 0],
                        scale: [1, 1.05, 1]
                    }}
                    transition={{
                        duration: 32,
                        repeat: Infinity,
                        ease: "easeInOut",
                        delay: 5
                    }}
                />
            </div>

            {/* Main Container */}
            <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, ease: "easeOut" }}
                className={cn(
                    "w-full max-w-md relative z-10",
                    className
                )}
            >
                {children}
            </motion.div>
        </div>
    );
};
