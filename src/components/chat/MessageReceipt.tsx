import React from 'react';
import { MessageReceipt as ReceiptType } from './types';
import { Check, CheckCheck } from 'lucide-react';

interface MessageReceiptProps {
	receipt?: ReceiptType;
	isCurrentUser: boolean;
	className?: string;
}

export function MessageReceipt({ receipt, isCurrentUser, className }: MessageReceiptProps) {
	if (!isCurrentUser || !receipt) return null;

	if (receipt.read) {
		return (
			<div className={`flex items-center gap-1 text-xs text-blue-600 ${className}`}>
				<CheckCheck size={12} />
				<span>Read</span>
			</div>
		);
	}

	if (receipt.delivered) {
		return (
			<div className={`flex items-center gap-1 text-xs text-gray-500 ${className}`}>
				<Check size={12} />
				<span>Delivered</span>
			</div>
		);
	}

	// Show sent status for messages that don't have delivery confirmation yet
	return (
		<div className={`flex items-center gap-1 text-xs text-gray-400 ${className}`}>
			<span>Sent</span>
		</div>
	);
}
