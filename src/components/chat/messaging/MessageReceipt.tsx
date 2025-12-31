import React, { useMemo } from 'react';
import { MessageReceipt as ReceiptType } from './types';
import { Check, CheckCheck } from 'lucide-react';
import { cn } from '../../../lib/utils';
import { formatReceiptTime } from '../../../lib/date-utils';

interface MessageReceiptProps {
	readonly receipt?: ReceiptType;
	readonly isCurrentUser: boolean;
	readonly className?: string;
}

export const MessageReceipt: React.FC<MessageReceiptProps> = ({ receipt, isCurrentUser, className }) => {
	if (!isCurrentUser || !receipt) return null;

	const readTime = useMemo(() => formatReceiptTime(receipt.readAt), [receipt?.readAt]);
	const deliveredTime = useMemo(() => formatReceiptTime(receipt.deliveredAt), [receipt?.deliveredAt]);

	if (receipt.read) {
		return (
			<div className={cn('flex items-center gap-1 text-xs text-blue-600 select-none', className)} role="status" aria-label={readTime ? `Read at ${readTime}` : 'Read'}>
				<CheckCheck size={12} aria-hidden="true" />
				<span>{readTime ? `Read ${readTime}` : 'Read'}</span>
			</div>
		);
	}

	if (receipt.delivered) {
		return (
			<div className={cn('flex items-center gap-1 text-xs text-gray-400 select-none', className)} role="status" aria-label={deliveredTime ? `Delivered at ${deliveredTime}` : 'Delivered'}>
				<Check size={12} aria-hidden="true" />
				<span>{deliveredTime ? `Delivered ${deliveredTime}` : 'Delivered'}</span>
			</div>
		);
	}

	return (
		<div className={cn('flex items-center gap-1 text-xs text-gray-400 select-none', className)} role="status" aria-label="Sent">
			<span>Sent</span>
		</div>
	);
};
