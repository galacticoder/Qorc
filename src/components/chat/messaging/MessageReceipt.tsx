import React, { useMemo } from 'react';
import { MessageReceipt as ReceiptType } from './types';
import { Check, CheckCheck, Loader2 } from 'lucide-react';
import { cn } from '../../../lib/utils/shared-utils';
import { formatReceiptTime } from '../../../lib/utils/date-utils';

interface MessageReceiptProps {
	readonly receipt?: ReceiptType;
	readonly isCurrentUser: boolean;
	readonly className?: string;
}

export const MessageReceipt: React.FC<MessageReceiptProps> = ({ receipt, isCurrentUser, className }) => {
	if (!isCurrentUser || !receipt) return null;

	if (receipt.sending) {
		return (
			<div className={cn('qorc-message-receipt qorc-message-receipt--sending flex items-center gap-1 select-none italic', className)} role="status" aria-label="Sending">
				<Loader2 size={12} className="animate-spin" aria-hidden="true" />
				<span>Sending...</span>
			</div>
		);
	}

	const readTime = useMemo(() => formatReceiptTime(receipt.readAt), [receipt?.readAt]);
	const deliveredTime = useMemo(() => formatReceiptTime(receipt.deliveredAt), [receipt?.deliveredAt]);

	if (receipt.read) {
		return (
			<div className={cn('qorc-message-receipt qorc-message-receipt--read flex items-center gap-1 select-none', className)} role="status" aria-label={readTime ? `Read at ${readTime}` : 'Read'}>
				<CheckCheck size={12} aria-hidden="true" />
				<span>{readTime ? `Read ${readTime}` : 'Read'}</span>
			</div>
		);
	}

	if (receipt.delivered) {
		return (
			<div className={cn('qorc-message-receipt qorc-message-receipt--delivered flex items-center gap-1 select-none', className)} role="status" aria-label={deliveredTime ? `Delivered at ${deliveredTime}` : 'Delivered'}>
				<Check size={12} aria-hidden="true" />
				<span>{deliveredTime ? `Delivered ${deliveredTime}` : 'Delivered'}</span>
			</div>
		);
	}

	return (
		<div className={cn('qorc-message-receipt qorc-message-receipt--sent flex items-center gap-1 select-none', className)} role="status" aria-label="Sent">
			<span>Sent</span>
		</div>
	);
};
