import React, { useId } from 'react';

interface AnimatedSwitchProps {
    checked: boolean;
    onCheckedChange: (checked: boolean) => void;
    className?: string;
}

export function AnimatedSwitch({ checked, onCheckedChange, className }: AnimatedSwitchProps) {
    const id = useId();

    return (
        <div className={className}>
            <input
                type="checkbox"
                id={id}
                className="custom-switch-input"
                checked={checked}
                onChange={(e) => onCheckedChange(e.target.checked)}
            />
            <label htmlFor={id} className="toggleSwitch"></label>
        </div>
    );
}
