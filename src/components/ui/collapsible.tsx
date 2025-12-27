import * as React from "react"
import { cn } from "@/lib/utils"

const Collapsible = React.forwardRef<
    HTMLDivElement,
    React.HTMLAttributes<HTMLDivElement> & {
        open?: boolean
        onOpenChange?: (open: boolean) => void
    }
>(({ className, open, onOpenChange, ...props }, ref) => {
    return (
        <div
            ref={ref}
            data-state={open ? "open" : "closed"}
            className={cn(className)}
            {...props}
        />
    )
})
Collapsible.displayName = "Collapsible"

const CollapsibleTrigger = React.forwardRef<
    HTMLButtonElement,
    React.ButtonHTMLAttributes<HTMLButtonElement> & { asChild?: boolean }
>(({ className, onClick, asChild, children, ...props }, ref) => {

    if (asChild && React.isValidElement(children)) {
        return React.cloneElement(children as React.ReactElement<any>, {
            ref,
            onClick: (e: any) => {
                onClick?.(e);
                (children.props as any).onClick?.(e);
            },
            ...props,
        });
    }

    return (
        <button
            ref={ref}
            type="button"
            onClick={onClick}
            className={cn(className)}
            {...props}
        >
            {children}
        </button>
    )
})
CollapsibleTrigger.displayName = "CollapsibleTrigger"

const CollapsibleContent = React.forwardRef<
    HTMLDivElement,
    React.HTMLAttributes<HTMLDivElement>
>(({ className, children, ...props }, ref) => {
    const { open } = React.useContext(CollapsibleContext);
    const contentRef = React.useRef<HTMLDivElement>(null);
    const [height, setHeight] = React.useState<number | undefined>(0);

    React.useEffect(() => {
        if (contentRef.current) {
            setHeight(open ? contentRef.current.scrollHeight : 0);
        }
    }, [open]);

    React.useEffect(() => {
        if (open && contentRef.current) {
            const updateHeight = () => {
                if (contentRef.current) {
                    setHeight(contentRef.current.scrollHeight);
                }
            };

            const resizeObserver = new ResizeObserver(updateHeight);
            resizeObserver.observe(contentRef.current);

            return () => {
                resizeObserver.disconnect();
            };
        }
    }, [open, children]);

    return (
        <div
            ref={ref}
            data-state={open ? "open" : "closed"}
            style={{
                height: height,
                overflow: 'hidden',
                transition: 'height 300ms cubic-bezier(0.4, 0, 0.2, 1)'
            }}
            className={cn(className)}
            {...props}
        >
            <div ref={contentRef}>
                {children}
            </div>
        </div>
    );
})
CollapsibleContent.displayName = "CollapsibleContent"

const CollapsibleContext = React.createContext<{ open?: boolean }>({ open: false })

const CollapsibleRoot = React.forwardRef<
    HTMLDivElement,
    React.HTMLAttributes<HTMLDivElement> & {
        open?: boolean
        onOpenChange?: (open: boolean) => void
    }
>(({ open, onOpenChange, children, ...props }, ref) => {
    return (
        <CollapsibleContext.Provider value={{ open }}>
            <div
                ref={ref}
                data-state={open ? "open" : "closed"}
                {...props}
            >
                {React.Children.map(children, (child) => {
                    if (React.isValidElement(child) && child.type === CollapsibleTrigger) {
                        return React.cloneElement(child as React.ReactElement<any>, {
                            onClick: (e: any) => {
                                if (!(child.props as any).disabled) {
                                    onOpenChange?.(!open);
                                }
                                (child.props as any).onClick?.(e);
                            },
                        })
                    }
                    return child
                })}
            </div>
        </CollapsibleContext.Provider>
    )
})
CollapsibleRoot.displayName = "Collapsible"

export { CollapsibleRoot as Collapsible, CollapsibleTrigger, CollapsibleContent }
