declare module 'styled-components' {
  import { ComponentType, ReactNode, CSSProperties } from 'react';
  
  type StyledComponent<T> = ComponentType<T & { children?: ReactNode; className?: string; style?: CSSProperties }>;
  
  interface StyledFunction {
    <T = {}>(strings: TemplateStringsArray, ...values: any[]): StyledComponent<T>;
  }
  
  interface Styled {
    div: StyledFunction;
    span: StyledFunction;
    button: StyledFunction;
    a: StyledFunction;
    p: StyledFunction;
    h1: StyledFunction;
    h2: StyledFunction;
    h3: StyledFunction;
    h4: StyledFunction;
    h5: StyledFunction;
    h6: StyledFunction;
    ul: StyledFunction;
    li: StyledFunction;
    input: StyledFunction;
    textarea: StyledFunction;
    form: StyledFunction;
    label: StyledFunction;
    section: StyledFunction;
    article: StyledFunction;
    header: StyledFunction;
    footer: StyledFunction;
    nav: StyledFunction;
    main: StyledFunction;
    aside: StyledFunction;
    img: StyledFunction;
    svg: StyledFunction;
    [key: string]: StyledFunction;
  }
  
  const styled: Styled;
  export default styled;
  export { css, keyframes, createGlobalStyle, ThemeProvider } from 'styled-components';
}

declare module 'primereact/toast' {
  import { Component, RefObject } from 'react';
  
  export interface ToastMessage {
    severity?: 'success' | 'info' | 'warn' | 'error';
    summary?: string;
    detail?: string;
    life?: number;
    sticky?: boolean;
    closable?: boolean;
    content?: React.ReactNode;
  }
  
  export interface ToastProps {
    id?: string;
    className?: string;
    style?: React.CSSProperties;
    baseZIndex?: number;
    position?: 'top-left' | 'top-center' | 'top-right' | 'bottom-left' | 'bottom-center' | 'bottom-right' | 'center';
    transitionOptions?: object;
    appendTo?: HTMLElement | 'self';
    onClick?: (message: ToastMessage) => void;
    onRemove?: (message: ToastMessage) => void;
    onShow?: () => void;
    onHide?: () => void;
  }
  
  export class Toast extends Component<ToastProps> {
    show(message: ToastMessage | ToastMessage[]): void;
    clear(): void;
    replace(message: ToastMessage | ToastMessage[]): void;
  }
}
