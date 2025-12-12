import React from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import rehypeHighlight from 'rehype-highlight';
import { isMarkdownMessage, extractMarkdownContent, hasMixedContent, parseMixedContent } from '../../lib/markdown-parser';

/**
 * Check if markdown content should be rendered inline
 */
function shouldRenderInline(content: string): boolean {
  if (content.includes('\n')) return false;

  const hasCodeBlock = /```/.test(content);
  const hasCodeFence = /~~~/.test(content);
  const hasList = /(^|\s)[-*+]\s/.test(content) || /(^|\s)\d+\.\s/.test(content);
  const hasBlockquote = /(^|\s)>\s/.test(content);
  const hasTable = /\|.*\|/.test(content);

  if (hasCodeBlock || hasCodeFence || hasList || hasBlockquote || hasTable) {
    return false;
  }

  return true;
}

interface MarkdownRendererProps {
  content: string;
  className?: string;
  isCurrentUser?: boolean;
  preCalculatedContent?: string;
}

export function MarkdownRenderer({ content, className = '', isCurrentUser = false, preCalculatedContent }: MarkdownRendererProps) {
  if (!preCalculatedContent && hasMixedContent(content)) {
    const segments = parseMixedContent(content);

    return (
      <div className={`mixed-content ${className}`}>
        {segments.map((segment, index) => {
          if (segment.type === 'text') {
            return <span key={index}>{segment.content}</span>;
          } else {
            const isLargeContent = segment.content.length > 500 ||
              segment.content.split('\n').length > 10 ||
              segment.content.includes('```') ||
              (segment.content.match(/^#{1,3}\s/gm) || []).length > 2;

            const isInlineContent = shouldRenderInline(segment.content) && !segment.hasOriginalNewlines;
            const contentClassName = isLargeContent
              ? 'markdown-content markdown-readme'
              : 'markdown-content';
            const useCurrentUserColors = !isLargeContent && isCurrentUser;

            const WrapperElement = isInlineContent ? 'span' : 'div';

            return (
              <WrapperElement
                key={index}
                className={contentClassName}
                style={useCurrentUserColors ? {
                  color: 'white',
                } : {}}
              >
                <ReactMarkdown
                  remarkPlugins={[remarkGfm]}
                  rehypePlugins={[rehypeHighlight]}
                  components={{
                    h1: ({ children, ...props }) => isInlineContent ?
                      <span style={{ fontWeight: 600, fontSize: '1.5em' }} {...props}>{children}</span> :
                      <h1 {...props}>{children}</h1>,
                    h2: ({ children, ...props }) => isInlineContent ?
                      <span style={{ fontWeight: 600, fontSize: '1.3em' }} {...props}>{children}</span> :
                      <h2 {...props}>{children}</h2>,
                    h3: ({ children, ...props }) => isInlineContent ?
                      <span style={{ fontWeight: 600, fontSize: '1.2em' }} {...props}>{children}</span> :
                      <h3 {...props}>{children}</h3>,
                    h4: ({ children, ...props }) => isInlineContent ?
                      <span style={{ fontWeight: 600, fontSize: '1.1em' }} {...props}>{children}</span> :
                      <h4 {...props}>{children}</h4>,
                    h5: ({ children, ...props }) => isInlineContent ?
                      <span style={{ fontWeight: 600, fontSize: '1em' }} {...props}>{children}</span> :
                      <h5 {...props}>{children}</h5>,
                    h6: ({ children, ...props }) => isInlineContent ?
                      <span style={{ fontWeight: 600, fontSize: '0.9em' }} {...props}>{children}</span> :
                      <h6 {...props}>{children}</h6>,
                    p: ({ children, ...props }) => isInlineContent ?
                      <span {...props}>{children}</span> :
                      <p {...props}>{children}</p>,
                    a: ({ href, children, ...props }) => (
                      <a
                        href={href}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ color: 'var(--markdown-link-color)' }}
                        {...props}
                      >
                        {children}
                      </a>
                    ),
                    code: ({ children, className, ...props }) => {
                      const isInline = !className;
                      return (
                        <code
                          className={className}
                          style={{
                            backgroundColor: isInline ? 'var(--markdown-inline-code-bg)' : 'transparent',
                            color: isInline ? 'var(--markdown-code-text)' : 'inherit',
                            padding: isInline ? '0.2em 0.4em' : '0',
                            borderRadius: isInline ? '6px' : '0',
                            fontSize: isInline ? '0.85em' : 'inherit',
                            fontFamily: 'var(--markdown-code-font)'
                          }}
                          {...props}
                        >
                          {children}
                        </code>
                      );
                    }
                  }}
                >
                  {segment.content}
                </ReactMarkdown>
              </WrapperElement>
            );
          }
        })}
      </div>
    );
  }

  if (!preCalculatedContent && !isMarkdownMessage(content)) {
    return <span className={className}>{content}</span>;
  }

  const markdownContent = preCalculatedContent || extractMarkdownContent(content);

  const isLargeContent = markdownContent.length > 500 ||
    markdownContent.split('\n').length > 10 ||
    markdownContent.includes('```') ||
    (markdownContent.match(/^#{1,3}\s/gm) || []).length > 2;

  const contentClassName = isLargeContent
    ? 'markdown-content markdown-readme'
    : `markdown-content ${className || ''} markdown-message`.trim();
  const useCurrentUserColors = !isLargeContent && isCurrentUser;

  return (
    <div
      className={contentClassName}
      style={useCurrentUserColors ? {
        color: 'white',
      } : {}}
    >
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        rehypePlugins={[rehypeHighlight]}
        components={{
          a: ({ href, children, ...props }) => (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              style={{ color: 'var(--markdown-link-color)' }}
              {...props}
            >
              {children}
            </a>
          ),
          code: ({ children, className, ...props }) => {
            const isInline = !className;
            return (
              <code
                className={className}
                style={{
                  backgroundColor: isInline ? 'var(--markdown-inline-code-bg)' : 'transparent',
                  color: isInline ? 'var(--markdown-code-text)' : 'inherit',
                  padding: isInline ? '0.2em 0.4em' : '0',
                  borderRadius: isInline ? '6px' : '0',
                  fontSize: isInline ? '0.85em' : 'inherit',
                  fontFamily: 'var(--markdown-code-font)'
                }}
                {...props}
              >
                {children}
              </code>
            );
          }
        }}
      >
        {markdownContent}
      </ReactMarkdown>
    </div>
  );
}

export const markdownStyles = `
.markdown-content {
  font-family: inherit;
  line-height: 1.6;
}

.markdown-content h1,
.markdown-content h2,
.markdown-content h3,
.markdown-content h4,
.markdown-content h5,
.markdown-content h6 {
  margin: 0.4em 0 0.2em 0;
  font-weight: 600;
  color: var(--markdown-header-color);
  line-height: 1.3;
}

.markdown-content h1 { font-size: 1.5em; }
.markdown-content h2 { font-size: 1.3em; }
.markdown-content h3 { font-size: 1.2em; }
.markdown-content h4 { font-size: 1.1em; }
.markdown-content h5 { font-size: 1em; }
.markdown-content h6 { font-size: 0.9em; }

.markdown-content p {
  margin: 0.3em 0;
}

.markdown-content p:first-child {
  margin-top: 0;
}

.markdown-content p:last-child {
  margin-bottom: 0;
}

.markdown-content code {
  background-color: var(--markdown-inline-code-bg);
  color: var(--markdown-code-text);
  padding: 0.2em 0.4em;
  border-radius: 6px;
  font-size: 0.85em;
  font-family: var(--markdown-code-font);
}

.markdown-content pre {
  background-color: var(--markdown-code-bg);
  border: 1px solid var(--markdown-code-border);
  border-radius: 6px;
  padding: 0.6em;
  overflow-x: auto;
  margin: 0.4em 0;
  color: var(--markdown-code-text);
}

.markdown-content pre code {
  background: none;
  padding: 0;
  border-radius: 0;
  font-size: 0.85em;
  color: var(--markdown-code-text);
}

.markdown-content ul,
.markdown-content ol {
  margin: 0.3em 0;
  padding-left: 1.2em;
}

.markdown-content li {
  margin: 0.1em 0;
  list-style-type: disc;
}

.markdown-content a {
  color: var(--markdown-link-color);
  text-decoration: underline;
  text-decoration-skip-ink: auto;
}

.markdown-content a:hover {
  text-decoration: none;
}

.markdown-content strong {
  font-weight: 600;
}

.markdown-content em {
  font-style: italic;
}

.markdown-content br {
  line-height: 1.8;
}

/* Compact spacing for chat bubbles */
.markdown-content.compact {
  font-size: 0.95em;
}

.markdown-content.compact h1,
.markdown-content.compact h2,
.markdown-content.compact h3,
.markdown-content.compact h4,
.markdown-content.compact h5,
.markdown-content.compact h6 {
  margin: 0.2em 0 0.1em 0;
}

.markdown-content.compact p {
  margin: 0.2em 0;
}

.markdown-content.compact pre {
  margin: 0.3em 0;
  padding: 0.5em;
}

.markdown-content.compact ul,
.markdown-content.compact ol {
  margin: 0.2em 0;
  padding-left: 1em;
}

/* Mixed content styling */
.mixed-content {
  display: block;
  word-break: break-word;
  margin: 0;
  padding: 0;
}

.mixed-content.compact {
  font-size: 0.95em;
}

.mixed-content .markdown-content {
  display: block;
  margin: 0;
  padding: 0;
}

.mixed-content .markdown-content:not(:last-child) {
  margin-bottom: 0.3em;
}

/* Inline markdown content styling */
.mixed-content span.markdown-content {
  display: inline;
  margin: 0;
  padding: 0;
}

.mixed-content span.markdown-content:not(:last-child) {
  margin-bottom: 0;
}

/* Remove margins for inline headers and paragraphs */
.mixed-content span.markdown-content span {
  margin: 0;
  display: inline;
}
`;
