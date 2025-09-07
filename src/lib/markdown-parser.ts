/**
 * Simple markdown delimiter detection for chat messages
 * Uses react-markdown for actual parsing
 */

/**
 * Check if a message contains markdown formatting delimiters
 * More flexible detection - handles spacing and mixed content
 */
export function isMarkdownMessage(content: string): boolean {
  // 1) Explicit markdown block using {{{ ... }}}
  const explicitBlockPattern = /\{\{\{([\s\S]*?)\}\}\}/;
  if (explicitBlockPattern.test(content)) return true;

  // 2) Heuristic detection for typical Markdown/README indicators
  const text = content || "";
  const hasCodeFence = /(^|\n)```/.test(text) || /(^|\n)~~~/.test(text);
  const hasHeading = /(^|\n)#{1,6}\s+\S/.test(text);
  const hasList = /(^|\n)(?:-|\*|\+)\s+\S/.test(text) || /(^|\n)\d+\.\s+\S/.test(text);
  const hasLink = /\[[^\]]+\]\([^\)]+\)/.test(text);
  const hasBlockquote = /(^|\n)>\s+\S/.test(text);
  const hasTable = /(^|\n)\|[^\n]+\|\n\|[\s:|-]+\|/.test(text); // GFM table header

  // Consider longer multi-line content with any strong markdown signal as markdown
  const lineCount = text.split('\n').length;
  const isLongForm = text.length > 240 || lineCount > 6;

  return (
    hasCodeFence ||
    hasHeading ||
    hasTable ||
    (isLongForm && (hasList || hasLink || hasBlockquote))
  );
}

/**
 * Parse mixed content into segments of plain text and markdown blocks
 */
export function parseMixedContent(content: string): Array<{type: 'text' | 'markdown', content: string, hasOriginalNewlines?: boolean}> {
  const segments: Array<{type: 'text' | 'markdown', content: string, hasOriginalNewlines?: boolean}> = [];
  const markdownPattern = /\{\{\{([\s\S]*?)\}\}\}/g;
  
  let lastIndex = 0;
  let match;
  
  while ((match = markdownPattern.exec(content)) !== null) {
    // Add any text before this markdown block
    if (match.index > lastIndex) {
      const textContent = content.slice(lastIndex, match.index);
      if (textContent.length > 0) {
        segments.push({ type: 'text', content: textContent });
      }
    }
    
    // Add the markdown block
    const originalMarkdownContent = match[1]; // Keep original before trimming
    const hasOriginalNewlines = originalMarkdownContent.includes('\n');
    
    let markdownContent = originalMarkdownContent.trim();
    
    // Apply the same cleaning logic as extractMarkdownContent
    markdownContent = markdownContent.replace(/^(#{1,6})([^\s#])/gm, '$1 $2');
    
    if (markdownContent.startsWith('\n')) {
      const lines = markdownContent.split('\n');
      lines.shift();
      
      const nonEmptyLines = lines.filter(line => line.trim() !== '');
      if (nonEmptyLines.length > 0) {
        const minIndent = Math.min(...nonEmptyLines.map(line => {
          const match = line.match(/^(\s*)/);
          return match ? match[1].length : 0;
        }));
        
        if (minIndent > 0) {
          const dedentedLines = lines.map(line => {
            if (line.trim() === '') return line;
            return line.slice(minIndent);
          });
          markdownContent = dedentedLines.join('\n');
        } else {
          markdownContent = lines.join('\n');
        }
      }
    }
    
    segments.push({ type: 'markdown', content: markdownContent.trim(), hasOriginalNewlines });
    lastIndex = match.index + match[0].length;
  }
  
  // Add any remaining text after the last markdown block
  if (lastIndex < content.length) {
    const textContent = content.slice(lastIndex);
    if (textContent.length > 0) {
      segments.push({ type: 'text', content: textContent });
    }
  }
  
  return segments;
}

/**
 * Check if content has mixed content (both text and markdown blocks)
 */
export function hasMixedContent(content: string): boolean {
  const segments = parseMixedContent(content);
  return segments.length > 1 || (segments.length === 1 && segments[0].type === 'markdown' && /\{\{\{[\s\S]*?\}\}\}/.test(content));
}

/**
 * Extract markdown content from {{{ }}} delimiters
 * Handles flexible spacing and extracts the first markdown block found
 */
export function extractMarkdownContent(content: string): string {
  // Find the first {{{ }}} block in the message
  const markdownPattern = /\{\{\{([\s\S]*?)\}\}\}/;
  const match = content.match(markdownPattern);
  
  if (!match) {
    // No explicit block; return original content while also attempting
    // to gently de-indent common-leading whitespace for multi-line pastes.
    const lines = content.split('\n');
    if (lines.length <= 1) return content;

    const nonEmpty = lines.filter(l => l.trim() !== '');
    if (nonEmpty.length === 0) return content.trim();

    const minIndent = Math.min(
      ...nonEmpty.map(l => (l.match(/^(\s*)/)?.[1].length) || 0)
    );
    if (minIndent > 0) {
      return lines
        .map(l => (l.trim() === '' ? l : l.slice(minIndent)))
        .join('\n')
        .trim();
    }
    return content.trim();
  }
  
  // Extract and clean up the content between the delimiters
  let extractedContent = match[1];
  
  // Clean up the content:
  // 1. Remove leading/trailing whitespace
  extractedContent = extractedContent.trim();
  
  // 2. Fix common markdown formatting issues
  // Add missing spaces after # symbols for headers
  extractedContent = extractedContent.replace(/^(#{1,6})([^\s#])/gm, '$1 $2');
  
  // 3. If it starts with a newline, normalize the indentation
  if (extractedContent.startsWith('\n')) {
    const lines = extractedContent.split('\n');
    // Remove first empty line
    lines.shift();
    
    // Find minimum indentation (ignoring empty lines)
    const nonEmptyLines = lines.filter(line => line.trim() !== '');
    if (nonEmptyLines.length > 0) {
      const minIndent = Math.min(...nonEmptyLines.map(line => {
        const match = line.match(/^(\s*)/);
        return match ? match[1].length : 0;
      }));
      
      // Remove common indentation
      if (minIndent > 0) {
        const dedentedLines = lines.map(line => {
          if (line.trim() === '') return line; // Keep empty lines as-is
          return line.slice(minIndent);
        });
        extractedContent = dedentedLines.join('\n');
      } else {
        extractedContent = lines.join('\n');
      }
    }
  }
  
  return extractedContent.trim();
}
