import React, { useEffect } from "react";
import { createPortal } from "react-dom";
import { Download } from "lucide-react";
import { cn } from "../../../../lib/utils/shared-utils";
import { useFileUrl } from "../../../../hooks/file-handling/useFileUrl";
import {
  createDownloadLink,
  formatFileSize,
  hasExtension,
  isSafeFileUrl,
  parseCurrentVoiceNoteFilename,
} from "../../../../lib/utils/file-utils";
import { AUDIO_EXTENSIONS, IMAGE_EXTENSIONS, VIDEO_EXTENSIONS } from "../../../../lib/constants";
import type { Message } from "../types";
import { MaterialFileIcon } from "../../../ui/MaterialFileIcon";
import type { SecureDB } from '../../../../lib/database/secureDB';

interface FileContentProps {
  readonly message: Message;
  readonly secureDB: SecureDB;
  readonly onRendered: () => void;
  readonly loadFile: boolean;
}

export const FileContent: React.FC<FileContentProps> = ({
  message,
  secureDB,
  onRendered,
  loadFile,
}) => {
  const { filename, fileSize, mimeType } = message;
  const [imageError, setImageError] = React.useState(false);
  const [videoError, setVideoError] = React.useState(false);
  const [audioError, setAudioError] = React.useState(false);
  const [lightboxOpen, setLightboxOpen] = React.useState(false);
  const [imageLoaded, setImageLoaded] = React.useState(false);
  const [downloadRequested, setDownloadRequested] = React.useState(false);
  const [mediaRequested, setMediaRequested] = React.useState(false);
  const pendingDownloadRef = React.useRef(false);
  const onRenderedRef = React.useRef(onRendered);
  onRenderedRef.current = onRendered;

  const normalizedMimeType = typeof mimeType === 'string' ? mimeType.trim().toLowerCase() : '';
  const isVoiceNote = parseCurrentVoiceNoteFilename(filename) !== null;
  const imageByExtension = hasExtension(filename || "", IMAGE_EXTENSIONS);
  const audioByExtension = hasExtension(filename || "", AUDIO_EXTENSIONS) && !isVoiceNote;
  const videoByExtension = hasExtension(filename || "", VIDEO_EXTENSIONS);
  const mediaKind = normalizedMimeType.startsWith('image/')
    ? 'image'
    : normalizedMimeType.startsWith('video/')
      ? 'video'
      : normalizedMimeType.startsWith('audio/') && !isVoiceNote
        ? 'audio'
        : imageByExtension
          ? 'image'
          : audioByExtension
            ? 'audio'
            : videoByExtension
              ? 'video'
              : 'generic';
  const isImageFile = mediaKind === 'image';
  const isVideoFile = mediaKind === 'video';
  const isAudioFile = mediaKind === 'audio';
  const isGenericFile = !isImageFile && !isVideoFile && !isAudioFile;

  useEffect(() => {
    onRenderedRef.current();
  }, [message.id]);

  const previewKind = mediaRequested && !downloadRequested
    ? isImageFile
      ? 'image'
      : isVideoFile
        ? 'video'
        : isAudioFile
          ? 'audio'
          : undefined
    : undefined;

  const { url: resolvedFileUrl, error: fileLoadError } = useFileUrl({
    secureDB,
    fileId: message.id,
    mimeType: mimeType || 'application/octet-stream',
    enabled: loadFile && (mediaRequested || downloadRequested),
    previewKind,
  });
  const effectiveFileUrl = isSafeFileUrl(resolvedFileUrl);

  useEffect(() => {
    if (!effectiveFileUrl) return;
    setImageError(false);
    setVideoError(false);
    setAudioError(false);
    setImageLoaded(false);
  }, [effectiveFileUrl]);

  const sizeLabel = formatFileSize(fileSize ?? 0);
  const downloadFile = () => {
    if (effectiveFileUrl) {
      createDownloadLink(effectiveFileUrl, filename || 'download');
      return;
    }
    pendingDownloadRef.current = true;
    setDownloadRequested(true);
  };

  useEffect(() => {
    if (!effectiveFileUrl || !pendingDownloadRef.current) return;
    pendingDownloadRef.current = false;
    createDownloadLink(effectiveFileUrl, filename || 'download');
    setDownloadRequested(false);
  }, [effectiveFileUrl, filename]);

  useEffect(() => {
    if (!fileLoadError || !pendingDownloadRef.current) return;
    pendingDownloadRef.current = false;
    setDownloadRequested(false);
  }, [fileLoadError]);

  const fileCard = (children: React.ReactNode, onClick?: () => void, label?: string) => (
    <div
      className="qorc-file-card"
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      aria-label={onClick ? label : undefined}
      title={onClick ? label : undefined}
      onClick={onClick}
      onKeyDown={onClick ? (event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          onClick();
        }
      } : undefined}
    >
      <MaterialFileIcon fileName={filename} className="qorc-file-card-icon" />
      {children}
    </div>
  );

  const mediaCard = (onOpen: () => void, label: string) => (
    <div className="qorc-file-card qorc-file-media-card">
      <button
        type="button"
        className="qorc-file-preview-trigger"
        onClick={onOpen}
        aria-label={label}
        title={label}
      >
        <MaterialFileIcon fileName={filename} className="qorc-file-card-icon" />
        <span className="qorc-file-meta">
          <span className="qorc-file-name" title={filename}>{filename || 'File'}</span>
          <span className="qorc-file-size">{sizeLabel}</span>
        </span>
      </button>
      <button
        type="button"
        className="qorc-file-dl"
        onClick={downloadFile}
        disabled={downloadRequested}
        aria-label="Download file"
        title="Download file"
      >
        <Download className="w-[18px] h-[18px]" aria-hidden="true" />
      </button>
    </div>
  );

  return (
    <>
      {!isGenericFile && (!mediaRequested || (!effectiveFileUrl && !fileLoadError)) && mediaCard(
        () => setMediaRequested(true),
        `Open ${mediaKind} preview`,
      )}

      {!isGenericFile && mediaRequested && fileLoadError && mediaCard(
        downloadFile,
        'Download file',
      )}

      {isImageFile && mediaRequested && effectiveFileUrl && (
        <>
          {!imageError ? (
            <div
              className="qorc-file-image group"
              onClick={() => setLightboxOpen(true)}
              role="button"
              tabIndex={0}
              onKeyDown={(event) => { if (event.key === 'Enter') setLightboxOpen(true); }}
              title="Click to expand"
            >
              {!imageLoaded && <div className="qorc-file-image-skeleton animate-pulse" />}
              <img
                src={effectiveFileUrl || undefined}
                alt={filename}
                className={cn("qorc-file-image-img", imageLoaded ? "opacity-100" : "opacity-0")}
                draggable={false}
                onLoad={() => { setImageLoaded(true); onRendered?.(); }}
                onError={() => { setImageError(true); setImageLoaded(true); onRendered?.(); }}
              />
            </div>
          ) : (
            <div className="qorc-file-error">Image cannot be loaded</div>
          )}

          {lightboxOpen && effectiveFileUrl && createPortal(
            <div
              className="fixed inset-0 flex items-center justify-center bg-black/80"
              style={{ zIndex: 9999 }}
              onClick={() => setLightboxOpen(false)}
              onContextMenu={(event) => { event.preventDefault(); event.stopPropagation(); }}
            >
              <img
                src={effectiveFileUrl}
                alt={filename}
                className="object-contain select-none pointer-events-none rounded-lg"
                style={{ maxWidth: '92vw', maxHeight: '92vh' }}
                draggable={false}
              />
            </div>,
            document.body
          )}
        </>
      )}

      {isVideoFile && mediaRequested && effectiveFileUrl && (
        !videoError ? (
          <div className="qorc-file-media">
            <video
              controls
              preload="none"
              src={effectiveFileUrl}
              className="qorc-file-video"
              onError={() => setVideoError(true)}
            />
            <div className="qorc-file-media-foot">
              <MaterialFileIcon fileName={filename} className="qorc-file-media-icon" />
              <div className="qorc-file-meta">
                <span className="qorc-file-name" title={filename}>{filename}</span>
                <span className="qorc-file-size">{sizeLabel}</span>
              </div>
            </div>
          </div>
        ) : (
          <div className="qorc-file-error">Video cannot be loaded</div>
        )
      )}

      {isAudioFile && mediaRequested && effectiveFileUrl && (
        !audioError ? (
          fileCard(
            <div className="qorc-file-meta">
              <span className="qorc-file-name" title={filename}>{filename}</span>
              <audio
                controls
                preload="none"
                src={effectiveFileUrl}
                className="qorc-file-audio"
                onError={() => setAudioError(true)}
              />
              <span className="qorc-file-size">{sizeLabel}</span>
            </div>
          )
        ) : (
          <div className="qorc-file-error">Audio cannot be loaded</div>
        )
      )}

      {isGenericFile && fileCard(
        <>
          <div className="qorc-file-meta">
            <span className="qorc-file-name" title={filename}>{filename || 'File'}</span>
            <span className="qorc-file-size">{sizeLabel}</span>
          </div>
          <div className="qorc-file-dl" aria-hidden="true"><Download className="w-[18px] h-[18px]" /></div>
        </>,
        downloadFile,
        'Download file',
      )}
    </>
  );
};
