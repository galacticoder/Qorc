import React, { useEffect } from "react";
import { createPortal } from "react-dom";
import { Download, Film, Image as ImageIcon, LoaderCircle, Play } from "lucide-react";
import { cn } from "../../../../lib/utils/shared-utils";
import { useFileUrl } from "../../../../hooks/file-handling/useFileUrl";
import {
  createDownloadLink,
  formatFileSize,
  hasExtension,
  isSafeFileUrl,
} from "../../../../lib/utils/file-utils";
import { AUDIO_EXTENSIONS, IMAGE_EXTENSIONS, VIDEO_EXTENSIONS } from "../../../../lib/constants";
import type { Message } from "../types";

interface FileContentProps {
  readonly message: Message;
  readonly secureDB?: any;
  readonly onRendered?: () => void;
  readonly loadFile?: boolean;
}

export const FileContent: React.FC<FileContentProps> = ({
  message,
  secureDB,
  onRendered,
  loadFile = true,
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
  const isVoiceNote = filename?.includes('voice-note') === true;
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
    onRenderedRef.current?.();
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

  const { url: resolvedFileUrl, error: fileLoadError, loading: fileLoading } = useFileUrl({
    secureDB: secureDB || null,
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
      className="qor-file-card"
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
      {children}
    </div>
  );

  const mediaActionIcon = fileLoading && mediaRequested
    ? <LoaderCircle className="w-[18px] h-[18px] animate-spin" />
    : isImageFile
      ? <ImageIcon className="w-[18px] h-[18px]" />
      : isVideoFile
        ? <Film className="w-[18px] h-[18px]" />
        : <Play className="w-[18px] h-[18px]" />;

  const mediaCard = (onClick: () => void, action: React.ReactNode, label: string) => fileCard(
    <>
      <div className="qor-file-meta">
        <span className="qor-file-name" title={filename}>{filename || 'File'}</span>
        <span className="qor-file-size">{sizeLabel}</span>
      </div>
      <div className="qor-file-dl" aria-hidden="true">{action}</div>
    </>,
    onClick,
    label,
  );

  return (
    <>
      {!isGenericFile && (!mediaRequested || (!effectiveFileUrl && !fileLoadError)) && mediaCard(
        () => setMediaRequested(true),
        mediaActionIcon,
        `Open ${mediaKind} preview`,
      )}

      {!isGenericFile && mediaRequested && fileLoadError && mediaCard(
        downloadFile,
        <Download className="w-[18px] h-[18px]" />,
        'Download file',
      )}

      {isImageFile && mediaRequested && effectiveFileUrl && (
        <>
          {!imageError ? (
            <div
              className="qor-file-image group"
              onClick={() => setLightboxOpen(true)}
              role="button"
              tabIndex={0}
              onKeyDown={(event) => { if (event.key === 'Enter') setLightboxOpen(true); }}
              title="Click to expand"
            >
              {!imageLoaded && <div className="qor-file-image-skeleton animate-pulse" />}
              <img
                src={effectiveFileUrl || undefined}
                alt={filename}
                className={cn("qor-file-image-img", imageLoaded ? "opacity-100" : "opacity-0")}
                draggable={false}
                onLoad={() => { setImageLoaded(true); onRendered?.(); }}
                onError={() => { setImageError(true); setImageLoaded(true); onRendered?.(); }}
              />
            </div>
          ) : (
            <div className="qor-file-error">Image cannot be loaded</div>
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
          <div className="qor-file-media">
            <video
              controls
              preload="none"
              src={effectiveFileUrl}
              className="qor-file-video"
              onError={() => setVideoError(true)}
            />
            <div className="qor-file-media-foot">
              <span className="qor-file-name" title={filename}>{filename}</span>
              <span className="qor-file-size">{sizeLabel}</span>
            </div>
          </div>
        ) : (
          <div className="qor-file-error">Video cannot be loaded</div>
        )
      )}

      {isAudioFile && mediaRequested && effectiveFileUrl && (
        !audioError ? (
          fileCard(
            <div className="qor-file-meta">
              <span className="qor-file-name" title={filename}>{filename}</span>
              <audio
                controls
                preload="none"
                src={effectiveFileUrl}
                className="qor-file-audio"
                onError={() => setAudioError(true)}
              />
              <span className="qor-file-size">{sizeLabel}</span>
            </div>
          )
        ) : (
          <div className="qor-file-error">Audio cannot be loaded</div>
        )
      )}

      {isGenericFile && fileCard(
        <>
          <div className="qor-file-meta">
            <span className="qor-file-name" title={filename}>{filename || 'File'}</span>
            <span className="qor-file-size">{sizeLabel}</span>
          </div>
          <div className="qor-file-dl" aria-hidden="true"><Download className="w-[18px] h-[18px]" /></div>
        </>,
        downloadFile,
        'Download file',
      )}
    </>
  );
};
