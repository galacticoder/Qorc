import React, { useState, useEffect } from "react";
import { Button } from "../../ui/button";
import { Cross2Icon } from "../icons";
import { cn } from "@/lib/utils";
import * as cm from "../ChatMessage";
import { Message } from "../types";
import { formatFileSize } from "../ChatMessage/FileMessage";
import { Play, Pause } from "lucide-react";

interface ReplyBannerProps {
  replyTo: Message;
  onCancelReply: () => void;
  getDisplayUsername?: (username: string) => Promise<string>;
}

// File type detection helpers
const IMAGE_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'svg', 'ico', 'tiff'];
const VIDEO_EXTENSIONS = ['mp4', 'webm', 'ogg', 'avi', 'mov', 'wmv', 'flv', 'mkv'];
const AUDIO_EXTENSIONS = ['mp3', 'wav', 'ogg', 'webm', 'm4a', 'aac', 'flac'];

const hasExtension = (filename: string, extensions: string[]): boolean => {
  if (!filename) return false;
  const ext = filename.toLowerCase().split('.').pop();
  return ext ? extensions.includes(ext) : false;
};

const isVoiceNote = (message: Message): boolean => {
  return Boolean(
    (message.filename && message.filename.toLowerCase().includes('voice-note')) ||
    (message.mimeType && message.mimeType.startsWith('audio/')) ||
    (message.filename && hasExtension(message.filename, AUDIO_EXTENSIONS))
  );
};

const isImage = (message: Message): boolean => {
  return Boolean(message.filename && hasExtension(message.filename, IMAGE_EXTENSIONS));
};

const isVideo = (message: Message): boolean => {
  return Boolean(message.filename && hasExtension(message.filename, VIDEO_EXTENSIONS));
};

export function ReplyBanner({ replyTo, onCancelReply, getDisplayUsername }: ReplyBannerProps) {
  const [displaySender, setDisplaySender] = useState(replyTo.sender);

  // Load display username
  useEffect(() => {
    if (getDisplayUsername) {
      getDisplayUsername(replyTo.sender)
        .then(setDisplaySender)
        .catch((error) => {
          console.error('Failed to get display username for reply banner:', error);
          setDisplaySender(replyTo.sender);
        });
    }
  }, [replyTo.sender, getDisplayUsername]);
  return (
    <div className="px-4 pt-3 pb-0">
      <div
        className={cn(
          "flex items-start gap-3 p-4 border-l-4 rounded-lg shadow-sm transition-colors duration-200",
          "bg-gradient-to-r from-slate-50 to-slate-100 border-slate-400 text-slate-900"
        )}
      >
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-2">
            <svg
              className={cn("w-4 h-4", "text-slate-500")}
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 10h10a8 8 0 018 8v2M3 10l6 6m-6-6l6-6"
              />
            </svg>
            <span className="text-sm font-semibold text-slate-700">
              {displaySender}
            </span>
          </div>

          {/* Content preview based on message type */}
          {isImage(replyTo) ? (
            <div className="flex items-center gap-3">
              <div className="flex-shrink-0">
                <img
                  src={replyTo.content}
                  alt={replyTo.filename}
                  className="w-12 h-12 object-cover rounded border"
                  onError={(e) => {
                    // Fallback to file icon if image fails to load
                    e.currentTarget.style.display = 'none';
                    e.currentTarget.nextElementSibling!.style.display = 'flex';
                  }}
                />
                <div className="w-12 h-12 bg-slate-200 rounded border items-center justify-center text-slate-500 hidden">
                  🖼️
                </div>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-slate-700 truncate">
                  {replyTo.filename || 'Image'}
                </p>
                <p className="text-xs text-slate-500">
                  {replyTo.fileSize ? formatFileSize(replyTo.fileSize) : 'Image'}
                </p>
              </div>
            </div>
          ) : isVideo(replyTo) ? (
            <div className="flex items-center gap-3">
              <div className="flex-shrink-0 relative">
                <video
                  src={replyTo.content}
                  className="w-12 h-12 object-cover rounded border"
                  muted
                  onError={(e) => {
                    // Fallback to video icon if video fails to load
                    e.currentTarget.style.display = 'none';
                    e.currentTarget.nextElementSibling!.style.display = 'flex';
                  }}
                />
                <div className="w-12 h-12 bg-slate-200 rounded border items-center justify-center text-slate-500 hidden">
                  🎬
                </div>
                <div className="absolute inset-0 flex items-center justify-center">
                  <Play className="w-4 h-4 text-white drop-shadow-lg" />
                </div>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-slate-700 truncate">
                  {replyTo.filename || 'Video'}
                </p>
                <p className="text-xs text-slate-500">
                  {replyTo.fileSize ? formatFileSize(replyTo.fileSize) : 'Video'}
                </p>
              </div>
            </div>
          ) : isVoiceNote(replyTo) ? (
            <div className="flex items-center gap-3">
              <div className="flex-shrink-0">
                <div className="w-12 h-12 bg-blue-100 rounded-full flex items-center justify-center">
                  <div className="w-6 h-6 bg-blue-500 rounded-full flex items-center justify-center">
                    <Play className="w-3 h-3 text-white ml-0.5" />
                  </div>
                </div>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-slate-700">
                  Voice message
                </p>
                <div className="flex items-center gap-1 mt-1">
                  {/* Mini waveform visualization */}
                  <div className="flex items-center gap-0.5">
                    {[...Array(8)].map((_, i) => (
                      <div
                        key={i}
                        className="w-0.5 bg-blue-400 rounded-full"
                        style={{
                          height: `${Math.random() * 8 + 4}px`,
                          opacity: 0.7
                        }}
                      />
                    ))}
                  </div>
                  <span className="text-xs text-slate-500 ml-1">
                    Voice note
                  </span>
                </div>
              </div>
            </div>
          ) : (replyTo.type === 'file' || replyTo.type === 'file-message' || replyTo.filename) ? (
            <div className="flex items-center gap-3">
              <div className="flex-shrink-0">
                <div className="w-12 h-12 bg-slate-200 rounded border flex items-center justify-center text-slate-500">
                  📎
                </div>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-slate-700 truncate">
                  {replyTo.filename || 'File'}
                </p>
                <p className="text-xs text-slate-500">
                  {replyTo.fileSize ? formatFileSize(replyTo.fileSize) : 'Document'}
                </p>
              </div>
            </div>
          ) : (
            <p className="text-sm line-clamp-2 text-slate-600">
              {replyTo.content?.slice(0, 100)}{replyTo.content && replyTo.content.length > 100 ? "..." : ""}
            </p>
          )}
        </div>
        <Button
          variant="ghost"
          size="sm"
          className="h-8 w-8 p-0 transition-colors hover:bg-slate-200 text-slate-500 hover:text-slate-700"
          onClick={onCancelReply}
        >
          <Cross2Icon className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
}