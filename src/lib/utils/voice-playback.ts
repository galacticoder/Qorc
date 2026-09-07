let activeVoiceAudio: HTMLAudioElement | null = null;

export function registerVoicePlayback(audio: HTMLAudioElement): () => void {
  const handlePlay = () => {
    if (audio.paused) return;
    const previous = activeVoiceAudio;
    activeVoiceAudio = audio;
    if (previous && previous !== audio) previous.pause();
  };
  const handlePause = () => {
    if (audio.paused && activeVoiceAudio === audio) activeVoiceAudio = null;
  };
  const stop = () => {
    audio.pause();
    if (activeVoiceAudio === audio) activeVoiceAudio = null;
  };

  audio.addEventListener('play', handlePlay);
  audio.addEventListener('pause', handlePause);
  audio.addEventListener('ended', handlePause);
  audio.addEventListener('error', stop);

  return () => {
    audio.removeEventListener('play', handlePlay);
    audio.removeEventListener('pause', handlePause);
    audio.removeEventListener('ended', handlePause);
    audio.removeEventListener('error', stop);
    stop();
  };
}
