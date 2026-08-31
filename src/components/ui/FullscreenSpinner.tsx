import { LoaderCircle } from 'lucide-react';
import { QorcBrandLogo } from './QorcBrandLogo';

export function FullscreenSpinner() {
  return (
    <div className="qorc-fullscreen-spinner" role="status" aria-label="Loading">
      <QorcBrandLogo
        className="qorc-fullscreen-spinner-logo"
        imageClassName="qorc-fullscreen-spinner-logo-image"
      />
      <LoaderCircle className="qorc-fullscreen-spinner-mark" aria-hidden="true" />
    </div>
  );
}
