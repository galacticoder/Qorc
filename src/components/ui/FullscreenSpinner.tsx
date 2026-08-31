import { LoaderCircle } from 'lucide-react';
import { QorBrandLogo } from './QorBrandLogo';

export function FullscreenSpinner() {
  return (
    <div className="qor-fullscreen-spinner" role="status" aria-label="Loading">
      <QorBrandLogo
        className="qor-fullscreen-spinner-logo"
        imageClassName="qor-fullscreen-spinner-logo-image"
      />
      <LoaderCircle className="qor-fullscreen-spinner-mark" aria-hidden="true" />
    </div>
  );
}
