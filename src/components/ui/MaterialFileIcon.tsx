import {
  MATERIAL_FILE_ICON_DEFAULT,
  MATERIAL_FILE_ICON_EXTENSIONS,
  MATERIAL_FILE_ICON_LIGHT_EXTENSIONS,
  MATERIAL_FILE_ICON_LIGHT_NAMES,
  MATERIAL_FILE_ICON_NAMES,
  MATERIAL_FILE_ICON_URLS,
} from '../../data/material-file-icons.generated';

interface MaterialFileIconProps {
  readonly fileName?: string | null;
  readonly className?: string;
}

interface ResolvedMaterialFileIcon {
  readonly baseUrl: string;
  readonly lightUrl: string;
}

const extensionCandidates = (fileName: string): string[] => {
  const candidates: string[] = [];
  let dotIndex = fileName.indexOf('.');
  while (dotIndex >= 0 && dotIndex < fileName.length - 1) {
    candidates.push(fileName.slice(dotIndex + 1));
    dotIndex = fileName.indexOf('.', dotIndex + 1);
  }
  return candidates;
};

const resolveIconId = (
  fileName: string,
  names: Readonly<Record<string, string>>,
  extensions: Readonly<Record<string, string>>,
): string | undefined => {
  const exact = names[fileName];
  if (exact) return exact;
  for (const extension of extensionCandidates(fileName)) {
    const iconId = extensions[extension];
    if (iconId) return iconId;
  }
  return undefined;
};

export const resolveMaterialFileIcon = (rawFileName?: string | null): ResolvedMaterialFileIcon => {
  const normalizedPath = typeof rawFileName === 'string'
    ? rawFileName.trim().replaceAll('\\', '/').toLowerCase()
    : '';
  const fileName = normalizedPath.split('/').pop() || '';
  const baseIconId = resolveIconId(fileName, MATERIAL_FILE_ICON_NAMES, MATERIAL_FILE_ICON_EXTENSIONS)
    || MATERIAL_FILE_ICON_DEFAULT;
  const lightIconId = resolveIconId(
    fileName,
    MATERIAL_FILE_ICON_LIGHT_NAMES,
    MATERIAL_FILE_ICON_LIGHT_EXTENSIONS,
  ) || baseIconId;
  const fallbackUrl = MATERIAL_FILE_ICON_URLS[MATERIAL_FILE_ICON_DEFAULT];
  return {
    baseUrl: MATERIAL_FILE_ICON_URLS[baseIconId] || fallbackUrl,
    lightUrl: MATERIAL_FILE_ICON_URLS[lightIconId] || MATERIAL_FILE_ICON_URLS[baseIconId] || fallbackUrl,
  };
};

export function MaterialFileIcon({ fileName, className }: MaterialFileIconProps) {
  const { baseUrl, lightUrl } = resolveMaterialFileIcon(fileName);
  const hasLightVariant = lightUrl !== baseUrl;
  const rootClassName = [
    'qorc-material-file-icon',
    hasLightVariant ? 'has-light-variant' : '',
    className || '',
  ].filter(Boolean).join(' ');

  return (
    <span className={rootClassName} aria-hidden="true">
      <img className="qorc-material-file-icon-base" src={baseUrl} alt="" draggable={false} />
      {hasLightVariant && (
        <img className="qorc-material-file-icon-light" src={lightUrl} alt="" draggable={false} />
      )}
    </span>
  );
}
