const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const packageRoot = path.dirname(require.resolve('material-icon-theme/package.json'));
const packageJson = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
const manifest = JSON.parse(fs.readFileSync(path.join(packageRoot, 'dist', 'material-icons.json'), 'utf8'));
const iconsRoot = path.join(packageRoot, 'icons');
const outputPath = path.join(repoRoot, 'src', 'data', 'material-file-icons.generated.ts');

const fileExtensions = manifest.fileExtensions || {};
const fileNames = manifest.fileNames || {};
const lightFileExtensions = manifest.light?.fileExtensions || {};
const lightFileNames = manifest.light?.fileNames || {};
const iconIds = new Set([
  manifest.file,
  ...Object.values(fileExtensions),
  ...Object.values(fileNames),
  ...Object.values(lightFileExtensions),
  ...Object.values(lightFileNames),
].filter(Boolean));

const icons = [...iconIds].sort().map((iconId, index) => {
  const definition = manifest.iconDefinitions?.[iconId];
  if (!definition || typeof definition.iconPath !== 'string') {
    throw new Error(`Material file icon definition is missing: ${iconId}`);
  }
  const iconPath = path.resolve(packageRoot, 'dist', definition.iconPath);
  const relativePath = path.relative(iconsRoot, iconPath);
  if (!relativePath || relativePath.startsWith('..') || path.isAbsolute(relativePath)) {
    throw new Error(`Material file icon path is invalid: ${definition.iconPath}`);
  }
  if (!fs.statSync(iconPath, { throwIfNoEntry: false })?.isFile()) {
    throw new Error(`Material file icon asset is missing: ${relativePath}`);
  }
  return {
    iconId,
    importName: `materialFileIcon${index}`,
    importPath: `material-icon-theme/icons/${relativePath.split(path.sep).join('/')}?url`,
  };
});

const imports = icons
  .map(({ importName, importPath }) => `import ${importName} from ${JSON.stringify(importPath)};`)
  .join('\n');
const iconUrls = Object.fromEntries(icons.map(({ iconId, importName }) => [iconId, importName]));
const iconUrlSource = Object.entries(iconUrls)
  .map(([iconId, importName]) => `  ${JSON.stringify(iconId)}: ${importName},`)
  .join('\n');

const source = `${imports}

export const MATERIAL_FILE_ICON_VERSION = ${JSON.stringify(packageJson.version)};
export const MATERIAL_FILE_ICON_DEFAULT = ${JSON.stringify(manifest.file || 'file')};
export const MATERIAL_FILE_ICON_EXTENSIONS: Readonly<Record<string, string>> = ${JSON.stringify(fileExtensions, null, 2)};
export const MATERIAL_FILE_ICON_NAMES: Readonly<Record<string, string>> = ${JSON.stringify(fileNames, null, 2)};
export const MATERIAL_FILE_ICON_LIGHT_EXTENSIONS: Readonly<Record<string, string>> = ${JSON.stringify(lightFileExtensions, null, 2)};
export const MATERIAL_FILE_ICON_LIGHT_NAMES: Readonly<Record<string, string>> = ${JSON.stringify(lightFileNames, null, 2)};
export const MATERIAL_FILE_ICON_URLS: Readonly<Record<string, string>> = {
${iconUrlSource}
};
`;

const previous = fs.statSync(outputPath, { throwIfNoEntry: false })?.isFile()
  ? fs.readFileSync(outputPath, 'utf8')
  : '';
if (previous !== source) fs.writeFileSync(outputPath, source);
