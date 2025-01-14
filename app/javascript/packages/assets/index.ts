type AssetPaths = Record<string, string>;

export function getAssetPath(path: string): string | undefined {
  if (!getAssetPath.cache) {
    try {
      const script = document.querySelector('[data-asset-map]') as HTMLScriptElement;
      getAssetPath.cache = JSON.parse(script.textContent!);
    } catch {
      getAssetPath.cache = {};
    }
  }

  return getAssetPath.cache![path];
}

getAssetPath.cache = undefined as AssetPaths | undefined;
