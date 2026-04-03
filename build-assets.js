const fs = require('fs/promises');
const path = require('path');

const projectRoot = __dirname;
const outputRoot = path.join(projectRoot, 'public');
const assetsToCopy = [
  'index.html',
  'styles.css',
  'script.js',
  'chat-widget.css',
  'chat-widget.js',
  path.join('pages', 'main.html'),
  path.join('pages', 'settings.html'),
  path.join('pages', 'admin.html'),
  path.join('pages', 'highlights.html'),
  path.join('pages', 'thread.html')
];

async function copyAsset(relativePath) {
  const sourcePath = path.join(projectRoot, relativePath);
  const targetPath = path.join(outputRoot, relativePath);
  await fs.mkdir(path.dirname(targetPath), { recursive: true });
  await fs.copyFile(sourcePath, targetPath);
}

async function main() {
  await fs.mkdir(outputRoot, { recursive: true });
  await Promise.all(assetsToCopy.map(copyAsset));
}

main().catch((error) => {
  console.error('Failed to build worker assets:', error);
  process.exitCode = 1;
});