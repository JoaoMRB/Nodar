export const REPO = 'https://github.com/JoaoMRB/Nodar';
export const RELEASES = `${REPO}/releases`;
export const LATEST_EXE = `${REPO}/releases/latest`;
export const ISSUES = `${REPO}/issues`;
export const LICENSE = `${REPO}/blob/main/LICENSE`;
export const README = (lang: 'pt' | 'en') => `${REPO}/blob/main/${lang === 'pt' ? 'README.md' : 'README.en.md'}`;
