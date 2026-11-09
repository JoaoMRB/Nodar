import { DOCUMENT, Injectable, computed, effect, inject, signal } from '@angular/core';
import { Title, Meta } from '@angular/platform-browser';
import { pt, type Dict } from './pt';
import { en } from './en';

export type Lang = 'pt' | 'en';

const STORAGE_KEY = 'nodar.lang';
const DICTS: Record<Lang, Dict> = { pt, en };

/** Idioma do site: como a app, segue o idioma do sistema e pode ser escolhido. Muda na hora. */
@Injectable({ providedIn: 'root' })
export class I18n {
  private readonly doc = inject(DOCUMENT);
  private readonly title = inject(Title);
  private readonly meta = inject(Meta);

  readonly lang = signal<Lang>(this.initialLang());
  readonly t = computed(() => DICTS[this.lang()]);

  constructor() {
    effect(() => {
      const lang = this.lang();
      const t = DICTS[lang];
      this.doc.documentElement.lang = lang === 'pt' ? 'pt-PT' : 'en';
      this.title.setTitle(t.meta.title);
      this.meta.updateTag({ name: 'description', content: t.meta.description });
      try {
        localStorage.setItem(STORAGE_KEY, lang);
      } catch {
        /* sem armazenamento: o idioma volta a seguir o sistema */
      }
    });
  }

  toggle(): void {
    this.lang.update((l) => (l === 'pt' ? 'en' : 'pt'));
  }

  /** Substitui {0}, {1}… como o Loc.T da app. */
  format(text: string, ...args: (string | number)[]): string {
    return text.replace(/\{(\d+)\}/g, (_, i) => String(args[+i] ?? ''));
  }

  private initialLang(): Lang {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'pt' || saved === 'en') return saved;
    } catch {
      /* ignora */
    }
    const nav = (globalThis.navigator?.languages ?? [globalThis.navigator?.language ?? 'pt']).join(',');
    return /(^|,)pt/i.test(nav) ? 'pt' : 'en';
  }
}
