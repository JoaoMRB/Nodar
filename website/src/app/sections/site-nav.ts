import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon } from '../shared/icon';
import { REPO } from '../shared/links';

@Component({
  selector: 'app-site-nav',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { '(window:scroll)': 'onScroll()' },
  template: `
    @let n = i18n.t().nav;
    <header class="bar" [class.scrolled]="scrolled()" [class.open]="open()">
      <div class="inner">
        <a class="logo" href="#top" (click)="open.set(false)">
          <img src="img/nodar-64.png" alt="" width="28" height="28" />
          <span>Nodar</span>
        </a>

        <nav class="links" [attr.aria-label]="n.menu">
          <a href="#demo" (click)="open.set(false)">{{ n.demo }}</a>
          <a href="#features" (click)="open.set(false)">{{ n.features }}</a>
          <a href="#how" (click)="open.set(false)">{{ n.how }}</a>
          <a href="#privacy" (click)="open.set(false)">{{ n.privacy }}</a>
          <a href="#install" (click)="open.set(false)">{{ n.install }}</a>
        </nav>

        <div class="right">
          <div class="lang" role="group" [attr.aria-label]="n.language">
            <button type="button" [class.on]="i18n.lang() === 'pt'" [attr.aria-pressed]="i18n.lang() === 'pt'" (click)="i18n.lang.set('pt')">PT</button>
            <button type="button" [class.on]="i18n.lang() === 'en'" [attr.aria-pressed]="i18n.lang() === 'en'" (click)="i18n.lang.set('en')">EN</button>
            <span class="thumb" [class.right]="i18n.lang() === 'en'"></span>
          </div>
          <a class="gh" [href]="repo" target="_blank" rel="noopener" [attr.aria-label]="n.github">
            <app-icon name="github" />
            <span>GitHub</span>
          </a>
          <button type="button" class="burger" [attr.aria-label]="n.menu" [attr.aria-expanded]="open()" (click)="open.set(!open())">
            <app-icon [name]="open() ? 'close' : 'menu'" />
          </button>
        </div>
      </div>
    </header>
  `,
  styleUrl: './site-nav.scss',
})
export class SiteNav {
  protected readonly i18n = inject(I18n);
  protected readonly repo = REPO;
  protected readonly scrolled = signal(false);
  protected readonly open = signal(false);

  protected onScroll(): void {
    const s = window.scrollY > 24;
    if (s !== this.scrolled()) this.scrolled.set(s);
  }
}
