import { ChangeDetectionStrategy, Component, DestroyRef, inject, signal } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon, type IconName } from '../shared/icon';
import { Reveal } from '../shared/reveal';
import { RELEASES } from '../shared/links';

@Component({
  selector: 'app-install',
  imports: [Icon, Reveal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @let s = i18n.t().install;
    <section class="section" id="install">
      <div class="container">
        <div class="section-head" appReveal>
          <div class="eyebrow"><span class="dot"></span>{{ s.eyebrow }}</div>
          <h2>{{ s.title }}</h2>
          <p>{{ s.subtitle }}</p>
        </div>

        <div class="layout">
          <div class="options">
            @for (o of s.options; track o.title; let i = $index) {
              <article class="opt glass" [class.main]="i === 0" [appReveal]="i * 90">
                <div class="opt-head">
                  <div class="ico"><app-icon [name]="icon(o.icon)" /></div>
                  <div>
                    <h3>{{ o.title }}</h3>
                    <p>{{ o.text }}</p>
                  </div>
                </div>
                @if (o.code) {
                  <div class="term">
                    <pre><code>{{ o.code }}</code></pre>
                    <button type="button" class="copy" (click)="copy(o.code, i)">
                      <app-icon [name]="copied() === i ? 'check' : 'copy'" />
                      <span>{{ copied() === i ? s.copied : s.copy }}</span>
                    </button>
                  </div>
                }
                @if (o.cta) {
                  <a class="btn btn-primary" [href]="releases" target="_blank" rel="noopener">
                    <app-icon name="download" />{{ o.cta }}
                  </a>
                }
              </article>
            }
          </div>

          <aside class="side">
            <div class="req glass" appReveal>
              <h4>{{ s.reqTitle }}</h4>
              <ul>
                @for (r of s.req; track r; let i = $index) {
                  <li><app-icon [name]="i === 0 ? 'windows' : i === 1 ? 'shieldCheck' : 'chip'" />{{ r }}</li>
                }
              </ul>
            </div>
            <div class="try glass" appReveal="100">
              <div class="try-ico"><app-icon name="sparkle" /></div>
              <h4>{{ s.demoTitle }}</h4>
              <p>{{ s.demoText }}</p>
              <div class="term small">
                <pre><code>{{ s.demoCode }}</code></pre>
                <button type="button" class="copy" (click)="copy(s.demoCode, 99)">
                  <app-icon [name]="copied() === 99 ? 'check' : 'copy'" />
                  <span class="sr-only">{{ s.copy }}</span>
                </button>
              </div>
            </div>
          </aside>
        </div>
      </div>
    </section>
  `,
  styleUrl: './install.scss',
})
export class Install {
  protected readonly i18n = inject(I18n);
  protected readonly releases = RELEASES;
  protected readonly copied = signal<number | null>(null);
  private timer?: ReturnType<typeof setTimeout>;

  constructor() {
    inject(DestroyRef).onDestroy(() => clearTimeout(this.timer));
  }

  protected icon(name: string): IconName {
    return name as IconName;
  }

  protected async copy(text: string, i: number): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      return;
    }
    this.copied.set(i);
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.copied.set(null), 1800);
  }
}
