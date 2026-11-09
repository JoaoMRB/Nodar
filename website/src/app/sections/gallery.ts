import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon } from '../shared/icon';
import { Reveal } from '../shared/reveal';

@Component({
  selector: 'app-gallery',
  imports: [Icon, Reveal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: { '(document:keydown)': 'onKey($event)' },
  template: `
    @let g = i18n.t().gallery;
    <section class="section" id="screens">
      <div class="container">
        <div class="section-head" appReveal>
          <div class="eyebrow"><span class="dot"></span>{{ g.eyebrow }}</div>
          <h2>{{ g.title }}</h2>
          <p>{{ g.subtitle }}</p>
        </div>

        <div class="grid">
          @for (item of g.items; track item.file; let i = $index) {
            <button type="button" class="shot" [appReveal]="(i % 2) * 100" (click)="open.set(i)">
              <div class="img">
                <img [src]="src(item.file)" [alt]="item.caption" loading="lazy" width="1440" height="900" />
              </div>
              <div class="cap">
                <strong>{{ item.title }}</strong>
                <span>{{ item.caption }}</span>
              </div>
              <span class="zoom" aria-hidden="true"><app-icon name="plus" /></span>
            </button>
          }
        </div>
      </div>
    </section>

    @if (current(); as item) {
      <div class="lightbox" role="dialog" aria-modal="true" [attr.aria-label]="item.title" (click)="open.set(null)">
        <figure (click)="$event.stopPropagation()">
          <img [src]="src(item.file)" [alt]="item.caption" />
          <figcaption><strong>{{ item.title }}</strong> · {{ item.caption }}</figcaption>
        </figure>
        <button type="button" class="lb-btn close" [attr.aria-label]="g.close" (click)="open.set(null)"><app-icon name="close" /></button>
        <button type="button" class="lb-btn prev" [attr.aria-label]="g.prev" (click)="step(-1, $event)"><app-icon name="chevron" /></button>
        <button type="button" class="lb-btn next" [attr.aria-label]="g.next" (click)="step(1, $event)"><app-icon name="chevron" /></button>
      </div>
    }
  `,
  styleUrl: './gallery.scss',
})
export class Gallery {
  protected readonly i18n = inject(I18n);
  protected readonly open = signal<number | null>(null);
  protected readonly current = computed(() => {
    const i = this.open();
    return i === null ? null : this.i18n.t().gallery.items[i];
  });

  protected src(file: string): string {
    return `screenshots/${this.i18n.lang()}/${file}.png`;
  }

  protected step(dir: number, ev?: Event): void {
    ev?.stopPropagation();
    const n = this.i18n.t().gallery.items.length;
    const i = this.open();
    if (i !== null) this.open.set((i + dir + n) % n);
  }

  protected onKey(ev: KeyboardEvent): void {
    if (this.open() === null) return;
    if (ev.key === 'Escape') this.open.set(null);
    if (ev.key === 'ArrowRight') this.step(1);
    if (ev.key === 'ArrowLeft') this.step(-1);
  }
}
