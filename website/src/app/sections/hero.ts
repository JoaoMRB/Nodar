import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon } from '../shared/icon';
import { LATEST_EXE } from '../shared/links';

@Component({
  selector: 'app-hero',
  imports: [Icon],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './hero.html',
  styleUrl: './hero.scss',
})
export class Hero {
  protected readonly i18n = inject(I18n);
  protected readonly download = LATEST_EXE;

  /** Inclinação ligeira da janela a seguir o rato (desligada em ecrãs tácteis e com movimento reduzido). */
  protected readonly tilt = signal({ x: 0, y: 0 });

  protected onMove(ev: PointerEvent): void {
    if (ev.pointerType !== 'mouse' || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const el = ev.currentTarget as HTMLElement;
    const r = el.getBoundingClientRect();
    const x = (ev.clientX - r.left) / r.width - 0.5;
    const y = (ev.clientY - r.top) / r.height - 0.5;
    this.tilt.set({ x: +(y * -6).toFixed(2), y: +(x * 8).toFixed(2) });
  }

  protected reset(): void {
    this.tilt.set({ x: 0, y: 0 });
  }
}
