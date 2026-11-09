import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon, type IconName } from '../shared/icon';
import { Reveal } from '../shared/reveal';

@Component({
  selector: 'app-features',
  imports: [Icon, Reveal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  templateUrl: './features.html',
  styleUrl: './features.scss',
})
export class Features {
  protected readonly i18n = inject(I18n);

  protected icon(name: string): IconName {
    return name as IconName;
  }

  /** Efeito de luz que segue o rato dentro de cada cartão. */
  protected spot(ev: PointerEvent): void {
    const el = ev.currentTarget as HTMLElement;
    const r = el.getBoundingClientRect();
    el.style.setProperty('--mx', `${ev.clientX - r.left}px`);
    el.style.setProperty('--my', `${ev.clientY - r.top}px`);
  }
}
