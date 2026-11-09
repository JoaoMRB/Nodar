import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { LiveDemo } from '../demo/live-demo';
import { Icon } from '../shared/icon';
import { Reveal } from '../shared/reveal';

@Component({
  selector: 'app-demo-section',
  imports: [LiveDemo, Icon, Reveal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @let d = i18n.t().demo;
    <section class="section" id="demo">
      <div class="glow" aria-hidden="true"></div>
      <div class="container">
        <div class="section-head" appReveal>
          <div class="eyebrow"><span class="dot"></span>{{ d.eyebrow }}</div>
          <h2>{{ d.title }}</h2>
          <p>{{ d.subtitle }}</p>
        </div>
        <div class="wrap" appReveal="120">
          <app-live-demo />
        </div>
        <p class="hint"><app-icon name="info" />{{ d.hint }} · {{ i18n.t().footer.disclaimer }}</p>
      </div>
    </section>
  `,
  styles: `
    :host { display: block; }
    .glow {
      position: absolute; left: 50%; top: 30%; width: min(1100px, 100%); height: 700px;
      transform: translateX(-50%); pointer-events: none;
      background: radial-gradient(50% 50% at 50% 50%, rgba(124,108,255,.22), rgba(76,141,255,.08) 50%, transparent 75%);
      filter: blur(40px);
    }
    .wrap { position: relative; max-width: 1180px; margin: 0 auto; }
    .hint {
      display: flex; align-items: flex-start; justify-content: center; gap: 8px; max-width: 760px;
      margin: 20px auto 0; color: var(--text-3); font-size: 13px; text-align: center;
    }
    .hint app-icon { margin-top: 3px; flex: none; }
  `,
})
export class DemoSection {
  protected readonly i18n = inject(I18n);
}
