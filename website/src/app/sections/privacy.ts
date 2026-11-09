import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon } from '../shared/icon';
import { Reveal } from '../shared/reveal';

@Component({
  selector: 'app-privacy',
  imports: [Icon, Reveal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @let p = i18n.t().privacy;
    <section class="section" id="privacy">
      <div class="container">
        <div class="section-head" appReveal>
          <div class="eyebrow"><span class="dot"></span>{{ p.eyebrow }}</div>
          <h2>{{ p.title }}</h2>
          <p>{{ p.subtitle }}</p>
        </div>

        <div class="grid">
          <div class="col stay glass" appReveal>
            <div class="head">
              <div class="badge ok"><app-icon name="lock" /></div>
              <h3>{{ p.stayTitle }}</h3>
            </div>
            <ul class="list">
              @for (s of p.stay; track s) {
                <li><app-icon name="check" [stroke]="2.2" />{{ s }}</li>
              }
            </ul>
            <div class="pc" aria-hidden="true">
              <div class="pc-ring"></div>
              <div class="pc-core"><app-icon name="computer" /></div>
            </div>
          </div>

          <div class="col leave glass" appReveal="120">
            <div class="head">
              <div class="badge out"><app-icon name="arrowOut" /></div>
              <h3>{{ p.leaveTitle }}</h3>
            </div>
            <ul class="flows">
              @for (f of p.leave; track f.where) {
                <li>
                  <div class="flow-what">
                    <strong>{{ f.what }}</strong>
                    <code>{{ f.ex }}</code>
                  </div>
                  <span class="arrow" aria-hidden="true"><i></i></span>
                  <span class="where">{{ f.where }}</span>
                </li>
              }
            </ul>
          </div>
        </div>

        <p class="foot" appReveal><app-icon name="shieldCheck" />{{ p.footnote }}</p>
      </div>
    </section>
  `,
  styleUrl: './privacy.scss',
})
export class Privacy {
  protected readonly i18n = inject(I18n);
}
