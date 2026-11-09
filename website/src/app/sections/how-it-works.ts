import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon } from '../shared/icon';
import { Reveal } from '../shared/reveal';

@Component({
  selector: 'app-how-it-works',
  imports: [Icon, Reveal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @let h = i18n.t().how;
    <section class="section" id="how">
      <div class="container">
        <div class="section-head" appReveal>
          <div class="eyebrow"><span class="dot"></span>{{ h.eyebrow }}</div>
          <h2>{{ h.title }}</h2>
          <p>{{ h.subtitle }}</p>
        </div>

        <ol class="steps">
          @for (s of h.steps; track s.n; let i = $index) {
            <li class="step glass" [appReveal]="i * 120">
              <span class="n gradient-text">{{ s.n }}</span>
              <h3>{{ s.title }}</h3>
              <p>{{ s.text }}</p>
              <pre class="code"><code>{{ s.code }}</code></pre>
            </li>
          }
        </ol>

        <div class="lower">
          <div class="panel glass" appReveal>
            <h4>{{ h.statusesTitle }}</h4>
            <ul class="statuses">
              @for (st of h.statuses; track st; let i = $index) {
                <li [class]="'s' + i"><span class="sdot"></span>{{ st }}</li>
              }
            </ul>
          </div>
          <div class="panel glass" appReveal="100">
            <h4>{{ h.productsTitle }}</h4>
            <ul class="products">
              @for (p of h.products; track p) {
                <li>{{ p }}</li>
              }
            </ul>
          </div>
        </div>

        <p class="note" appReveal><app-icon name="info" />{{ h.note }}</p>
      </div>
    </section>
  `,
  styleUrl: './how-it-works.scss',
})
export class HowItWorks {
  protected readonly i18n = inject(I18n);
}
