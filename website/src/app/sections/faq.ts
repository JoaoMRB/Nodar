import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { I18n } from '../i18n/i18n';
import { Icon } from '../shared/icon';
import { Reveal } from '../shared/reveal';

@Component({
  selector: 'app-faq',
  imports: [Icon, Reveal],
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @let f = i18n.t().faq;
    <section class="section" id="faq">
      <div class="container narrow">
        <div class="section-head" appReveal>
          <div class="eyebrow"><span class="dot"></span>{{ f.eyebrow }}</div>
          <h2>{{ f.title }}</h2>
        </div>
        <div class="list" appReveal>
          @for (item of f.items; track $index) {
            <details class="item" name="faq">
              <summary>
                <span>{{ item.q }}</span>
                <span class="plus"><app-icon name="plus" /></span>
              </summary>
              <p>{{ item.a }}</p>
            </details>
          }
        </div>
      </div>
    </section>
  `,
  styles: `
    :host { display: block; }
    .narrow { max-width: calc(820px + var(--gutter) * 2); }
    .list { display: flex; flex-direction: column; gap: 10px; }
    .item {
      border: 1px solid var(--stroke); border-radius: var(--r-lg);
      background: linear-gradient(180deg, rgba(255,255,255,.045), rgba(255,255,255,.015));
      transition: border-color .3s, background .3s;
    }
    .item[open] { border-color: var(--stroke-selected); background: var(--surface-selected); }
    summary {
      display: flex; align-items: center; justify-content: space-between; gap: 16px;
      padding: 18px 20px; font-size: 16px; font-weight: 600; cursor: pointer; list-style: none;
    }
    summary::-webkit-details-marker { display: none; }
    .plus {
      display: grid; place-items: center; flex: none; width: 30px; height: 30px; border-radius: 50%;
      background: var(--surface-strong); color: var(--text-2); font-size: 16px;
      transition: transform .35s var(--ease), background .3s, color .3s;
    }
    .item[open] .plus { transform: rotate(45deg); background: var(--accent); color: #fff; }
    p { padding: 0 20px 20px; color: var(--text-2); font-size: 15px; }
  `,
})
export class Faq {
  protected readonly i18n = inject(I18n);
}
