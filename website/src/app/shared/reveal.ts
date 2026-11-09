import { Directive, ElementRef, OnDestroy, afterNextRender, inject, input } from '@angular/core';

/** Mostra o elemento com uma entrada suave quando chega ao ecrã (ver [appReveal] em styles.scss). */
@Directive({
  selector: '[appReveal]',
  host: { '[style.--reveal-delay]': "(+appReveal() || 0) + 'ms'" },
})
export class Reveal implements OnDestroy {
  readonly appReveal = input<number | string>(0);
  private readonly el = inject<ElementRef<HTMLElement>>(ElementRef);
  private observer?: IntersectionObserver;

  constructor() {
    afterNextRender(() => {
      const node = this.el.nativeElement;
      if (!('IntersectionObserver' in window)) {
        node.classList.add('is-visible');
        return;
      }
      this.observer = new IntersectionObserver(
        (entries) => {
          for (const entry of entries) {
            if (entry.isIntersecting) {
              node.classList.add('is-visible');
              this.observer?.disconnect();
            }
          }
        },
        { rootMargin: '0px 0px -8% 0px', threshold: 0.12 },
      );
      this.observer.observe(node);
    });
  }

  ngOnDestroy(): void {
    this.observer?.disconnect();
  }
}
