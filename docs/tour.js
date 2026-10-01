// Pinned screenshot tour. Without GSAP, on small screens, or with reduced motion, the stacked layout stays.
(() => {
  const section = document.getElementById('tour');
  if (!section || !window.gsap || !window.ScrollTrigger) return;
  gsap.registerPlugin(ScrollTrigger);

  const items = [...section.querySelectorAll('.tour-item')];
  const shots = [...section.querySelectorAll('.frame-view img')];
  const spot = section.querySelector('.spot');
  const bar = section.querySelector('.tour-progress span');
  const box = (item) => {
    const [left, top, width, height] = item.dataset.spot.split(',').map(Number);
    return { left: `${left}%`, top: `${top}%`, width: `${width}%`, height: `${height}%` };
  };

  // Words for English, characters for Chinese, so each piece can animate in.
  function split(el) {
    const text = el.textContent;
    const cjk = /[\u3400-\u9fff]/.test(text);
    const parts = cjk ? text.match(/.[，。、；：？！”’）》」]*/gu) : text.split(/\s+/).filter(Boolean);
    el.replaceChildren();
    parts.forEach((part, i) => {
      if (i && !cjk) el.append(' ');
      el.append(Object.assign(document.createElement('span'), { className: 'w', textContent: part }));
    });
    return el.children;
  }

  let mm;
  function build() {
    mm?.revert();
    mm = gsap.matchMedia();
    mm.add('(min-width: 900px) and (prefers-reduced-motion: no-preference)', () => {
      section.classList.add('tour-on');
      const words = items.map((item) => [...item.querySelectorAll('h3, p')].flatMap((el) => [...split(el)]));

      gsap.set(items.slice(1), { autoAlpha: 0 });
      gsap.set(spot, box(items[0]));
      gsap.set(bar, { scaleX: 1 / items.length });

      const tl = gsap.timeline({
        defaults: { ease: 'power2.inOut' },
        scrollTrigger: {
          trigger: section.querySelector('.tour-pin'),
          start: 'top top',
          end: () => `+=${innerHeight * (items.length - 1) * 0.8}`,
          pin: true,
          scrub: 0.6,
          snap: { snapTo: 'labels', inertia: false, delay: 0.1, duration: { min: 0.2, max: 0.6 }, ease: 'power1.inOut' },
          invalidateOnRefresh: true,
        },
      });
      tl.addLabel('s0');
      for (let i = 1; i < items.length; i++) {
        const at = `s${i - 1}+=0.15`;
        tl.to(words[i - 1], { yPercent: -60, autoAlpha: 0, stagger: 0.008, duration: 0.3, ease: 'power2.in' }, at)
          .set(items[i - 1], { autoAlpha: 0 })
          .set(items[i], { autoAlpha: 1 })
          .fromTo(words[i], { yPercent: 70, autoAlpha: 0 }, { yPercent: 0, autoAlpha: 1, stagger: 0.012, duration: 0.45, ease: 'power3.out' })
          .to(shots[i], { opacity: 1, duration: 0.5 }, at)
          .to(shots[i - 1], { opacity: 0, duration: 0.5 }, at)
          .to(spot, { ...box(items[i]), duration: 0.6 }, at)
          .to(bar, { scaleX: (i + 1) / items.length, duration: 0.6 }, at)
          .addLabel(`s${i}`, i < items.length - 1 ? '+=0.15' : undefined);
      }

      return () => {
        section.classList.remove('tour-on');
        for (const el of section.querySelectorAll('.tour-item h3, .tour-item p')) el.textContent = el.textContent;
      };
    });
  }

  build();
  document.addEventListener('langchange', () => { build(); ScrollTrigger.refresh(); });
})();
