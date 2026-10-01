const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const GLYPHS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+=?@^~{}[]';
const running = new WeakMap();

// Reveal text by cycling random glyphs that settle left to right.
export function scramble(el, text, duration = 650) {
  cancelAnimationFrame(running.get(el));
  if (reduced) { el.textContent = text; return; }
  const start = performance.now();
  const frame = (now) => {
    const settled = Math.floor(((now - start) / duration) * text.length);
    let out = text.slice(0, settled);
    for (let i = settled; i < text.length; i++) {
      out += text[i] === ' ' ? ' ' : GLYPHS[(Math.random() * GLYPHS.length) | 0];
    }
    el.textContent = out;
    if (settled < text.length) running.set(el, requestAnimationFrame(frame));
  };
  running.set(el, requestAnimationFrame(frame));
}

// Scroll reveal; children of [data-stagger] get increasing delays.
const revealed = document.querySelectorAll('.reveal');
document.querySelectorAll('[data-stagger]').forEach((parent) => {
  [...parent.children].forEach((child, i) => child.style.setProperty('--delay', `${i * 90}ms`));
});
if (reduced || !('IntersectionObserver' in window)) {
  revealed.forEach((el) => el.classList.add('in'));
} else {
  const io = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) { entry.target.classList.add('in'); io.unobserve(entry.target); }
    }
  }, { rootMargin: '0px 0px -10% 0px' });
  revealed.forEach((el) => io.observe(el));
}

const nav = document.querySelector('.nav');
const onScroll = () => nav.classList.toggle('scrolled', scrollY > 8);
addEventListener('scroll', onScroll, { passive: true });
onScroll();

// Real outputs for ada@example.com / "correct horse battery staple", version 1, length 20.
const TICKER = [
  ['github.com', 'Um{GT&=2yz$:C[#j9}zk'],
  ['google.com', 'NsF06&m6K=y+s,KtrfnW'],
  ['amazon.com', '}HFLeD6}ugFS[#k(=Ux0'],
  ['linkedin.com', 'v82^%hg&,KQ(qYX)jLX%'],
  ['netflix.com', ':[xXkLY&7eeIr*r9Xi}y'],
];
const site = document.getElementById('t-site');
const pw = document.getElementById('t-pw');
if (site && pw) {
  let i = 0;
  const show = () => {
    const [s, p] = TICKER[i++ % TICKER.length];
    scramble(site, s, 300);
    scramble(pw, p, 900);
  };
  show();
  if (!reduced) setInterval(show, 2800);
}
