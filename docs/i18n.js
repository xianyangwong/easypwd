// English lives in the HTML; this holds Chinese plus strings that scripts create at runtime.
(() => {
  const zh = {
    title: 'EasyPwd：记住一句口令，每个网站都有同一个强密码',
    description: '离线 Chrome 扩展：用一句主口令为每个网站计算出固定的强密码。无需账号，无需同步，没有服务器。',
    navHow: '原理', navTour: '功能', navTry: '试一试', navSec: '安全',
    eyebrow: '开源 · 离线 · 无需账号',
    h1: '只需记住一句口令，<br>每个网站的强密码在任何设备上都一样。',
    lead: 'EasyPwd 根据你的邮箱、主口令和网站名称，为每个网站算出一个独一无二的密码。换一台电脑安装，输入同样的两样东西，所有密码就都回来了。不需要同步，因为根本没有东西要同步。',
    install: '安装 Chrome 扩展', tryBtn: '在浏览器里试试',
    howH: '原理',
    how1: '<strong>输入邮箱和主口令。</strong>EasyPwd 会显示四个单词，也就是你的密钥指纹。把它们记下来。',
    how2: '<strong>输入网站并回车。</strong><code>github.com</code>、<code>https://www.github.com/login</code> 和 <code>GitHub.com</code> 得到的是同一个密码。',
    how3: '<strong>在新设备上重复一遍。</strong>四个单词一致，所有密码就一致；不一致，说明你输错了。',
    flowAria: '邮箱和主口令经过 60 万轮 PBKDF2 得到根密钥。HKDF 再把根密钥分成三把：站点密钥通过 HMAC 生成每个网站的密码；保险库密钥用 AES-256-GCM 加密已保存的登录；以及四个单词的密钥指纹。',
    fYou: '你输入', fEmail: '邮箱', fPass: '主口令', fRoot: '根密钥',
    fSite: '站点密钥', fVault: '保险库密钥', fFp: '密钥指纹', f4w: '4 个单词',
    fGh: 'github.com 的密码', fSaved: '已保存的登录', fEnc: '加密，仅存本地', fCheck: '在每台设备上核对',
    tourH: '扩展内部一览', tourP: '五个界面，一个理念：没有东西要同步，也就没有东西会丢。',
    tour1t: '一分钟完成设置', tour1d: '只要邮箱和一句主口令。没有账号，不用注册，也没有服务器。',
    tour2t: '所有登录一目了然', tour2d: '生成的密码和保存的密码放在一起。搜索、复制，就这么简单。',
    tour3t: '任何新网站，密码已就绪', tour3d: '输入网站，密码立刻出现。长度和字符类型可以按网站单独设置。',
    tour4t: '输错口令，马上发现', tour4d: '只有你的邮箱和主口令才能得到这四个单词。在每台设备上都一样。',
    tour5t: '网站泄露？点一下就好', tour5d: '立即换新密码，旧密码会保留到你在网站上改完为止。还支持深色模式。',
    probH: '普通密码生成器的问题', probP: '“算出来的密码”并不是新点子。下面是它常见的坑，以及 EasyPwd 的解法。',
    c1t: '网站被泄露', c1d: '把版本号加一，就得到新密码。',
    c2t: '奇葩的密码规则', c2d: '每个网站单独设置长度和符号。',
    c3t: '改不了的旧密码', c3d: '放进本地加密保险库。',
    c4t: '主口令输错了', c4d: '四个单词立刻提醒你。',
    tryH: '试一试', tryP: '这里运行的是扩展本身的代码。所有计算都在你的浏览器里完成，但请使用虚构的值，不要输入真实口令。',
    secH: '你的秘密', secSub: '在每台设备上都一样', lId: '邮箱或名字', lPass: '主口令',
    showPass: '显示口令', hidePass: '隐藏口令',
    fpCap: '密钥指纹', fpNote: '换台设备单词不一样？说明你输错了。',
    tip: '试试看：改动口令中的任意一个字母，四个单词会全部改变。',
    siteH: '任意网站', lSite: '网站', pwFor: '密码：', lLen: '长度', lChars: '字符', rotate: '网站泄露？换个新密码',
    secuH: '安全性，不说空话',
    s1: '不联网。扩展的安全策略禁止一切网络连接。',
    s2: '安装时无权限警告。只在你点击“填充”时访问当前网页。',
    s3: '零依赖，只用浏览器内置的 Web Crypto。',
    s4: '算法<a href="https://github.com/xianyangwong/easypwd/blob/master/SECURITY.md#generated-passwords">以规范形式公开</a>，附测试向量，并与一个独立实现交叉验证。',
    tradeH: '需要权衡的地方',
    trade1: '任何人只要知道你的主口令和邮箱，就能算出所有生成的密码，不需要你的保险库。某个网站泄露了一个密码，攻击者也可以用它离线猜测你的主口令。请使用由多个不相关单词组成的长口令，并且不要在别处重复使用。',
    trade2: 'EasyPwd 尚未经过独立安全审计。',
    foot: 'MIT 许可 · 作者 <a href="https://github.com/xianyangwong">Xian Yang Wong</a>',
    privacy: '隐私', source: '源代码',
    privTitle: '隐私政策 · EasyPwd', privH: '隐私政策',
    priv1: 'EasyPwd 不收集、不传输、不出售，也不分享任何数据。',
    priv2: '你的邮箱或名字、主口令、登录信息和设置都只留在你的设备上。已保存的登录以加密形式存放在 Chrome 的本地扩展存储中。邮箱或名字未加密，以便锁屏界面显示。',
    priv3: '生成的密码在你的设备上计算，从不存储。',
    priv4: '扩展不发出任何网络请求。没有统计、广告、追踪、账号或服务器。只有在你打开 EasyPwd 弹窗时才读取当前网页的地址，只有在你点击“填充”时才填入登录信息。',
    priv5: '备份是你自己导出、自己保管的文件。',
    priv6: '卸载扩展或点击 <strong>Forgot passphrase?</strong> 会删除本地保险库。',
    priv7: '本网站（不是扩展）使用 Google Analytics 统计访问量，会设置 Cookie。<a href="./#try">演示</a>完全在你的浏览器中运行，你输入的内容不会发送到任何地方。',
    priv8: '有问题？<a href="https://github.com/xianyangwong/easypwd/issues">在 GitHub 上提 issue</a>。',
  };
  const runtime = {
    en: {
      busy: 'Running 600,000 PBKDF2 rounds…', bits: '≈ {n} bits of entropy', old: ' still shown until you update the site',
      copy: 'Copy', copied: 'Copied', noSite: 'Enter a website.', noId: 'Enter your email or name.',
      showPass: 'Show passphrase', hidePass: 'Hide passphrase',
    },
    zh: {
      busy: '正在进行 600,000 轮 PBKDF2 运算…', bits: '≈ {n} 位熵', old: ' 会保留到你在网站上改完为止',
      copy: '复制', copied: '已复制', noSite: '请输入网站。', noId: '请输入邮箱或名字。',
      showPass: zh.showPass, hidePass: zh.hidePass,
    },
  };
  const original = new Map();
  for (const el of document.querySelectorAll('[data-i18n]')) original.set(el, el.innerHTML);
  for (const el of document.querySelectorAll('[data-i18n-aria]')) original.set(el, el.getAttribute('aria-label'));
  const meta = document.querySelector('meta[name=description]');
  const page = { title: document.title, description: meta?.content, key: document.body.dataset.page || '' };

  let lang = 'en';
  function apply(next) {
    lang = next;
    const zhOn = lang === 'zh';
    document.documentElement.lang = zhOn ? 'zh-CN' : 'en';
    for (const el of document.querySelectorAll('[data-i18n]')) {
      el.innerHTML = zhOn ? zh[el.dataset.i18n] ?? original.get(el) : original.get(el);
    }
    for (const el of document.querySelectorAll('[data-i18n-aria]')) {
      el.setAttribute('aria-label', zhOn ? zh[el.dataset.i18nAria] ?? original.get(el) : original.get(el));
    }
    document.title = zhOn ? zh[page.key ? page.key + 'Title' : 'title'] : page.title;
    if (meta) meta.content = zhOn && !page.key ? zh.description : page.description;
    const button = document.getElementById('lang');
    if (button) {
      button.textContent = zhOn ? 'EN' : '中文';
      button.setAttribute('aria-label', zhOn ? 'Switch to English' : '切换到中文');
    }
    document.dispatchEvent(new CustomEvent('langchange', { detail: lang }));
  }

  window.i18n = {
    get lang() { return lang; },
    t(key, vars = {}) {
      return (runtime[lang][key] ?? runtime.en[key] ?? key).replace(/\{(\w+)\}/g, (_, name) => vars[name]);
    },
  };

  const asked = new URLSearchParams(location.search).get('lang');
  const saved = (() => { try { return localStorage.getItem('lang'); } catch { return null; } })();
  const initial = ['en', 'zh'].includes(asked) ? asked : saved || (/^zh\b/i.test(navigator.language) ? 'zh' : 'en');
  if (initial !== 'en') apply(initial);

  document.getElementById('lang')?.addEventListener('click', () => {
    const next = lang === 'zh' ? 'en' : 'zh';
    try { localStorage.setItem('lang', next); } catch { /* private mode */ }
    apply(next);
  });
})();
